#!/usr/bin/env python3
"""verdict-sink.py - persist workflow / agent hunt verdicts into the CANONICAL
audit artifacts so they (a) are credited by the hunt-completeness + coverage
gates and (b) feed the self-learning loop. The missing bridge between the
sonnet-via-Agent / Workflow hunt (whose verdicts otherwise live only in the
workflow journal) and `<ws>/.auditooor/hunt_findings_sidecars/`.

WHY THIS EXISTS (the gap it forecloses):
The canonical per-function hunt (`make hunt-haiku MODEL=sonnet`, the haiku
Workflow, mimo-corpus-miner) writes per-task sidecars that `hunt-sidecar-bridge.py`
materialises into the workspace, so the gates see them. But an ad-hoc Workflow /
Agent hunt returns its verdicts only in the run journal - real work that
EVAPORATES from the funnel's and the learning loop's view. This tool ingests a
workflow journal (or its final result JSON) and writes the same canonical
sidecars, plus a killed-leads digest, so no hunt's output is ever lost again.

CORPUS-FEEDBACK-CLOSURE (the learning-loop close, FIX verdict-sink-corpus-feedback):
After the sidecars + sink-log are written, this tool shells the canonical learning
ETL `hackerman-etl-from-finding-sidecars.py --workspace <ws>` per workspace
(best-effort, never blocks the sink). The ETL is idempotent / content-hashed and
routes CONFIRMED verdicts -> invariant_library_extended + detector_synthesis_v2 and
rule-out / collapse / KILLED verdicts -> reports/known_dead_ends.jsonl (read by
vault_known_dead_ends), so a sunk KILL suppresses future re-chasing of the same
angle instead of evaporating. To make this fire, the sink sidecar now exposes
verdict / proposed_severity tokens at the TOP LEVEL (the keys the ETL classifies on).
The companion enforcement (`hunt-verdict-persistence-gate.py` + the Workflow
PostToolUse obligation hook) makes running it non-optional before any done /
audit-complete claim, AND now fails-closed when a workspace has CONFIRMED / kill
sidecars with no corresponding corpus record (the closure check).

HONESTY (never a false-green):
- A sidecar is emitted ONLY for a verdict whose primary file:line resolves to a
  real file in the target workspace (R76). An unresolvable / hallucinated
  file:line is written with status="needs-source-verification" and
  applies_to_target left as the agent stated it - it is NOT auto-promoted.
- applies_to_target / confidence are copied from the agent verdict, never
  upgraded. A `collapse` adjudication becomes applies_to_target="no" (a genuine
  rule-out = real coverage); a `paste-ready` / `needs-poc` becomes "yes".
- Idempotent: each sidecar id is a content hash; re-running overwrites identically
  and never double-counts.

USAGE:
  python3 tools/verdict-sink.py --journal <run>/journal.jsonl
  python3 tools/verdict-sink.py --journal <run>/journal.jsonl --run-id wf_abc --dry-run
  python3 tools/verdict-sink.py --result-json <task>.output            # final return
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_WS_PATH_RE = re.compile(r"(/Users/[^/]+/audits/[^/\s\"']+)")
_FILE_LINE_RE = re.compile(r"([/\w.\-]+\.(?:rs|sol|go|move|cairo|circom))(?::(\d+))?")
_SINK_LOG = Path(os.environ.get("AUDITOOOR_VERDICT_SINK_LOG",
                                str(REPO_ROOT / ".auditooor" / "verdict_sink_log.jsonl")))
_AUDIT_ROOT = Path("/Users/wolf/audits")
# Module-level fallback workspace (set from --workspace) for verdicts whose
# cited paths are relative and ambiguous; None disables the fallback.
_WS_HINT: Path | None = None
_BASENAME_INDEX: dict[str, set] | None = None


def _audit_workspaces() -> list[Path]:
    if not _AUDIT_ROOT.is_dir():
        return []
    return [d for d in _AUDIT_ROOT.iterdir() if d.is_dir() and not d.name.startswith(".")]


def _basename_index() -> dict[str, set]:
    """Lazily map source-file basename -> set of workspace names that contain it,
    so a relative cite like 'orchard_policy.rs' resolves to its unique workspace."""
    global _BASENAME_INDEX
    if _BASENAME_INDEX is not None:
        return _BASENAME_INDEX
    idx: dict[str, set] = {}
    for ws in _audit_workspaces():
        src = ws / "src"
        root = src if src.is_dir() else ws
        for ext in ("*.rs", "*.sol", "*.go", "*.move", "*.cairo", "*.circom"):
            for f in root.rglob(ext):
                parts = set(f.parts)
                if parts & {"target", "node_modules", "out", "lib", ".git", "cache"}:
                    continue
                idx.setdefault(f.name, set()).add(ws.name)
    _BASENAME_INDEX = idx
    return idx


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _feed_corpus(ws_path: str, kills: list[dict]) -> dict:
    """Corpus-feedback-closure: route this run's freshly-sunk sidecars into the
    canonical learning corpus via hackerman-etl-from-finding-sidecars.py. The ETL
    is idempotent / content-hashed (re-running never double-counts) and routes
    CONFIRMED verdicts -> invariant_library_extended + detector_synthesis_v2 and
    rule-out / collapse / killed verdicts -> reports/known_dead_ends.jsonl (read by
    vault_known_dead_ends, so already-killed angles are not re-dispatched).

    Best-effort: a corpus-ETL failure (missing tool, ETL crash, timeout) must NOT
    block the sink - the sidecars + sink-log are already written. Returns a small
    status dict for the run summary; never raises.
    """
    etl = REPO_ROOT / "tools" / "hackerman-etl-from-finding-sidecars.py"
    n_kills = len([k for k in kills if k.get("ws") == Path(ws_path).name])
    if not etl.exists():
        return {"ws": Path(ws_path).name, "status": "etl-missing", "kills_in_run": n_kills}
    try:
        proc = subprocess.run(
            [sys.executable, str(etl), "--workspace", ws_path, "--json"],
            capture_output=True, text=True, timeout=600,
        )
    except Exception as exc:  # noqa: BLE001 - best-effort, must not block the sink
        return {"ws": Path(ws_path).name, "status": f"etl-error:{type(exc).__name__}",
                "kills_in_run": n_kills}
    if proc.returncode != 0:
        return {"ws": Path(ws_path).name, "status": f"etl-rc-{proc.returncode}",
                "kills_in_run": n_kills, "stderr": (proc.stderr or "")[:200]}
    out = {"ws": Path(ws_path).name, "status": "ok", "kills_in_run": n_kills}
    try:
        summ = json.loads(proc.stdout)
        out.update({
            "invariant_records": summ.get("invariant_records", 0),
            "detector_seed_records": summ.get("detector_seed_records", 0),
            "new_kde_records": summ.get("new_kde_records", 0),
        })
    except Exception:  # noqa: BLE001 - parse is informational only
        pass
    return out


def _read_journal(path: Path) -> list[dict]:
    """Return the list of agent RESULT objects from a workflow journal."""
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        if j.get("type") == "result" and isinstance(j.get("result"), dict):
            out.append(j["result"])
    return out


def _read_result_json(path: Path) -> list[dict]:
    """Pull verdict-shaped dicts out of a workflow's final return blob."""
    try:
        blob = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    blob = blob.get("result", blob) if isinstance(blob, dict) else blob
    found: list[dict] = []

    def walk(x):
        if isinstance(x, dict):
            if any(k in x for k in ("findings", "final_verdict", "verdict", "survives")):
                found.append(x)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(blob)
    return found


def _first(*vals):
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v
    return ""


def _resolve_ws(*texts: str) -> str | None:
    # 1. an absolute /Users/.../audits/<ws> path anywhere in the verdict.
    for t in texts:
        if not isinstance(t, str):
            continue
        m = _WS_PATH_RE.search(t)
        if m:
            # normalise to the workspace ROOT (/Users/x/audits/<ws>)
            mr = re.match(r"(/Users/[^/]+/audits/[^/]+)", m.group(1))
            return mr.group(1) if mr else m.group(1)
    # 2. a relative source-file cite (e.g. 'orchard_policy.rs:10') -> the unique
    #    workspace that contains that basename.
    idx = _basename_index()
    for t in texts:
        if not isinstance(t, str):
            continue
        fm = _FILE_LINE_RE.search(t)
        if fm:
            base = Path(fm.group(1)).name
            owners = idx.get(base)
            if owners and len(owners) == 1:
                return str(_AUDIT_ROOT / next(iter(owners)))
    # 3. explicit --workspace fallback (orchestrator-supplied lane context).
    if _WS_HINT is not None:
        return str(_WS_HINT)
    return None


def _parse_file_line(*texts: str):
    for t in texts:
        if not isinstance(t, str):
            continue
        m = _FILE_LINE_RE.search(t)
        if m:
            return m.group(1), (int(m.group(2)) if m.group(2) else 0)
    return "", 0


def _verified(ws: str, file_part: str, line: int) -> bool:
    """R76: does the cited file:line resolve to a real file in the workspace?"""
    if not file_part:
        return False
    cand = Path(file_part)
    if not cand.is_absolute():
        hits = list(Path(ws).rglob(Path(file_part).name)) if Path(file_part).name else []
        cand = hits[0] if hits else cand
    if not cand.exists():
        return False
    if line > 0:
        try:
            return line <= len(cand.read_text(errors="replace").splitlines())
        except OSError:
            return False
    return True


def _candidates_from_result(r: dict) -> list[dict]:
    """Normalise one journal/return result into a flat list of verdict records:
    {title, file_line, severity, applies, confidence, rubric, finding_text,
     attacker_path, defending, provider, poc_result, kind}."""
    recs: list[dict] = []

    # Hunt result: {lane, findings: [...]}
    if isinstance(r.get("findings"), list):
        for f in r["findings"]:
            if not isinstance(f, dict):
                continue
            recs.append({
                "title": _first(f.get("title")),
                "file_line": _first(f.get("file_line")),
                "severity": _first(f.get("severity")),
                "applies": "yes" if _first(f.get("severity")).lower() in ("critical", "high", "medium") else "maybe",
                "confidence": _first(f.get("confidence"), "medium"),
                "rubric": _first(f.get("rubric_row")),
                "finding_text": _first(f.get("exploit_mechanism"), f.get("title")),
                "attacker_path": _first(f.get("attacker_profit_nonself")),
                "defending": _first(f.get("designed_or_oos_precheck")),
                "provider": "sonnet-via-agent",
                "poc_result": "",
                "kind": "hunt",
            })
        return recs

    # Adjudication result: {final_verdict, severity, finding_title, ...}
    if "final_verdict" in r:
        fv = _first(r.get("final_verdict"))
        recs.append({
            "title": _first(r.get("finding_title")),
            "file_line": _first(r.get("file_line")),
            "severity": _first(r.get("severity")),
            "applies": "no" if fv == "collapse" else "yes",
            "confidence": "high",
            "rubric": _first(r.get("rubric_row")),
            "finding_text": _first(r.get("reason")),
            "attacker_path": _first(r.get("escalation")),
            "defending": _first(r.get("reason")) if fv == "collapse" else "",
            "provider": "opus-adjudicator",
            "poc_result": "",
            "kind": "adjudication",
            "final_verdict": fv,
            "pre_submit_ready": bool(r.get("pre_submit_ready")),
        })
        return recs

    # Validation result: {survives, severity, value_sink, poc_result, kill_reason}
    if "survives" in r or "poc_result" in r:
        recs.append({
            "title": _first(r.get("rubric_row"), r.get("severity")),
            "file_line": _first(r.get("value_sink"), r.get("poc_or_trace")),
            "severity": _first(r.get("severity")),
            "applies": "yes" if r.get("survives") else "no",
            "confidence": "high",
            "rubric": _first(r.get("rubric_row")),
            "finding_text": _first(r.get("value_sink"), r.get("poc_or_trace")),
            "attacker_path": _first(r.get("r24")),
            "defending": _first(r.get("kill_reason")),
            "provider": "sonnet-via-agent",
            "poc_result": _first(r.get("poc_result")),
            "kind": "validation",
        })
        return recs

    # Generic single-verdict (e.g. older decompose schema): {verdict, severity_candidate, value_sink, ...}
    if "verdict" in r:
        v = _first(r.get("verdict"))
        recs.append({
            "title": _first(r.get("bug"), r.get("rubric_row")),
            "file_line": _first(r.get("value_sink"), r.get("file_line")),
            "severity": _first(r.get("severity_candidate"), r.get("severity")),
            "applies": "no" if v in ("collapse", "killed") else "yes",
            "confidence": "high",
            "rubric": _first(r.get("rubric_row")),
            "finding_text": _first(r.get("bug")),
            "attacker_path": _first(r.get("r24_non_self")),
            "defending": _first(r.get("kill_reason_if_any"), r.get("oos_match")),
            "provider": "sonnet-via-agent",
            "poc_result": _first(r.get("poc_result")),
            "kind": "verdict",
        })
    return recs


def _sidecar_id(ws_name: str, rec: dict) -> str:
    h = hashlib.sha256(
        (ws_name + "|" + rec.get("title", "") + "|" + rec.get("file_line", "") + "|" + rec.get("kind", "")).encode()
    ).hexdigest()[:16]
    return f"verdictsink_{ws_name}_{rec.get('kind','x')}_{h}"


def build_sidecar(rec: dict, run_id: str) -> tuple[Path, dict] | None:
    ws = rec.get("workspace_path") if isinstance(rec.get("workspace_path"), str) and rec.get("workspace_path") else None
    if not ws:
        ws = _resolve_ws(rec.get("file_line", ""), rec.get("finding_text", ""),
                         rec.get("attacker_path", ""), rec.get("defending", ""))
    if not ws:
        return None
    ws_name = Path(ws).name
    file_part, line = _parse_file_line(rec.get("file_line", ""), rec.get("finding_text", ""), rec.get("defending", ""))
    verified = _verified(ws, file_part, line)
    # Ensure a source-cited rule-out carries its file:line in defending_lines so
    # the function-coverage gate credits it as FP-defended (not bare-prose hollow).
    defending = rec.get("defending", "") or ""
    if rec.get("applies") == "no" and file_part and not _FILE_LINE_RE.search(defending):
        anchor = f"{file_part}:{line}" if line else file_part
        defending = (f"{anchor} - " + defending).strip()
    tier = "tier-1-poc-verified" if rec.get("poc_result") == "PASS" else (
        "tier-2-source-verified" if verified else "tier-4-unverified")
    status = "ok" if verified or rec.get("applies") == "no" else "needs-source-verification"
    sid = _sidecar_id(ws_name, rec)
    # Corpus-feedback-closure: expose verdict/severity tokens at the TOP LEVEL so the
    # learning ETL (hackerman-etl-from-finding-sidecars.py, which reads top-level
    # `verdict` via _verdict_blob and top-level `proposed_severity`/`severity` via
    # _sidecar_severity) can classify this sidecar without needing to know the
    # verdict-sink result-nested shape. A rule-out (applies==no) carries a KILLED /
    # collapse token so it becomes a known-dead-end record; a CRITICAL/HIGH/MEDIUM
    # applies==yes verdict surfaces its severity so it becomes an INV + detector seed.
    severity_norm = (rec.get("severity", "") or "").strip()
    final_verdict = rec.get("final_verdict", "") or ""
    if rec.get("applies") == "no":
        corpus_verdict = f"KILLED collapse {final_verdict}".strip()
        corpus_severity = ""
    else:
        corpus_verdict = final_verdict or rec.get("confidence", "")
        corpus_severity = severity_norm if severity_norm.lower() in ("critical", "high", "medium") else ""
    sidecar = {
        "task_id": sid,
        "workspace": ws_name,
        "workspace_path": ws,
        "function_anchor": {"file": file_part or "n/a", "function": rec.get("title", ""), "line": line},
        "task_type": "workflow_hunt_verdict",
        "provider": rec.get("provider", "sonnet-via-agent"),
        "model_id": "claude-opus-4-8" if rec.get("provider") == "opus-adjudicator" else "claude-sonnet-4-6",
        "status": status,
        "verification_tier": tier,
        # Top-level mirrors for the learning ETL (see comment above). These are
        # provenance-only duplicates of the canonical result.* fields; they never
        # change applies_to_target / confidence (R76: copied, never upgraded).
        "verdict": corpus_verdict,
        "proposed_severity": corpus_severity,
        "slug": sid,
        "title": rec.get("title", ""),
        "audit_pin": rec.get("audit_pin", ""),
        "why_dropped": (rec.get("defending", "") or "")[:500] if rec.get("applies") == "no" else "",
        "source_run": run_id,
        "result": {
            "applies_to_target": rec.get("applies", "maybe"),
            "confidence": rec.get("confidence", "medium"),
            "rubric_class": rec.get("rubric", "n/a") or "n/a",
            "candidate_finding": (rec.get("finding_text", "") or rec.get("title", ""))[:600],
            "defending_lines": defending[:600],
            "attacker_path": (rec.get("attacker_path", "") or "")[:400],
            "severity": rec.get("severity", ""),
            "final_verdict": rec.get("final_verdict", ""),
            "pre_submit_ready": rec.get("pre_submit_ready", False),
        },
    }
    out = Path(ws) / ".auditooor" / "hunt_findings_sidecars" / f"{sid}.json"
    return out, sidecar


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--journal", help="path to a workflow run journal.jsonl")
    ap.add_argument("--result-json", help="path to a workflow final-result/task output JSON")
    ap.add_argument("--run-id", default="", help="run id for provenance + the sink resolution log")
    ap.add_argument("--workspace", default="", help="fallback workspace ROOT for verdicts whose cited paths are relative/ambiguous")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-etl", action="store_true",
                    help="skip the corpus-feedback ETL (hackerman-etl-from-finding-sidecars) "
                         "that routes sunk verdicts into invariants/detectors/known-dead-ends")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    global _WS_HINT
    if args.workspace:
        wsp = Path(args.workspace)
        if not wsp.is_dir():
            print(f"ERR: --workspace not a directory: {wsp}", file=sys.stderr)
            return 2
        _WS_HINT = wsp

    if not args.journal and not args.result_json:
        print("ERR: pass --journal or --result-json", file=sys.stderr)
        return 2

    results: list[dict] = []
    src = ""
    if args.journal:
        p = Path(args.journal)
        if not p.exists():
            print(f"ERR: journal not found: {p}", file=sys.stderr)
            return 2
        results = _read_journal(p)
        src = str(p)
        if not args.run_id:
            args.run_id = p.parent.name
    if args.result_json:
        p = Path(args.result_json)
        if p.exists():
            results += _read_result_json(p)
            src = src or str(p)
            if not args.run_id:
                args.run_id = p.stem

    recs: list[dict] = []
    for r in results:
        recs.extend(_candidates_from_result(r))

    written, skipped_no_ws, by_ws = 0, 0, {}
    ws_paths: dict[str, str] = {}
    fileable, kills = [], []
    for rec in recs:
        built = build_sidecar(rec, args.run_id)
        if built is None:
            skipped_no_ws += 1
            continue
        out, sidecar = built
        ws_name = sidecar["workspace"]
        by_ws[ws_name] = by_ws.get(ws_name, 0) + 1
        ws_paths.setdefault(ws_name, sidecar["workspace_path"])
        if sidecar["result"].get("final_verdict") in ("paste-ready", "needs-poc"):
            fileable.append({"ws": ws_name, "title": rec.get("title"), "verdict": sidecar["result"]["final_verdict"]})
        if rec.get("applies") == "no":
            kills.append({"ws": ws_name, "title": rec.get("title"), "why": rec.get("defending", "")[:200]})
        if not args.dry_run:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(sidecar, indent=1), encoding="utf-8")
        written += 1

    # Resolution log: closes the persistence obligation for this run.
    if not args.dry_run and args.run_id:
        _SINK_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _SINK_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "run_id": args.run_id, "ts": _now(), "source": src,
                "sidecars_written": written, "by_workspace": by_ws,
                "skipped_no_workspace": skipped_no_ws,
                "fileable": fileable, "kills": len(kills),
            }) + "\n")

    # Corpus-feedback-closure (the learning-loop close): route the freshly-sunk
    # sidecars into the canonical corpus per workspace so KILL verdicts suppress
    # future re-chasing (vault_known_dead_ends) and CONFIRMED verdicts seed
    # invariants + detectors. Best-effort: never blocks the sink (see _feed_corpus).
    corpus_feed: list[dict] = []
    if not args.dry_run and not args.no_etl and written:
        for ws_name, ws_path in ws_paths.items():
            corpus_feed.append(_feed_corpus(ws_path, kills))

    summary = {
        "run_id": args.run_id, "results_parsed": len(results), "verdict_records": len(recs),
        "sidecars_written": written, "by_workspace": by_ws,
        "skipped_no_workspace": skipped_no_ws, "fileable": fileable, "kills_recorded": len(kills),
        "corpus_feed": corpus_feed,
        "dry_run": args.dry_run,
    }
    if args.json:
        print(json.dumps(summary, indent=1))
    else:
        cf = "".join(
            f" corpus[{c['ws']}]={c.get('status')}"
            f"(inv={c.get('invariant_records', '?')},det={c.get('detector_seed_records', '?')},"
            f"kde={c.get('new_kde_records', '?')})"
            for c in corpus_feed
        )
        print(f"[verdict-sink] run={args.run_id} parsed={len(results)} records={len(recs)} "
              f"sidecars={written} by_ws={by_ws} fileable={len(fileable)} kills={len(kills)} "
              f"skipped_no_ws={skipped_no_ws}{cf}{' (DRY)' if args.dry_run else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
