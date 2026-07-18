#!/usr/bin/env python3
"""triage-verdict-feedback.py - feed manual triage verdicts back into corpora.

RELATED TOOLS (read these BEFORE building anything overlapping):
  - tools/outcome-feedback-loop.py (835 lines): F5 learning loop:
    outcome -> tier adjustment. Operates on filing OUTCOMES (won/lost/dupe
    at the platform), not on triage decisions.
  - tools/triage-feedback-collector.py (229 lines): different schema and
    output set; this one is the read side.
  - tools/triage-kill-promoter.py: flows KILL verdicts only to
    vault_known_dead_ends.

UNIQUE GAP this tool fills: reads OUR triage_v2_results.jsonl format (the
mechanical triage output produced by the 2026-05-27 triage swarm) plus
the kill_md files written by drill agents, and promotes them to 4
specific products that the existing tools do NOT produce:
  - workspace_oos_extension_<ws>.json (per-workspace OOS extensions
    consumed by the per-fn-question-ranker as hard-skip patterns)
  - obsidian-vault/anti-patterns/v2/ entries (auto-generated catalog)
  - exploit_predicates_defense_found_from_triage.jsonl (defense-present
    rows extracted from drill agent kill memos)
  - exploit_queue_from_triage_survivors.jsonl (survivor candidates).

r36-rebuttal: registered lane mimo-corpus-mining-wave-2026-05-28.

After a triage swarm produces kill reasons + drill verdicts (e.g. the
2026-05-27 wave that killed 45 of 46 YES candidates with file:line
evidence), this tool walks the triage outputs and promotes:

  1. KILL-L31-FILED-DUPE rows -> workspace_oos_extensions.json
     (per-workspace catalog of "this question/class always dupes to filed-X")
     -> pre-MIMO ranker reads this to hard-skip the pattern

  2. KILL-R76-HALLUCINATION / KILL-HALLUCINATED-PREMISE -> anti-patterns/v2/
     new entries (e.g. "MIMO generates Chainlink hypotheses against
     non-oracle contracts")

  3. KILL-FALSE-POSITIVE with named defense (e.g. "onlyCustomYearnStrategy
     blocks first-depositor") -> exploit_predicates_promoted.jsonl with
     defense-found rows so future MIMO context shows the defense

  4. PROMOTE candidates that survived all triage -> exploit_queue_priorities

Schema: auditooor.triage_verdict_feedback.v1

USAGE:
  python3 tools/triage-verdict-feedback.py --triage-dir /tmp/triage_46_yes [--json]
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.triage_verdict_feedback.v1"
AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent


def derived_dir() -> Path:
    override = os.environ.get("AUDITOOOR_DERIVED_DIR")
    return Path(override) if override else AUDITOOOR_ROOT / "audit/corpus_tags/derived"


def anti_patterns_v2_dir() -> Path:
    override = os.environ.get("AUDITOOOR_ANTI_PATTERNS_V2_DIR")
    return Path(override) if override else AUDITOOOR_ROOT / "obsidian-vault/anti-patterns/v2"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(AUDITOOOR_ROOT))
    except ValueError:
        return str(path)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_triage_results(triage_dir: Path) -> list[dict]:
    """Read triage_v2_results.jsonl (the mechanical triage output)."""
    f = triage_dir / "triage_v2_results.jsonl"
    out = []
    if not f.is_file():
        return out
    with f.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def load_kill_markdown(triage_dir: Path) -> list[dict]:
    """Read *_kill.md files (drill-agent verdicts)."""
    out = []
    for f in glob.glob(str(triage_dir / "*_kill*.md")):
        try:
            text = Path(f).read_text(encoding="utf-8")
        except Exception:
            continue
        out.append({
            "source_path": f,
            "name": Path(f).stem,
            "text": text,
            "size_chars": len(text),
        })
    return out


def workspace_oos_extension_path(ws: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(ws).strip())[:120] or "unknown"
    return derived_dir() / f"workspace_oos_extension_{safe}.json"


def update_workspace_oos(ws: str, new_rows: list[dict]) -> int:
    """Append OOS extension rows for a workspace (dedupe by reason+pattern)."""
    p = workspace_oos_extension_path(ws)
    p.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if p.is_file():
        try:
            existing = json.loads(p.read_text()).get("rows", [])
        except Exception:
            existing = []
    seen_keys = {r.get("dedupe_key") for r in existing}
    added = 0
    for r in new_rows:
        key = r.get("dedupe_key")
        if key and key not in seen_keys:
            existing.append(r)
            seen_keys.add(key)
            added += 1
    p.write_text(json.dumps({
        "schema_version": SCHEMA,
        "workspace": ws,
        "updated_at_utc": iso_now(),
        "rows": existing,
    }, indent=2))
    return added


def write_anti_pattern_md(name: str, ws_distribution: dict, evidence_count: int,
                          example_findings: list[str]) -> Path:
    """Write a new anti-pattern catalog entry."""
    out_dir = anti_patterns_v2_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / f"{name}.md"
    if p.is_file():
        return p  # idempotent
    body = f"""# Anti-pattern: {name}

**Source**: derived from triage-verdict-feedback.py on 2026-05 verdict batches
**Evidence count**: {evidence_count}
**Workspace distribution**: {json.dumps(ws_distribution)}

## Pattern
LLM-driven hunt (MIMO / DeepSeek / Claude fanout) generates hypotheses
of class `{name}` against contracts that lack the required surface for
this attack class to apply. The hypothesis matches a generic template
("Chainlink staleness", "flashloan initiator", "admin zero-address")
but the target contract has no Chainlink reference, no flashloan
integration, or no admin functions, respectively.

## Empirical examples (top 3)
{chr(10).join(f"- {e}" for e in example_findings[:3])}

## Detection
- File-hint resolves to a real file but the cited primitive (oracle call,
  flashloan callback, setter) does not appear in that file via grep.
- `tools/r76-hallucination-guard.py --scan-mimo-dir <dir>` catches this
  shape mechanically.

## Mitigation
- Pre-MIMO filter: skip questions of this class against contracts that
  do not contain the surface keyword (`AggregatorV3`, `flashLoan`,
  `onlyOwner`, etc.).
- `tools/per-fn-question-ranker.py` should penalize this (class x file)
  pair after N negative observations.

Generated by `tools/triage-verdict-feedback.py` at {iso_now()}.
"""
    p.write_text(body)
    return p


def _stable_candidate_id(row: dict) -> str:
    explicit = row.get("candidate_id") or row.get("task_id") or row.get("finding_id")
    if explicit:
        return str(explicit)
    seed = json.dumps(
        {
            "workspace": row.get("workspace"),
            "finding": row.get("finding"),
            "reason": row.get("reason"),
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return "triage-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def _load_json_or_empty(path: Path) -> dict | list:
    if not path.is_file():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, (dict, list)) else {}


def _queue_rows(raw: dict | list) -> list[dict]:
    if isinstance(raw, list):
        return [r for r in raw if isinstance(r, dict)]
    if isinstance(raw, dict):
        rows = raw.get("queue") or raw.get("rows") or []
        return [r for r in rows if isinstance(r, dict)]
    return []


def _write_exploit_queue(path: Path, raw_existing: dict | list, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(raw_existing, dict):
        out = dict(raw_existing)
        if "queue" in out or "rows" not in out:
            out["queue"] = rows
        else:
            out["rows"] = rows
        out.setdefault("schema", "auditooor.exploit_queue.v1")
        out["updated_at_utc"] = iso_now()
    else:
        out = {
            "schema": "auditooor.exploit_queue.v1",
            "generated_at_utc": iso_now(),
            "updated_at_utc": iso_now(),
            "queue": rows,
        }
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def merge_survivors_into_exploit_queues(survivor_rows: list[dict]) -> dict[str, int]:
    """Append survivor rows to each workspace .auditooor/exploit_queue.json."""
    by_ws: dict[str, list[dict]] = collections.defaultdict(list)
    for row in survivor_rows:
        ws = str(row.get("workspace") or "").strip()
        if ws and Path(ws).is_absolute():
            by_ws[ws].append(row)

    added_by_ws: dict[str, int] = {}
    for ws_raw, rows in by_ws.items():
        ws = Path(ws_raw)
        queue_path = ws / ".auditooor" / "exploit_queue.json"
        existing_raw = _load_json_or_empty(queue_path)
        existing_rows = _queue_rows(existing_raw)
        seen = {
            str(r.get("candidate_id") or r.get("lead_id") or r.get("task_id") or "")
            for r in existing_rows
        }
        added = 0
        for row in rows:
            candidate_id = _stable_candidate_id(row)
            if candidate_id in seen:
                continue
            finding = str(row.get("finding") or row.get("title") or candidate_id)
            existing_rows.append({
                "lead_id": candidate_id,
                "candidate_id": candidate_id,
                "title": finding,
                "attack_class": row.get("attack_class") or row.get("question_class") or row.get("class") or "",
                "likely_severity": row.get("severity") or row.get("severity_estimate") or "",
                "severity_confidence": row.get("confidence") or "",
                "quality_gate_status": "triage-survivor",
                "learning_route": "triage-verdict-feedback",
                "next_command": row.get("next_command") or "",
                "priority_score": float(row.get("priority_score") or 0.0),
                "blockers": [],
                "dupe_risk": row.get("dupe_risk") or "unknown",
                "source": "triage-survivor",
                "source_task_id": row.get("task_id"),
                "reason": row.get("reason") or "",
                "promoted_at_utc": row.get("promoted_at_utc") or iso_now(),
            })
            seen.add(candidate_id)
            added += 1
        if added:
            _write_exploit_queue(queue_path, existing_raw, existing_rows)
        added_by_ws[ws_raw] = added
    return added_by_ws


def load_r76_report(report_path: Path, kill_class: str) -> list[dict]:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    fails = report.get("fails") if isinstance(report, dict) else []
    out = []
    for fail in fails or []:
        if not isinstance(fail, dict):
            continue
        source_artifact = str(fail.get("source_artifact") or "")
        workspace = str(fail.get("workspace") or "")
        if not workspace and source_artifact:
            m = re.search(r"mimo_harness_([^/]+)", source_artifact)
            if m:
                workspace = m.group(1)
        out.append({
            "decision": kill_class,
            "workspace": workspace or "unknown",
            "task_id": fail.get("task_id") or Path(source_artifact).stem,
            "question_class": fail.get("verdict") or "r76-hallucination",
            "class": fail.get("verdict") or "r76-hallucination",
            "finding": fail.get("reason") or fail.get("excerpt_needle") or "R76 hallucination",
            "reason": fail.get("reason") or "",
            "file": fail.get("input_file_line") or "",
            "source_artifact": source_artifact,
        })
    return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--triage-dir")
    p.add_argument("--r76-report", default="",
                   help="R76 scan report JSON to promote as KILL-R76-HALLUCINATION rows.")
    p.add_argument("--kill-class", default="KILL-R76-HALLUCINATION",
                   help="Decision class used for --r76-report rows.")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if not args.triage_dir and not args.r76_report:
        sys.stderr.write("[feedback] pass --triage-dir and/or --r76-report\n")
        return 2

    triage_dir = Path(args.triage_dir) if args.triage_dir else None
    if triage_dir is not None and not triage_dir.is_dir():
        sys.stderr.write(f"[feedback] no triage dir: {triage_dir}\n")
        return 2

    triage_rows = load_triage_results(triage_dir) if triage_dir else []
    kill_mds = load_kill_markdown(triage_dir) if triage_dir else []
    if args.r76_report:
        triage_rows.extend(load_r76_report(Path(args.r76_report), args.kill_class))
    sys.stderr.write(f"[feedback] triage_rows={len(triage_rows)} kill_mds={len(kill_mds)}\n")

    # === Categorize triage rows by decision ===
    by_decision = collections.defaultdict(list)
    for r in triage_rows:
        by_decision[r.get("decision", "?")].append(r)

    # === Output 1: workspace OOS extensions from KILL-L31-FILED-DUPE ===
    oos_by_ws = collections.defaultdict(list)
    for r in by_decision.get("KILL-L31-FILED-DUPE", []):
        ws = r.get("workspace", "unknown")
        finding = r.get("finding", "")
        l31_path = r.get("l31_hit") or ""
        # Build a fuzzy-match key from finding nouns
        nouns = re.findall(r"\b[a-zA-Z][a-zA-Z0-9]{4,}\b", finding)
        nouns_sig = "+".join(sorted(set(n.lower() for n in nouns))[:5])
        oos_by_ws[ws].append({
            "schema_version": SCHEMA,
            "source": "kill-l31-filed-dupe",
            "reason": f"Already filed at platform: {Path(l31_path).name if l31_path else 'unknown'}",
            "finding_pattern": finding[:160],
            "dedupe_key": f"l31:{nouns_sig}",
            "evidence_task": r.get("task_id"),
            "added_at_utc": iso_now(),
        })
    oos_added_by_ws = {}
    for ws, rows in oos_by_ws.items():
        oos_added_by_ws[ws] = update_workspace_oos(ws, rows)

    # R76 hallucination rows are also dead sampling surfaces for the affected
    # workspace and class. Feed them into the same OOS extension consumer.
    hallu_oos_by_ws = collections.defaultdict(list)
    for r in triage_rows:
        if "HALLUCINAT" not in r.get("decision", "").upper():
            continue
        ws = r.get("workspace", "unknown")
        klass = r.get("question_class") or r.get("class") or "r76-hallucination"
        finding = r.get("finding") or r.get("reason") or ""
        hallu_oos_by_ws[ws].append({
            "schema_version": SCHEMA,
            "source": "kill-r76-hallucination",
            "reason": f"R76 hallucinated premise: {finding[:160]}",
            "finding_pattern": finding[:160],
            "attack_class": klass,
            "dedupe_key": f"r76:{klass}:{r.get('task_id')}",
            "evidence_task": r.get("task_id"),
            "added_at_utc": iso_now(),
        })
    for ws, rows in hallu_oos_by_ws.items():
        oos_added_by_ws[ws] = oos_added_by_ws.get(ws, 0) + update_workspace_oos(ws, rows)

    # === Output 2: anti-pattern from KILL-HALLUCINATION distribution ===
    hallu_per_class = collections.defaultdict(list)
    for r in triage_rows:
        if "HALLUCINAT" in r.get("decision", "").upper():
            klass = r.get("question_class") or r.get("class") or "unknown"
            hallu_per_class[klass].append(r)
    anti_patterns_written = []
    for klass, rs in hallu_per_class.items():
        if len(rs) >= 1:  # any hallucination -> create catalog entry
            ws_dist = collections.Counter(r.get("workspace") for r in rs)
            examples = [r.get("finding", "")[:140] for r in rs]
            name = f"mimo-hallucinated-{klass.replace('_', '-')}-on-incompatible-surface"
            path = write_anti_pattern_md(name, dict(ws_dist), len(rs), examples)
            anti_patterns_written.append(rel(path))

    # === Output 3: defense-present rows from kill_md files ===
    defense_rows = []
    for k in kill_mds:
        text = k["text"].lower()
        # Heuristic: kill_md mentions a defense modifier / pattern
        if any(d in text for d in ("only", "modifier", "require(", "ensure_signed",
                                    "messageid", "replay", "ceiling", "guard")):
            # Extract file:line if present
            m = re.search(r"([\w./-]+\.(sol|rs|go|ts)):(\d+)", k["text"])
            file_line = f"{m.group(1)}:{m.group(3)}" if m else "?"
            defense_rows.append({
                "schema_version": SCHEMA,
                "source": "triage-kill-defense-found",
                "kill_md": k["name"],
                "defense_evidence_file_line": file_line,
                "summary": k["text"][:300],
                "added_at_utc": iso_now(),
            })
    out_def = derived_dir() / "exploit_predicates_defense_found_from_triage.jsonl"
    out_def.parent.mkdir(parents=True, exist_ok=True)
    with out_def.open("w") as fh:
        for r in defense_rows:
            fh.write(json.dumps(r) + "\n")

    # === Output 4: survivor candidates for exploit_queue ===
    survivors = [r for r in triage_rows if r.get("decision", "").startswith("PROMOTE") or
                  r.get("decision", "").startswith("DRILL")]
    survivor_path = derived_dir() / "exploit_queue_from_triage_survivors.jsonl"
    with survivor_path.open("w") as fh:
        for r in survivors:
            fh.write(json.dumps({
                "schema_version": SCHEMA,
                "kind": "exploit_queue_candidate",
                "candidate_id": _stable_candidate_id(r),
                "task_id": r.get("task_id"),
                "workspace": r.get("workspace"),
                "severity": r.get("severity"),
                "attack_class": r.get("attack_class") or r.get("question_class") or r.get("class"),
                "finding": r.get("finding"),
                "decision": r.get("decision"),
                "reason": r.get("reason"),
                "promoted_at_utc": iso_now(),
            }) + "\n")
    survivor_merge = merge_survivors_into_exploit_queues(survivors)

    summary = {
        "schema_version": SCHEMA,
        "generated_at_utc": iso_now(),
        "triage_rows_processed": len(triage_rows),
        "kill_mds_processed": len(kill_mds),
        "workspace_oos_extensions": oos_added_by_ws,
        "anti_patterns_written": anti_patterns_written,
        "defense_found_rows": len(defense_rows),
        "survivors_for_exploit_queue": len(survivors),
        "exploit_queue_merges": survivor_merge,
        "outputs": {
            "workspace_oos_files": [rel(workspace_oos_extension_path(ws)) for ws in oos_added_by_ws],
            "defense_found": rel(out_def),
            "survivors": rel(survivor_path),
        },
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"triage rows: {summary['triage_rows_processed']}")
        print(f"kill_md files: {summary['kill_mds_processed']}")
        print(f"workspace OOS extensions added (per ws): {oos_added_by_ws}")
        print(f"anti-patterns written: {len(anti_patterns_written)}")
        for ap in anti_patterns_written:
            print(f"  {ap}")
        print(f"defense-found rows: {len(defense_rows)} -> {out_def.relative_to(AUDITOOOR_ROOT)}")
        print(f"survivors: {len(survivors)} -> {survivor_path.relative_to(AUDITOOOR_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
