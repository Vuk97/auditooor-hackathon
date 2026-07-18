#!/usr/bin/env python3
"""triage-kill-promoter.py - flow killed candidates → vault_known_dead_ends.

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

Operator's "how does mined stuff improve capability" gap: today's 7 KILLs
sat in docs/CANDIDATE_TRIAGE_2026-05-27_v3.md and never flowed back to
reports/known_dead_ends.jsonl. Next session would re-hypothesize them.

This tool reads:
  - audit/corpus_tags/derived/mega3/*.json (re-eval verdicts)
  - audit/corpus_tags/derived/mega4/*.json (function-drill verdicts)
  - docs/CANDIDATE_TRIAGE_*.md (manual triage docs)

Extracts any candidate with verdict in {KILL, FALSE-POSITIVE-KILL,
KILLED, NOT_A_BUG, FP} and appends it to reports/known_dead_ends.jsonl
in the `auditooor.known_dead_end.v1` schema:

  {
    "schema_version": "auditooor.known_dead_end.v1",
    "record_id": "<workspace>:<task-id>",
    "workspace": "...",
    "candidate_id": "...",
    "kill_reason": "...",
    "kill_verdict": "KILL|FALSE-POSITIVE-KILL|NOT_A_BUG",
    "evidence_file_line": "...",
    "evidence_code_excerpt": "...",
    "promoted_at_utc": "2026-05-27T...",
    "source_artifact": "<path-to-source-sidecar>"
  }

Future MIMO harness batches consult vault_known_dead_ends so they
DON'T re-hypothesize killed bug classes.

USAGE:
  python3 tools/triage-kill-promoter.py [--dry-run] [--source-dir <dir>]
  python3 tools/triage-kill-promoter.py --append-from-md docs/CANDIDATE_TRIAGE_2026-05-27_v3.md

Idempotent: deduplicates by record_id.
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
KDE_PATH = AUDITOOOR_ROOT / "reports" / "known_dead_ends.jsonl"
SCHEMA = "auditooor.known_dead_end.v1"

KILL_VERDICTS = {
    "KILL", "KILLED", "FALSE-POSITIVE-KILL", "FP",
    "NOT_A_BUG", "FALSE_POSITIVE", "DROP", "DROPPED",
}


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_existing() -> dict:
    """Load existing known_dead_ends keyed by record_id."""
    out = {}
    if not KDE_PATH.is_file():
        return out
    with KDE_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                rid = r.get("record_id")
                if rid:
                    out[rid] = r
            except json.JSONDecodeError:
                continue
    return out



def _safe_relpath(path):
    """Return path relative to AUDITOOOR_ROOT if possible, else str(path)."""
    try:
        return str(path.resolve().relative_to(AUDITOOOR_ROOT))
    except (ValueError, OSError):
        return str(path)


def parse_mimo_sidecar(path: Path) -> dict | None:
    """Extract kill info from a single MIMO mega-wave sidecar, if it's a kill."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if d.get("status") != "ok":
        return None
    r = d.get("result", "")
    if not isinstance(r, str) or not r.strip():
        return None
    body = r.strip().strip("`").lstrip("json").strip()
    try:
        j = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(j, dict):
        return None
    verdict = str(j.get("verdict", "")).upper().replace(" ", "-")
    if not any(k in verdict for k in KILL_VERDICTS):
        return None
    task_id = d.get("task_id", path.stem)
    workspace = d.get("workspace") or _infer_workspace(task_id)
    return {
        "schema_version": SCHEMA,
        "record_id": f"{workspace}:{task_id}",
        "workspace": workspace,
        "candidate_id": task_id,
        "kill_verdict": verdict,
        "kill_reason": str(j.get("reasoning", "") or j.get("notes", ""))[:500],
        "evidence_file_line": str(j.get("file_line", "") or "")[:200],
        "evidence_code_excerpt": str(j.get("code_excerpt", "") or "")[:500],
        "severity_claim": str(j.get("severity_final", "") or j.get("severity_estimate", "") or ""),
        "promoted_at_utc": iso_now(),
        "source_artifact": _safe_relpath(path),
    }


def _infer_workspace(task_id: str) -> str:
    for ws in ("morpho-midnight", "hyperbridge", "near", "dydx", "zebra", "spark"):
        if ws in task_id.lower():
            return ws
    return "unknown"


def parse_md_table_kills(md_path: Path) -> list[dict]:
    """Extract kill records from a CANDIDATE_TRIAGE markdown doc."""
    out = []
    if not md_path.is_file():
        return out
    text = md_path.read_text(encoding="utf-8")
    # Match a markdown table row with bold KILL marker
    for m in re.finditer(
        r"\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*\*\*KILL[A-Z-]*\*\*[^|]*\|\s*([^|\n]+)",
        text,
    ):
        cand_name = m.group(1).strip()
        sev = m.group(2).strip()
        reason = m.group(3).strip()
        rid = "md-triage:" + re.sub(r"[^a-zA-Z0-9_-]", "-", cand_name)[:60]
        out.append({
            "schema_version": SCHEMA,
            "record_id": rid,
            "workspace": _infer_workspace(cand_name),
            "candidate_id": cand_name,
            "kill_verdict": "KILL",
            "kill_reason": reason[:500],
            "evidence_file_line": "",
            "evidence_code_excerpt": "",
            "severity_claim": sev,
            "promoted_at_utc": iso_now(),
            "source_artifact": _safe_relpath(md_path),
        })
    return out


def parse_md_bullet_kills(md_path: Path, workspace: str | None = None) -> list[dict]:
    """Extract kill records from a BULLET-format triage log (the shape actually
    written by the per-workspace loop into <ws>/.auditooor/triage_log.md):

        - <candidate> @ <file:line> -> KILLED<suffix>: <reason>
        - <candidate> -> DROP-OOS: <reason>

    Complements parse_md_table_kills (which only handles markdown tables). Both
    run so either format is consumed. Generic across workspaces.
    """
    out: list[dict] = []
    if not md_path.is_file():
        return out
    ws = workspace or _infer_workspace(str(md_path)) or md_path.parent.parent.name
    kill_re = re.compile(
        r"^\s*[-*+]\s+(?P<cand>.+?)\s*"
        r"(?:@\s*(?P<loc>[^\s][^>]*?))?\s*"
        r"-+>\s*(?P<verdict>KILL[A-Z0-9_-]*|DROP[A-Z0-9_-]*|DROPPED|NOT_A_BUG|FP|SUPERSEDED)\b"
        r"[:\s]*(?P<reason>.*)$"
    )
    for raw in md_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = kill_re.match(raw)
        if not m:
            continue
        cand = m.group("cand").strip().strip("`")
        loc = (m.group("loc") or "").strip()
        verdict = m.group("verdict").strip()
        reason = m.group("reason").strip()
        slug = re.sub(r"[^a-zA-Z0-9_-]", "-", cand)[:60].strip("-")
        if not slug:
            continue
        rid = f"md-triage:{ws}:{slug}"
        out.append({
            "schema_version": SCHEMA,
            "record_id": rid,
            "workspace": ws,
            "candidate_id": cand,
            "kill_verdict": verdict,
            "kill_reason": reason[:500],
            "evidence_file_line": loc,
            "evidence_code_excerpt": "",
            "severity_claim": "",
            "promoted_at_utc": iso_now(),
            "source_artifact": _safe_relpath(md_path),
        })
    return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--source-dir", default=None,
                   help="Glob a single sidecar dir (default: scan all mega*/*.json)")
    p.add_argument("--append-from-md", default=None,
                   help="Also extract kills from a CANDIDATE_TRIAGE markdown")
    p.add_argument("--workspace", default=None,
                   help="Tag dead-end records with this workspace name (md bullet form).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print what would be added, don't write")
    p.add_argument("--json", action="store_true",
                   help="Emit summary JSON to stdout")
    args = p.parse_args(argv)

    existing = load_existing()
    sys.stderr.write(f"[kill-promoter] existing KDE records: {len(existing)}\n")

    new_records = []
    # 1. Scan mega-wave sidecars
    if args.source_dir:
        patterns = [f"{args.source_dir.rstrip('/')}/*.json"]
    else:
        patterns = [
            str(AUDITOOOR_ROOT / "audit/corpus_tags/derived/mega3/*.json"),
            str(AUDITOOOR_ROOT / "audit/corpus_tags/derived/mega4/*.json"),
            str(AUDITOOOR_ROOT / "audit/corpus_tags/derived/mimo_reeval/*.json"),
        ]
    for pat in patterns:
        for f in sorted(glob.glob(pat)):
            rec = parse_mimo_sidecar(Path(f))
            if rec and rec["record_id"] not in existing:
                new_records.append(rec)
                existing[rec["record_id"]] = rec

    # 2. Markdown source
    if args.append_from_md:
        md_p = Path(args.append_from_md)
        for rec in (parse_md_table_kills(md_p)
                    + parse_md_bullet_kills(md_p, args.workspace)):
            if rec["record_id"] not in existing:
                new_records.append(rec)
                existing[rec["record_id"]] = rec

    sys.stderr.write(f"[kill-promoter] {len(new_records)} new kill records to add\n")

    if args.dry_run:
        for r in new_records:
            sys.stderr.write(f"  [DRY] {r['workspace']}/{r['candidate_id']}: {r['kill_reason'][:80]}\n")
    else:
        KDE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with KDE_PATH.open("a", encoding="utf-8") as f:
            for r in new_records:
                f.write(json.dumps(r) + "\n")
        sys.stderr.write(f"[kill-promoter] appended {len(new_records)} to {KDE_PATH}\n")

    summary = {
        "schema_version": "auditooor.kill_promoter_summary.v1",
        "existing_kde_count_before": len(existing) - len(new_records),
        "new_kills_added": len(new_records),
        "total_kde_now": len(existing),
        "kills_by_workspace": {},
        "kills_by_verdict": {},
    }
    for r in new_records:
        ws = r.get("workspace", "?")
        v = r.get("kill_verdict", "?")
        summary["kills_by_workspace"][ws] = summary["kills_by_workspace"].get(ws, 0) + 1
        summary["kills_by_verdict"][v] = summary["kills_by_verdict"].get(v, 0) + 1

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"existing-before={summary['existing_kde_count_before']} | "
              f"added={summary['new_kills_added']} | total-now={summary['total_kde_now']}")
        if summary["kills_by_workspace"]:
            print("by workspace:", summary["kills_by_workspace"])
        if summary["kills_by_verdict"]:
            print("by verdict:", summary["kills_by_verdict"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
