#!/usr/bin/env python3
"""dead-end-ledger.py - per-unit queryable dead-end ledger for the learning loop.

WHAT THIS TOOL DOES
===================
Every lane that rules an audit unit OUT writes a free-text verdict to its own
sidecar JSONL:
  - hunt verdicts:        <ws>/.auditooor/hunt_findings_sidecars/*.jsonl
  - depth-probe verdicts: <ws>/.auditooor/depth_probes*/*.jsonl
  - negative-space gaps:  <ws>/.auditooor/negative_space_gaps.jsonl

Those sidecars are per-lane and per-batch, so the learning loop could NOT answer
"which units did we drop, and WHY" without re-reading every file by hand - dead
ends got silently re-hunted next engagement. This tool UNIFIES the ruled-out
rows from all three sources into ONE queryable ledger
(<ws>/.auditooor/dead_end_ledger.jsonl, schema auditooor.known_dead_end.v1) with
a canonical drop_class (via tools/lib/dead_end_classify.py) and the cited
R-codes, and with --report prints a markdown histogram grouped by drop_class.

IDEMPOTENT: each row carries a stable dead_end_id (hash of source+unit+file_line)
and a re-run merges by that id rather than appending duplicates.

COMPLETENESS-SAFE: a row whose drop reason is unrecognised classifies as
``ruled-out-other`` (loud catch-all, never dropped); a malformed JSONL line is
WARN-skipped on stderr, never silently lost.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Compose with the shared classifier (lib import, with standalone fallback).
# ---------------------------------------------------------------------------
try:
    from tools.lib.dead_end_classify import classify, parse_rule_codes  # type: ignore
except Exception:
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    from dead_end_classify import classify, parse_rule_codes  # type: ignore

LEDGER_SCHEMA = "auditooor.known_dead_end.v1"

# Verdict strings (lower-cased) that mean "this unit was ruled OUT". Anything
# else (plausible / confirmed / open / pending) is NOT a dead end and is skipped.
_RULED_OUT_VERDICTS = {
    "rejected", "reject", "oos", "out-of-scope", "out of scope",
    "drop", "dropped", "no-gap", "no_gap", "ruled-out", "ruled_out",
    "false-positive", "false_positive", "fp", "negative", "not-a-bug",
}

# Candidate field names for each logical attribute, across the 3 sources.
_REASON_FIELDS = (
    "reason", "ruled_out_reason", "why_no_gap_or_exploit",
    "rebuttal_or_guard", "attacker_trace", "guard_reason",
)
_VERDICT_FIELDS = ("verdict", "disposition")
_UNIT_FIELDS = ("unit_id", "guard_id")
_FILELINE_FIELDS = ("file_line", "source_path")
_EXCERPT_FIELDS = ("code_excerpt", "excerpt")
_DECIDER_FIELDS = ("probe_source", "decided_by", "source", "lane")


def _first(d: Dict[str, Any], keys: Iterable[str], default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return str(v)
    return default


def _is_ruled_out(row: Dict[str, Any]) -> bool:
    """True when a row represents a dropped / ruled-out unit."""
    verdict = _first(row, _VERDICT_FIELDS, "").strip().lower()
    if verdict in _RULED_OUT_VERDICTS:
        return True
    # negative_space_gap rows: a confirmed gap (gap_found True) is NOT a dead
    # end; an explicit "drop"/no-gap disposition is.
    if "gap_found" in row and row.get("gap_found") is False:
        # only count it if it was actually probed / dispositioned to a drop
        disp = str(row.get("disposition", "")).strip().lower()
        if disp in _RULED_OUT_VERDICTS or row.get("probed") is True or disp == "":
            return True
    return False


def _dead_end_id(source_file: str, unit_id: str, file_line: str) -> str:
    base = Path(source_file).name + "|" + unit_id + "|" + file_line
    return "DE-" + hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception as exc:
                    sys.stderr.write(
                        f"[WARN] dead-end-ledger: skipping malformed line "
                        f"{path}:{ln}: {exc}\n"
                    )
                    continue
                if isinstance(obj, dict):
                    yield obj
    except OSError as exc:
        sys.stderr.write(f"[WARN] dead-end-ledger: cannot read {path}: {exc}\n")


def _source_files(ws: Path) -> List[Path]:
    """Every sidecar JSONL we mine ruled-out rows from."""
    aud = ws / ".auditooor"
    found: List[Path] = []
    found += [Path(p) for p in glob.glob(str(aud / "hunt_findings_sidecars" / "*.jsonl"))]
    # depth_probes/ and depth_probes_*/ both occur in the wild
    found += [Path(p) for p in glob.glob(str(aud / "depth_probes" / "*.jsonl"))]
    found += [Path(p) for p in glob.glob(str(aud / "depth_probes_*" / "*.jsonl"))]
    ns = aud / "negative_space_gaps.jsonl"
    if ns.exists():
        found.append(ns)
    return sorted(set(found))


def build_ledger(ws: Path) -> List[Dict[str, Any]]:
    """Mine all sidecars -> unified, deduped ledger rows (list of dicts)."""
    rows_by_id: Dict[str, Dict[str, Any]] = {}
    for src in _source_files(ws):
        for raw in _iter_jsonl(src):
            if not _is_ruled_out(raw):
                continue
            unit_id = _first(raw, _UNIT_FIELDS, "unknown-unit")
            file_line = _first(raw, _FILELINE_FIELDS, "")
            reason = _first(raw, _REASON_FIELDS, "")
            excerpt = _first(raw, _EXCERPT_FIELDS, "")
            verdict = _first(raw, _VERDICT_FIELDS, "").strip().lower() or "drop"
            decided_by = _first(raw, _DECIDER_FIELDS, "") or Path(src).name
            drop_class = classify(reason, excerpt)
            rule_cited = parse_rule_codes(reason, excerpt)
            de_id = _dead_end_id(str(src), unit_id, file_line)
            ledger_row = {
                "schema": LEDGER_SCHEMA,
                "dead_end_id": de_id,
                "file_line": file_line,
                "unit_id": unit_id,
                "verdict": verdict,
                "drop_class": drop_class,
                "rule_cited": rule_cited,
                "reason": reason,
                "decided_by": decided_by,
                "source_file": Path(src).name,
            }
            # Idempotent merge on dead_end_id (last writer wins; stable id).
            rows_by_id[de_id] = ledger_row
    return list(rows_by_id.values())


def write_ledger(ws: Path, rows: List[Dict[str, Any]]) -> Path:
    out = ws / ".auditooor" / "dead_end_ledger.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    return out


def render_report(rows: List[Dict[str, Any]]) -> str:
    """Markdown table: drop_class -> count + a sample file:line."""
    from collections import defaultdict

    buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        buckets[r.get("drop_class", "ruled-out-other")].append(r)

    lines = [
        "# Dead-End Ledger Report",
        "",
        f"Total ruled-out units: {len(rows)}",
        "",
        "| drop_class | count | sample file:line |",
        "| --- | ---: | --- |",
    ]
    for drop_class in sorted(buckets, key=lambda k: (-len(buckets[k]), k)):
        bucket = buckets[drop_class]
        sample = next((b.get("file_line", "") for b in bucket if b.get("file_line")), "")
        lines.append(f"| {drop_class} | {len(bucket)} | {sample or '-'} |")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Unify ruled-out audit units into a queryable dead-end ledger."
    )
    ap.add_argument("--workspace", "--ws", required=True, dest="workspace",
                    help="Workspace path (the dir containing .auditooor/).")
    ap.add_argument("--report", action="store_true",
                    help="Also print a markdown histogram grouped by drop_class.")
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not ws.exists():
        sys.stderr.write(f"[ERR] dead-end-ledger: workspace not found: {ws}\n")
        return 2

    rows = build_ledger(ws)
    out = write_ledger(ws, rows)
    sys.stderr.write(
        f"[ok] dead-end-ledger: {len(rows)} ruled-out units -> {out}\n"
    )
    if args.report:
        sys.stdout.write(render_report(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
