#!/usr/bin/env python3
"""Quarantine zero-payload verbatim-template blocks from the hacker-question library
(X-hackerq-dedup).

The library (audit/corpus_tags/derived/hacker_questions_library.jsonl) carries a large
block of verbatim-identical, zero-payload rows (e.g. 1404 rows all with the exact
question_text "Does this contract exhibit the vulnerability described in this audit
finding? ..." + empty grep_patterns + empty linked_invariant_ids + empty
target_function_patterns, anchor audit-firm-finding-other). These are unmatchable by the
automated Step-6 consumer (corpus-driven-hunt drops empty-needle rows) AND bloat the
cap window, so they crowd out routable questions. Quarantine (NOT delete) them so
provenance/source_incident_id stays recoverable.

A group is quarantined ONLY when count >= --min-block AND EVERY row in it is zero-payload
(grep_patterns AND linked_invariant_ids AND target_function_patterns all falsy). That
protects a legitimately-repeated high-value question that carries real grep payload.

Default = dry-run, rc=1 if any quarantine-eligible block exists (CI/hygiene gate).
--apply moves the rows to the sidecar and rewrites the live file.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LIB = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "hacker_questions_library.jsonl"
DEFAULT_SIDECAR = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "hq_quarantine" / "hacker_q_quarantine.jsonl"

_PAYLOAD_KEYS = ("grep_patterns", "linked_invariant_ids", "target_function_patterns")


def _is_zero_payload(row: dict) -> bool:
    return all(not row.get(k) for k in _PAYLOAD_KEYS)


def _load(path: Path) -> tuple[list[dict], int]:
    rows, bad = [], 0
    if not path.is_file():
        return rows, bad
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows, bad


def select_quarantine(rows: list[dict], min_block: int) -> tuple[list[dict], list[dict], dict]:
    """Return (keep, quarantine, blocks_meta)."""
    by_q: dict[str, list[dict]] = collections.defaultdict(list)
    for r in rows:
        by_q[str(r.get("question_text") or "")].append(r)
    quarantine_qs = {}
    for q, group in by_q.items():
        if len(group) >= min_block and all(_is_zero_payload(r) for r in group):
            quarantine_qs[q] = len(group)
    keep, quar = [], []
    for r in rows:
        if str(r.get("question_text") or "") in quarantine_qs:
            quar.append(r)
        else:
            keep.append(r)
    return keep, quar, quarantine_qs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--library", default=str(DEFAULT_LIB))
    ap.add_argument("--sidecar", default=str(DEFAULT_SIDECAR))
    ap.add_argument("--min-block", type=int, default=50)
    ap.add_argument("--apply", action="store_true", help="move rows + rewrite the live file (default: dry-run)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    lib = Path(args.library)
    rows, bad = _load(lib)
    keep, quar, blocks = select_quarantine(rows, args.min_block)

    summary = {
        "schema": "auditooor.hacker_q_quarantine.summary.v1",
        "library": str(lib),
        "rows_in": len(rows),
        "rows_kept": len(keep),
        "rows_quarantined": len(quar),
        "blocks": blocks,
        "decode_errors": bad,
        "applied": bool(args.apply),
    }

    if args.apply and quar:
        sidecar = Path(args.sidecar)
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        # append (preserve any prior quarantine), verbatim
        with sidecar.open("a", encoding="utf-8") as fh:
            for r in quar:
                fh.write(json.dumps(r) + "\n")
        lib.write_text("\n".join(json.dumps(r) for r in keep) + "\n", encoding="utf-8")
        summary["sidecar"] = str(sidecar)

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        verb = "moved" if args.apply else "would move"
        print(f"hacker-q quarantine: {verb} {len(quar)} zero-payload rows "
              f"({len(blocks)} block(s)) ; {len(keep)} live rows remain")
        for q, n in sorted(blocks.items(), key=lambda x: -x[1]):
            print(f"  {n:5d}  {q[:80]}")

    # dry-run with an eligible block present = rc 1 (hygiene gate fires)
    if quar and not args.apply:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
