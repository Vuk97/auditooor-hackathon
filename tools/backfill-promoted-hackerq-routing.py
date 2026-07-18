#!/usr/bin/env python3
"""Backfill routing patterns onto the PROMOTED hacker-question firing set (wave-2 D1).

The promoted set (audit/corpus_tags/derived/hacker_questions_library_promoted.jsonl, 2007
rows) is the questions that actually get FIRED, but 0/2007 carry target_function_patterns /
grep_patterns, so corpus-driven-hunt drops every one at the empty-needle guard -> every
promoted question self-routes to ZERO hits. Reuse the existing grep-less enricher
(lib/per_function_target_patterns.enrich_hacker_question_record) by mapping the row's
`statement` (a JSON blob of sub_question_variants) into question_text so role-based
target_function_patterns are derived. Additive + idempotent; default dry-run.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROMOTED = REPO / "audit" / "corpus_tags" / "derived" / "hacker_questions_library_promoted.jsonl"
_LIB = REPO / "tools" / "lib" / "per_function_target_patterns.py"
_spec = importlib.util.spec_from_file_location("pftp", _LIB)
_pftp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pftp)


def _statement_haystack(row: dict) -> str:
    """Extract readable question text from the promoted `statement` (JSON blob or str)."""
    raw = row.get("statement")
    if isinstance(raw, str) and raw.strip():
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return raw
    else:
        obj = raw
    parts: list[str] = []
    if isinstance(obj, dict):
        for k in ("question", "question_text", "primary_question"):
            if isinstance(obj.get(k), str):
                parts.append(obj[k])
        v = obj.get("sub_question_variants")
        if isinstance(v, list):
            parts.extend(str(x) for x in v if isinstance(x, (str, int, float)))
        if not parts:
            parts.append(json.dumps(obj))
    elif isinstance(obj, str):
        parts.append(obj)
    return " ".join(parts)[:4000]


def backfill_row(row: dict) -> dict:
    if not isinstance(row, dict):
        return row
    haystack = _statement_haystack(row)
    # feed the enricher a question_text it can derive roles from; preserve category as anchor.
    probe = dict(row)
    probe["question_text"] = haystack
    probe.setdefault("attack_class_anchor", row.get("category") or "")
    probe.setdefault("grep_patterns", [])
    enriched = _pftp.enrich_hacker_question_record(probe)
    out = dict(row)
    for k in ("target_function_patterns", "target_function_roles",
              "target_contract_patterns", "scope_specificity"):
        if enriched.get(k):
            out[k] = enriched[k]
    if enriched.get("non_targetable_meta"):
        out["non_targetable_meta"] = True
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--path", default=str(PROMOTED))
    ap.add_argument("--apply", action="store_true", help="write back (default: dry-run)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    path = Path(args.path)
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    before = sum(1 for r in rows if r.get("target_function_patterns"))
    out = [backfill_row(r) for r in rows]
    recovered = sum(1 for r in out if r.get("target_function_patterns"))
    meta = sum(1 for r in out if r.get("non_targetable_meta"))
    if args.apply:
        path.write_text("\n".join(json.dumps(r) for r in out) + "\n", encoding="utf-8")
    summary = {"schema": "auditooor.promoted_hackerq_routing_backfill.v1",
               "rows": len(rows), "routable_before": before, "routable_after": recovered,
               "non_targetable_meta": meta, "applied": bool(args.apply)}
    print(json.dumps(summary, indent=2) if args.json
          else f"promoted routing backfill: routable {before} -> {recovered} of {len(rows)} "
               f"({meta} meta){' [APPLIED]' if args.apply else ' [dry-run]'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
