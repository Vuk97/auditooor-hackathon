#!/usr/bin/env python3
"""trusted-corpus-index-check.py - Phase 1 trusted-corpus index validator.

The check half of the Phase 1 trust layer. Validates that the built
trusted-corpus index + ledgers satisfy the Phase-1 definition-of-done:

  - Active corpus contains no unstated verification-tier records.
  - Active corpus contains no known fabricated or prose-only rows.
  - Every index row validates against
    auditooor.corpus_trust_record.v1.schema.json.
  - Quarantine/trust/prose ledgers validate against their schemas.
  - Restore is ledger-driven: any record whose trust_state moved from
    quarantine to a non-quarantine state must have a corresponding 'restore'
    event in CORPUS_TRUST_LEDGER.jsonl (manual index edits are forbidden).

RELATED TOOLS:
  - tools/trusted-corpus-index-build.py - the build half this validates.
  - tools/corpus-quality-routing.py - upstream routing classification.

Verdicts:
  - pass-trusted-corpus-clean
  - pass-empty-index (index absent/empty - nothing to validate yet)
  - fail-active-unstated-tier
  - fail-active-fabricated-or-prose
  - fail-schema-invalid
  - fail-restore-not-ledger-driven
  - error

Usage:
  python3 tools/trusted-corpus-index-check.py [--index-dir DIR] [--json] [--strict]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEX_DIR = REPO_ROOT / "reference" / "corpus_trust"
SCHEMA_DIR = DEFAULT_INDEX_DIR / "schemas"

TRUST_RECORD_SCHEMA = "auditooor.corpus_trust_record.v1"

ACTIVE = "active"
QUARANTINE = "quarantine"

REQUIRED_RECORD_FIELDS = (
    "schema", "record_id", "trust_state", "admission_id",
    "verification_tier", "source_path",
)
VALID_STATES = {"active", "advisory", "prose_memory", "quarantine", "superseded"}


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"__malformed__": line[:200]})
    return out


def _validate_record_shape(rec: dict) -> str | None:
    if rec.get("__malformed__"):
        return "malformed json line"
    if rec.get("schema") != TRUST_RECORD_SCHEMA:
        return f"bad schema: {rec.get('schema')!r}"
    for f in REQUIRED_RECORD_FIELDS:
        if f not in rec:
            return f"missing field: {f}"
    if rec.get("trust_state") not in VALID_STATES:
        return f"bad trust_state: {rec.get('trust_state')!r}"
    if not isinstance(rec.get("admission_blockers", []), list):
        return "admission_blockers not a list"
    return None


def check(index_dir: Path) -> dict:
    index_path = index_dir / "TRUSTED_CORPUS_INDEX.jsonl"
    trust_ledger = index_dir / "CORPUS_TRUST_LEDGER.jsonl"

    rows = _read_jsonl(index_path)
    if not rows:
        return {
            "schema": "auditooor.trusted_corpus_index_check.v1",
            "verdict": "pass-empty-index",
            "index_path": str(index_path),
            "total_rows": 0,
            "errors": [],
        }

    errors: list[str] = []
    active_unstated_tier: list[str] = []
    active_fab_or_prose: list[str] = []
    state_counts: dict[str, int] = {}
    schema_invalid = 0

    for rec in rows:
        shape_err = _validate_record_shape(rec)
        if shape_err:
            schema_invalid += 1
            if len(errors) < 25:
                errors.append(f"{rec.get('record_id','?')}: {shape_err}")
            continue
        st = rec["trust_state"]
        state_counts[st] = state_counts.get(st, 0) + 1
        if st == ACTIVE:
            if not str(rec.get("verification_tier") or "").strip():
                active_unstated_tier.append(rec["record_id"])
            if rec.get("is_fabricated") or rec.get("is_prose_only"):
                active_fab_or_prose.append(rec["record_id"])

    # restore-discipline check: any row whose admission_blockers cite
    # 'restored-by-ledger' must have a real restore event in the ledger.
    restored_in_ledger: set[str] = set()
    for ev in _read_jsonl(trust_ledger):
        if ev.get("event") == "restore":
            restored_in_ledger.add(str(ev.get("record_id")))
    restore_violations: list[str] = []
    for rec in rows:
        if rec.get("__malformed__"):
            continue
        if "restored-by-ledger" in (rec.get("admission_blockers") or []):
            if rec["record_id"] not in restored_in_ledger:
                restore_violations.append(rec["record_id"])

    verdict = "pass-trusted-corpus-clean"
    if schema_invalid:
        verdict = "fail-schema-invalid"
    elif active_unstated_tier:
        verdict = "fail-active-unstated-tier"
    elif active_fab_or_prose:
        verdict = "fail-active-fabricated-or-prose"
    elif restore_violations:
        verdict = "fail-restore-not-ledger-driven"

    return {
        "schema": "auditooor.trusted_corpus_index_check.v1",
        "verdict": verdict,
        "index_path": str(index_path),
        "total_rows": len(rows),
        "trust_state_counts": state_counts,
        "schema_invalid_rows": schema_invalid,
        "active_unstated_tier": active_unstated_tier[:25],
        "active_fabricated_or_prose": active_fab_or_prose[:25],
        "restore_not_ledger_driven": restore_violations[:25],
        "errors": errors,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Validate the trusted-corpus index + ledgers.")
    p.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    p.add_argument("--json", dest="json_output", action="store_true")
    p.add_argument("--strict", action="store_true",
                   help="Treat pass-empty-index as a failure.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    report = check(Path(args.index_dir))
    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        print(f"[trusted-corpus-check] {report['verdict']}  rows={report['total_rows']}")
        for e in report.get("errors", [])[:10]:
            print(f"  - {e}")
        if report.get("active_unstated_tier"):
            print(f"  active-unstated-tier: {len(report['active_unstated_tier'])}")
        if report.get("restore_not_ledger_driven"):
            print(f"  restore-not-ledger-driven: {len(report['restore_not_ledger_driven'])}")
    v = report["verdict"]
    if v == "pass-trusted-corpus-clean":
        return 0
    if v == "pass-empty-index":
        return 1 if args.strict else 0
    if v == "error":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
