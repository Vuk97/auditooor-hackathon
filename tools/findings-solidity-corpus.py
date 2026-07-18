#!/usr/bin/env python3
"""findings-solidity-corpus.py — validator for reference/findings_solidity.jsonl.

Asserts every row in the Solidity-language findings corpus has the required
fields and that language=="solidity". Exit non-zero on any violation. Stdlib-only.

Usage:
    python3 tools/findings-solidity-corpus.py [--path PATH] [--json]

Used by Makefile target ``findings-solidity-validate`` and by the regression test
``tools/tests/test_findings_solidity_corpus.py``.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any


REPO = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_PATH = REPO / "reference" / "findings_solidity.jsonl"

REQUIRED_FIELDS = (
    "finding_id",
    "protocol",
    "language",
    "impact_tier",
    "bug_class",
    "github_ref",
    "summary",
    "provenance",
)

ALLOWED_TIERS = {"critical", "high", "medium", "low", "informational"}


def validate_row(row: dict[str, Any], idx: int) -> list[str]:
    errors: list[str] = []
    for f in REQUIRED_FIELDS:
        if f not in row:
            errors.append(f"row {idx}: missing required field '{f}'")
            continue
        v = row[f]
        if v is None or (isinstance(v, str) and not v.strip()):
            errors.append(f"row {idx}: required field '{f}' is empty")
    if "language" in row and row["language"] != "solidity":
        errors.append(
            f"row {idx}: language must be 'solidity' (got {row['language']!r}); "
            f"corpus is Solidity-scoped"
        )
    if "impact_tier" in row and row["impact_tier"] not in ALLOWED_TIERS:
        errors.append(
            f"row {idx}: impact_tier {row['impact_tier']!r} not in "
            f"{sorted(ALLOWED_TIERS)}"
        )
    if "provenance" in row and not isinstance(row["provenance"], dict):
        errors.append(f"row {idx}: provenance must be a dict")
    return errors


def validate_file(path: pathlib.Path) -> tuple[int, list[str]]:
    if not path.exists():
        return 0, [f"file not found: {path}"]
    errors: list[str] = []
    rows = 0
    seen_ids: set[str] = set()
    with path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                errors.append(f"line {lineno}: invalid JSON: {exc}")
                continue
            rows += 1
            errors.extend(validate_row(row, lineno))
            fid = row.get("finding_id")
            if fid:
                if fid in seen_ids:
                    errors.append(f"line {lineno}: duplicate finding_id {fid!r}")
                seen_ids.add(fid)
    return rows, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path",
        type=pathlib.Path,
        default=DEFAULT_PATH,
        help="Path to findings_solidity.jsonl (default: reference/findings_solidity.jsonl)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary on stdout",
    )
    args = parser.parse_args(argv)

    rows, errors = validate_file(args.path)
    if args.json:
        print(json.dumps({
            "path": str(args.path),
            "rows": rows,
            "errors": errors,
            "ok": not errors,
        }, indent=2))
    else:
        print(f"validated {rows} rows from {args.path}")
        for e in errors:
            print(f"  ERROR: {e}", file=sys.stderr)
        if not errors:
            print("PASS: all rows have required fields and language=='solidity'")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
