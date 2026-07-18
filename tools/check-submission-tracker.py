#!/usr/bin/env python3
"""Validate a workspace's canonical SUBMISSIONS.md tracker."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from submission_counts import (
    DRAFT_STATUS_TOKENS,
    SUBMITTED_STATUS_TOKENS,
    _iter_markdown_tables,
    find_submission_file,
    summarize_workspace,
)


def _nearest_heading(lines: list[str], line_no: int) -> str:
    for i in range(line_no, -1, -1):
        line = lines[i].strip()
        if line.startswith("#"):
            return line.lstrip("#").strip().lower()
    return ""


def validate_workspace(workspace: Path) -> dict[str, Any]:
    path = find_submission_file(workspace)
    errors: list[str] = []
    warnings: list[str] = []

    if path is None:
        errors.append("missing canonical SUBMISSIONS.md")
        return {"ok": False, "errors": errors, "warnings": warnings, "summary": summarize_workspace(workspace)}

    text = path.read_text()
    lines = text.splitlines()
    summary = summarize_workspace(workspace)

    table_start_line = 0
    for header, rows in _iter_markdown_tables(text):
        normalized = [cell.lower() for cell in header]
        if "status" not in normalized:
            table_start_line += len(rows) + 2
            continue

        heading = _nearest_heading(lines, table_start_line)
        status_idx = normalized.index("status")
        ident_idx = next(
            (i for i, cell in enumerate(normalized) if cell in {"cantina #", "cantina", "id"}),
            None,
        )

        if "submitted" in heading:
            for row in rows:
                if status_idx >= len(row):
                    continue
                status = row[status_idx].lower()
                ident = row[ident_idx] if ident_idx is not None and ident_idx < len(row) else ""
                ident_has_number = bool(re.search(r"\d", ident))
                if any(token in status for token in DRAFT_STATUS_TOKENS):
                    errors.append("draft row found inside submitted table")
                    break
                if not ident_has_number and any(token in status for token in SUBMITTED_STATUS_TOKENS):
                    warnings.append("submitted-style row in submitted table has no platform identifier")

        table_start_line += len(rows) + 2

    totals_match = re.search(r"Totals submitted:\s*(\d+)", text, flags=re.IGNORECASE)
    if totals_match:
        declared_total = int(totals_match.group(1))
        if declared_total != summary["submitted"]:
            errors.append(
                f"totals line says {declared_total} submitted but parsed tracker has {summary['submitted']}"
            )

    deposit_match = re.search(r"Deposit:\s*\$?(\d+)\s*[x×]\s*(\d+)\s*=", text, flags=re.IGNORECASE)
    if deposit_match:
        deposited_count = int(deposit_match.group(2))
        if deposited_count != summary["submitted"]:
            errors.append(
                f"deposit line says {deposited_count} findings but parsed tracker has {summary['submitted']}"
            )

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a workspace SUBMISSIONS.md tracker")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        raise SystemExit(f"workspace not found: {workspace}")

    result = validate_workspace(workspace)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        summary = result["summary"]
        print(f"[submission-tracker] workspace: {workspace.name}")
        print(f"[submission-tracker] source: {summary['source_kind']}")
        print(f"[submission-tracker] submitted: {summary['submitted']}")
        if result["warnings"]:
            for warning in result["warnings"]:
                print(f"[submission-tracker] WARN: {warning}")
        if result["errors"]:
            for error in result["errors"]:
                print(f"[submission-tracker] FAIL: {error}")
            return 1
        print("[submission-tracker] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
