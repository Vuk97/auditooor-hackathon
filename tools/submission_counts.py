#!/usr/bin/env python3
"""Derive submission stats from a workspace's SUBMISSIONS.md."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SUBMISSION_FILE_CANDIDATES = (
    Path("submissions/SUBMISSIONS.md"),
    Path("SUBMISSIONS.md"),
)

SUBMITTED_STATUS_TOKENS = (
    "submitted",
    "pending",
    "in review",
    "duplicate",
    "rejected",
    "paid",
    "accepted",
    "triaged",
)

DRAFT_STATUS_TOKENS = (
    "draft",
    "ready_to_submit",
    "ready to submit",
    "packaged",
    "on_hold",
    "on hold",
)


def _strip_markup(value: str) -> str:
    value = value.replace("**", "").replace("`", "")
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def find_submission_file(workspace: Path) -> Path | None:
    for rel in SUBMISSION_FILE_CANDIDATES:
        candidate = workspace / rel
        if candidate.is_file():
            return candidate
    return None


def _iter_markdown_tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    lines = text.splitlines()
    tables: list[tuple[list[str], list[list[str]]]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.startswith("|"):
            i += 1
            continue
        if i + 1 >= len(lines) or not lines[i + 1].startswith("|"):
            i += 1
            continue
        header = [_strip_markup(cell) for cell in line.split("|") if cell.strip()]
        divider = lines[i + 1]
        if "---" not in divider:
            i += 1
            continue
        rows: list[list[str]] = []
        i += 2
        while i < len(lines) and lines[i].startswith("|"):
            row = [_strip_markup(cell) for cell in lines[i].split("|") if cell.strip()]
            if row and "---" not in "".join(row):
                rows.append(row)
            i += 1
        tables.append((header, rows))
    return tables


def _parse_table_counts(text: str) -> dict[str, int]:
    counts = {"submitted": 0, "drafts": 0, "duplicates": 0, "in_review": 0}
    for header, rows in _iter_markdown_tables(text):
        normalized = [cell.lower() for cell in header]
        if "status" not in normalized:
            continue
        if not any(key in normalized for key in ("title", "cantina #", "cantina", "id")):
            continue

        status_idx = normalized.index("status")
        ident_idx = next(
            (i for i, cell in enumerate(normalized) if cell in {"cantina #", "cantina", "id"}),
            None,
        )

        for row in rows:
            if status_idx >= len(row):
                continue
            status = row[status_idx].lower()
            ident = row[ident_idx] if ident_idx is not None and ident_idx < len(row) else ""
            ident_has_number = bool(re.search(r"\d", ident))
            is_draft = any(token in status for token in DRAFT_STATUS_TOKENS)
            is_submitted = ident_has_number or any(token in status for token in SUBMITTED_STATUS_TOKENS)

            if is_draft and not ident_has_number:
                counts["drafts"] += 1
            elif is_submitted:
                counts["submitted"] += 1

            if "duplicate" in status:
                counts["duplicates"] += 1
            if "review" in status:
                counts["in_review"] += 1
    return counts


def summarize_submission_file(path: Path) -> dict[str, Any]:
    text = path.read_text()
    counts = _parse_table_counts(text)
    source_kind = "table" if any(counts.values()) else "none"

    if source_kind == "none":
        comment_hits = re.findall(r"<!--\s*CANTINA-ID:\d+\s*-->", text)
        if comment_hits:
            counts["submitted"] = len(comment_hits)
            source_kind = "cantina-comments"

    if source_kind == "none":
        status_hits = re.findall(r"^\*\*Status:\*\*.*\bSUBMITTED\b", text, flags=re.IGNORECASE | re.MULTILINE)
        if status_hits:
            counts["submitted"] = len(status_hits)
            source_kind = "status-lines"

    return {
        "path": str(path),
        "source_kind": source_kind,
        **counts,
    }


def summarize_workspace(workspace: Path) -> dict[str, Any]:
    path = find_submission_file(workspace)
    if path is None:
        return {
            "path": None,
            "source_kind": "missing",
            "submitted": 0,
            "drafts": 0,
            "duplicates": 0,
            "in_review": 0,
        }
    return summarize_submission_file(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize submissions from SUBMISSIONS.md")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        raise SystemExit(f"workspace not found: {workspace}")

    summary = summarize_workspace(workspace)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        source = summary["source_kind"]
        print(f"workspace: {workspace.name}")
        print(f"source: {source}")
        print(f"submitted: {summary['submitted']}")
        print(f"drafts: {summary['drafts']}")
        print(f"duplicates: {summary['duplicates']}")
        print(f"in_review: {summary['in_review']}")
        if summary["path"]:
            print(f"path: {summary['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
