#!/usr/bin/env python3
"""Emit uncategorized Solodit detector-gap findings for taxonomy assignment.

This helper is deliberately advisory-only. It reads the machine-readable
detector gap report and extracts rows still classified as ``uncategorized`` so
G1 work can assign concrete taxonomy before any detector-writing dispatch.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO / "reports" / "detector_gap.json"
SCHEMA = "auditooor.solodit_taxonomy_triage.v0"


class TriageInputError(ValueError):
    """Raised when the source report cannot be trusted."""


def _string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = None
        for key in ("rows", "findings", "results"):
            candidate = payload.get(key)
            if isinstance(candidate, list):
                rows = candidate
                break
        if rows is None:
            raise TriageInputError(
                "expected a JSON list or an object with rows/findings/results"
            )
    else:
        raise TriageInputError("expected detector gap JSON to be a list or object")

    bad = [idx for idx, row in enumerate(rows) if not isinstance(row, dict)]
    if bad:
        raise TriageInputError(f"expected all rows to be objects; bad index {bad[0]}")
    return rows


def load_gap_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise TriageInputError(f"missing detector gap JSON: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TriageInputError(f"invalid JSON in {path}: {exc}") from exc
    return _rows_from_payload(payload)


def _coerce_signals(row: dict[str, Any]) -> list[str]:
    raw = row.get("signals")
    signals: list[str] = []
    if isinstance(raw, list):
        signals.extend(_string(item) for item in raw if _string(item))
    elif isinstance(raw, dict):
        for key in sorted(raw):
            value = raw[key]
            if value in (None, "", [], {}):
                continue
            signals.append(f"{key}: {_string(value)}")
    elif _string(raw):
        signals.append(_string(raw))

    severity = _string(row.get("severity"))
    if severity:
        signals.append(f"severity: {severity}")

    analysis_mode = _string(row.get("analysis_mode"))
    if analysis_mode:
        signals.append(f"analysis_mode: {analysis_mode}")

    github_ref = row.get("github_ref")
    if isinstance(github_ref, dict):
        repo = _string(github_ref.get("repo"))
        filepath = _string(github_ref.get("filepath"))
        commit = _string(github_ref.get("commit"))
        if repo or filepath:
            ref = "/".join(part for part in (repo, filepath) if part)
            if commit:
                ref = f"{ref}@{commit[:8]}" if ref else commit[:8]
            signals.append(f"github_ref: {ref}")

    url = _string(row.get("solodit_url") or row.get("url"))
    if url:
        signals.append(f"solodit_url: {url}")

    return list(dict.fromkeys(signals))


def is_uncategorized_gap(row: dict[str, Any]) -> bool:
    """Select rows that need taxonomy assignment before detector work."""
    if _string(row.get("status") or "analyzed") != "analyzed":
        return False
    if _string(row.get("bug_class") or row.get("classification")) != "uncategorized":
        return False
    return row.get("is_blindspot") is True


def build_worklist(rows: list[dict[str, Any]], source: Path) -> dict[str, Any]:
    work_rows: list[dict[str, Any]] = []
    for row in rows:
        if not is_uncategorized_gap(row):
            continue
        finding_id = _string(
            row.get("finding_id") or row.get("id") or row.get("solodit_id")
        )
        title = _string(row.get("title") or row.get("name"))
        work_rows.append(
            {
                "finding_id": finding_id,
                "title": title,
                "signals": _coerce_signals(row),
                "taxonomy_status": "uncategorized",
                "next_action": "assign_concrete_bug_class_before_detector_work",
            }
        )

    return {
        "schema": SCHEMA,
        "source": str(source),
        "advisory_only": True,
        "promotion_authority": False,
        "limits": [
            "Does not assess detector coverage.",
            "Does not assess submission readiness.",
        ],
        "input_row_count": len(rows),
        "uncategorized_count": len(work_rows),
        "rows": work_rows,
    }


def _md_cell(value: Any) -> str:
    text = _string(value).replace("|", "\\|")
    return text.replace("\n", " ")


def render_markdown(worklist: dict[str, Any]) -> str:
    lines = [
        "# Solodit Taxonomy Triage",
        "",
        "Advisory-only worklist for G1 taxonomy assignment.",
        "",
        "- Does not assess detector coverage.",
        "- Does not assess submission readiness.",
        f"- Source: `{worklist.get('source', '')}`",
        f"- Uncategorized findings: `{worklist.get('uncategorized_count', 0)}`",
        "",
        "| Finding ID | Title | Signals | Next action |",
        "|---|---|---|---|",
    ]
    for row in worklist.get("rows", []):
        signals = "; ".join(row.get("signals", []))
        lines.append(
            "| "
            f"{_md_cell(row.get('finding_id'))} | "
            f"{_md_cell(row.get('title'))} | "
            f"{_md_cell(signals)} | "
            f"{_md_cell(row.get('next_action'))} |"
        )
    if not worklist.get("rows"):
        lines.append("| | No matching uncategorized rows found in input. | | |")
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract uncategorized detector-gap findings for manual taxonomy "
            "assignment. This tool is advisory-only."
        )
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT,
        help="Detector gap JSON path (default: reports/detector_gap.json)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument("--output", type=Path, help="Write output to this path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        rows = load_gap_rows(args.input)
        worklist = build_worklist(rows, args.input)
    except TriageInputError as exc:
        print(f"solodit-taxonomy-triage: {exc}", file=sys.stderr)
        return 2

    if args.format == "markdown":
        rendered = render_markdown(worklist)
    else:
        rendered = json.dumps(worklist, indent=2, sort_keys=True) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
