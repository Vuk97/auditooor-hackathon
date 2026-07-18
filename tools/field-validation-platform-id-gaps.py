#!/usr/bin/env python3
"""Read-only platform-ID backfill gap report for field validation.

The helper scans a workspace's ``submissions/SUBMISSIONS.md`` and
``reference/outcomes.jsonl`` and emits the exact rows still needed to turn
filed-without-platform-ID tracker entries into structured outcome evidence.

It never edits submission drafts, trackers, or ledgers. Optional output files
are report artifacts only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.field_validation_platform_id_gaps.v1"
PENDING_TRACKER = "pending_filed_without_platform_id.jsonl"
REAL_OUTCOME_STATES = {
    "accepted",
    "paid",
    "rewarded",
    "valid",
    "confirmed",
    "duplicate",
    "duplicate_of_accepted",
    "duplicate_of_rejected",
    "rejected",
    "oos",
    "out_of_scope",
    "withdrawn",
    "invalid",
}
PENDING_STATES = {"pending", "submitted", "in_review", "triage", "open", "artifact_present_pending"}


@dataclass(frozen=True)
class Candidate:
    local_id: str
    date: str
    severity: str
    status: str
    title: str
    source: str


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if not path.is_file():
        return rows, errors
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append({"path": str(path), "line": line_no, "error": str(exc)})
            continue
        if isinstance(data, dict):
            rows.append(data)
        else:
            errors.append({"path": str(path), "line": line_no, "error": "expected JSON object"})
    return rows, errors


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _split_md_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _filed_slugs(text: str) -> list[str]:
    slugs: list[str] = []
    for match in re.finditer(r"\bfiled/([^/\s]+)/", text):
        slug = match.group(1).strip()
        if slug and slug not in slugs:
            slugs.append(slug)
    return slugs


def _submitted_without_platform_rows(submissions_path: Path) -> tuple[list[Candidate], list[str]]:
    if not submissions_path.is_file():
        return [], [f"{submissions_path}: missing"]
    text = submissions_path.read_text(encoding="utf-8", errors="replace")
    slugs = _filed_slugs(text)
    rows: list[Candidate] = []
    table_index = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|") or "---" in line:
            continue
        cells = _split_md_row(line)
        if len(cells) < 5:
            continue
        if cells[0].lower() in {"hackenproof #", "cantina #", "report-id", "id"}:
            continue
        status = cells[3]
        if "submitted without platform id" not in status.lower():
            continue
        local_id = slugs[table_index] if table_index < len(slugs) else ""
        table_index += 1
        rows.append(
            Candidate(
                local_id=local_id or f"submission-row-{table_index}",
                date=cells[1],
                severity=cells[2],
                status=status,
                title=cells[4],
                source=str(submissions_path),
            )
        )
    return rows, []


def _pending_tracker_rows(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows, errors = _read_jsonl(path)
    return [row for row in rows if row.get("requires_platform_id_backfill") is True], errors


def _merge_pending_metadata(candidates: list[Candidate], pending_rows: list[dict[str, Any]]) -> list[Candidate]:
    if not pending_rows:
        return candidates
    by_id = {str(row.get("local_id") or row.get("report_id") or ""): row for row in pending_rows}
    merged: list[Candidate] = []
    seen: set[str] = set()
    for candidate in candidates:
        row = by_id.get(candidate.local_id, {})
        merged.append(
            Candidate(
                local_id=candidate.local_id,
                date=candidate.date,
                severity=candidate.severity or str(row.get("severity") or ""),
                status=candidate.status,
                title=candidate.title or str(row.get("title") or ""),
                source=candidate.source,
            )
        )
        seen.add(candidate.local_id)
    for local_id, row in by_id.items():
        if local_id and local_id not in seen:
            merged.append(
                Candidate(
                    local_id=local_id,
                    date="",
                    severity=str(row.get("severity") or ""),
                    status=str(row.get("status") or "artifact_present_pending"),
                    title=str(row.get("title") or ""),
                    source=str(row.get("source_path") or ""),
                )
            )
    return merged


def _has_real_url(row: dict[str, Any]) -> bool:
    url = str(row.get("url") or row.get("report_url") or row.get("platform_url") or "").strip()
    return url.startswith(("http://", "https://"))


def _has_real_report_id(row: dict[str, Any], local_id: str) -> bool:
    report_id = str(row.get("report_id") or row.get("submission_id") or row.get("platform_id") or "").strip()
    if not report_id or report_id in {"-", "—", "pending", "unknown", local_id}:
        return False
    return True


def _has_real_platform(row: dict[str, Any]) -> bool:
    platform = str(row.get("platform") or "").strip().lower()
    return bool(platform and platform not in {"unknown", "pending", "none"})


def _outcome_state(row: dict[str, Any]) -> str:
    for key in ("outcome", "outcome_class", "status", "state", "triager_outcome"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _row_matches_candidate(row: dict[str, Any], candidate: Candidate) -> bool:
    local = candidate.local_id
    if local and any(str(row.get(key) or "") == local for key in ("local_id", "draft_id", "source_local_id")):
        return True
    source = str(row.get("source_path") or row.get("proof_artifact") or row.get("source") or "")
    if local and local in source:
        return True
    title = _norm(candidate.title)
    row_title = _norm(row.get("title"))
    return bool(title and row_title and (title == row_title or title in row_title or row_title in title))


def _real_filing_rows(rows: list[dict[str, Any]], candidate: Candidate) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if _row_matches_candidate(row, candidate)
        and _has_real_platform(row)
        and _has_real_report_id(row, candidate.local_id)
        and _has_real_url(row)
    ]


def _real_outcome_rows(rows: list[dict[str, Any]], candidate: Candidate, filing_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    report_ids = {
        str(row.get("report_id") or row.get("submission_id") or row.get("platform_id") or "").strip()
        for row in filing_rows
    }
    report_ids.discard("")
    out: list[dict[str, Any]] = []
    for row in rows:
        state = _outcome_state(row)
        normalized_state = state.replace(" ", "_")
        if normalized_state not in REAL_OUTCOME_STATES or normalized_state in PENDING_STATES:
            continue
        row_report_id = str(row.get("report_id") or row.get("submission_id") or row.get("platform_id") or "").strip()
        if (row_report_id and row_report_id in report_ids) or _row_matches_candidate(row, candidate):
            out.append(row)
    return out


def _report_id(row: dict[str, Any]) -> str:
    return str(row.get("report_id") or row.get("submission_id") or row.get("platform_id") or "")


def _report_url(row: dict[str, Any]) -> str:
    return str(row.get("url") or row.get("report_url") or row.get("platform_url") or "")


def _commands(workspace: Path, candidate: Candidate, needs_filing: bool, needs_outcome: bool, platform_id: str) -> list[str]:
    cmds: list[str] = []
    if needs_filing:
        cmds.append(
            "make record-submission "
            f"WS={workspace} PLATFORM=hackenproof URL=<real-platform-url> ID=<real-platform-id> "
            f'TITLE="{candidate.title}" SEVERITY={candidate.severity or "<severity>"}'
        )
    if needs_outcome:
        id_arg = platform_id or "<real-platform-id>"
        cmds.append(
            "make record-outcome "
            f"WS={workspace} ID={id_arg} "
            "STATE=<accepted|paid|duplicate|rejected|duplicate_of_accepted|duplicate_of_rejected|withdrawn>"
        )
    if cmds:
        cmds.append(f"make validate-outcome-ledger WS={workspace} JSON=1")
        cmds.append(f"make field-validation-report WS={workspace} JSON=1")
    return cmds


def _next_action_rows(
    workspace: Path,
    candidate: Candidate,
    *,
    needs_filing: bool,
    needs_outcome: bool,
    platform_id: str,
) -> list[dict[str, Any]]:
    action_rows: list[dict[str, Any]] = []
    if needs_filing:
        action_rows.append(
            {
                "action_id": f"{candidate.local_id}:record_submission",
                "action_kind": "record_submission",
                "command": (
                    "make record-submission "
                    f"WS={workspace} PLATFORM=hackenproof URL=<real-platform-url> ID=<real-platform-id> "
                    f'TITLE="{candidate.title}" SEVERITY={candidate.severity or "<severity>"}'
                ),
                "required_fields": ["platform", "real platform id", "real platform url", "title", "severity"],
            }
        )
    if needs_outcome:
        id_arg = platform_id or "<real-platform-id>"
        action_rows.append(
            {
                "action_id": f"{candidate.local_id}:record_outcome",
                "action_kind": "record_outcome",
                "command": (
                    "make record-outcome "
                    f"WS={workspace} ID={id_arg} "
                    "STATE=<accepted|paid|duplicate|rejected|duplicate_of_accepted|duplicate_of_rejected|withdrawn>"
                ),
                "required_fields": ["real platform id", "state"],
            }
        )
    if action_rows:
        action_rows.append(
            {
                "action_id": f"{candidate.local_id}:validate_outcome_ledger",
                "action_kind": "validate_outcome_ledger",
                "command": f"make validate-outcome-ledger WS={workspace} JSON=1",
                "required_fields": [],
            }
        )
        action_rows.append(
            {
                "action_id": f"{candidate.local_id}:field_validation_report",
                "action_kind": "field_validation_report",
                "command": f"make field-validation-report WS={workspace} JSON=1",
                "required_fields": [],
            }
        )
    return action_rows


def build_report(
    workspace: Path,
    *,
    submissions_path: Path | None = None,
    outcomes_path: Path | None = None,
    pending_path: Path | None = None,
) -> dict[str, Any]:
    ws = workspace.expanduser().resolve()
    submissions = (submissions_path or ws / "submissions" / "SUBMISSIONS.md").expanduser().resolve()
    outcomes = (outcomes_path or ws / "reference" / "outcomes.jsonl").expanduser().resolve()
    pending = (pending_path or ws / "reference" / PENDING_TRACKER).expanduser().resolve()

    candidates, candidate_errors = _submitted_without_platform_rows(submissions)
    pending_rows, pending_errors = _pending_tracker_rows(pending)
    candidates = _merge_pending_metadata(candidates, pending_rows)
    outcome_rows, outcome_errors = _read_jsonl(outcomes)

    gaps: list[dict[str, Any]] = []
    complete: list[dict[str, Any]] = []
    next_action_rows: list[dict[str, Any]] = []
    for candidate in candidates:
        filing_rows = _real_filing_rows(outcome_rows, candidate)
        outcome_matches = _real_outcome_rows(outcome_rows, candidate, filing_rows)
        needs_filing = not filing_rows
        needs_outcome = not outcome_matches
        platform_id = _report_id(filing_rows[-1]) if filing_rows else ""
        platform_url = _report_url(filing_rows[-1]) if filing_rows else ""
        row_actions = _next_action_rows(
            ws,
            candidate,
            needs_filing=needs_filing,
            needs_outcome=needs_outcome,
            platform_id=platform_id,
        )
        row = {
            "local_id": candidate.local_id,
            "title": candidate.title,
            "severity": candidate.severity,
            "submission_status": candidate.status,
            "platform_id": platform_id,
            "platform_url": platform_url,
            "needs_platform_filing_row": needs_filing,
            "needs_platform_outcome_row": needs_outcome,
            "required_filing_fields": ["platform", "real platform id", "real platform url", "title", "severity"]
            if needs_filing
            else [],
            "required_outcome_fields": ["real platform id", "state"] if needs_outcome else [],
            "commands": _commands(ws, candidate, needs_filing, needs_outcome, platform_id),
            "next_action_rows": row_actions,
        }
        (gaps if needs_filing or needs_outcome else complete).append(row)
        next_action_rows.extend(row_actions)

    return {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(ws),
        "inputs": {
            "submissions": str(submissions),
            "outcomes": str(outcomes),
            "pending_filed_without_platform_id": str(pending),
        },
        "safety": {
            "read_only_workspace_inputs": True,
            "submissions_edited": False,
            "outcomes_edited": False,
            "pending_tracker_edited": False,
        },
        "counts": {
            "submitted_without_platform_id_candidates": len(candidates),
            "pending_tracker_rows": len(pending_rows),
            "outcome_rows_scanned": len(outcome_rows),
            "gap_rows": len(gaps),
            "complete_rows": len(complete),
            "next_action_rows": len(next_action_rows),
        },
        "gap_rows": gaps,
        "complete_rows": complete,
        "next_action_rows": next_action_rows,
        "parse_errors": candidate_errors + pending_errors + outcome_errors,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Field Validation Platform-ID Gaps",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "This is a read-only backfill helper. It did not edit `SUBMISSIONS.md`, `outcomes.jsonl`, or the pending tracker.",
        "",
        "## Summary",
        "",
        f"- Submitted-without-platform-ID candidates: {report['counts']['submitted_without_platform_id_candidates']}",
        f"- Gap rows: {report['counts']['gap_rows']}",
        f"- Complete rows: {report['counts']['complete_rows']}",
        "",
        "## Missing Rows",
        "",
        "| Local ID | Severity | Missing platform row | Missing outcome row | Title |",
        "|---|---|---:|---:|---|",
    ]
    for row in report["gap_rows"]:
        lines.append(
            "| {local_id} | {severity} | {filing} | {outcome} | {title} |".format(
                local_id=row["local_id"],
                severity=row["severity"],
                filing="yes" if row["needs_platform_filing_row"] else "no",
                outcome="yes" if row["needs_platform_outcome_row"] else "no",
                title=row["title"].replace("|", "\\|"),
            )
        )
    if not report["gap_rows"]:
        lines.append("| (none) |  |  |  |  |")
    lines.extend(["", "## Operator Commands", ""])
    for row in report["gap_rows"]:
        lines.append(f"### {row['local_id']}")
        lines.append("")
        for command in row["commands"]:
            lines.append(f"- `{command}`")
        lines.append("")
    if report["parse_errors"]:
        lines.extend(["## Parse Errors", ""])
        for error in report["parse_errors"]:
            lines.append(f"- `{error}`")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", "-w", type=Path, required=True)
    parser.add_argument("--submissions", type=Path)
    parser.add_argument("--outcomes", type=Path)
    parser.add_argument("--pending", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--json", action="store_true", help="print JSON to stdout")
    args = parser.parse_args(argv)

    report = build_report(
        args.workspace,
        submissions_path=args.submissions,
        outcomes_path=args.outcomes,
        pending_path=args.pending,
    )
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(render_markdown(report), encoding="utf-8")
    if args.json or not (args.out_json or args.out_md):
        print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["parse_errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
