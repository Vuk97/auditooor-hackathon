#!/usr/bin/env python3
"""Validate operator-supplied resolved-outcome calibration linkage rows.

This is the strict import gate between raw resolved triager outcomes and
outcome-calibration scorecards. It accepts only durable linkage rows supplied in
``.audit_logs/outcome_calibration/outcome_calibration_resolved_linkage_rows.jsonl``.

It never invents accepted/rejected/duplicate outcomes. A row is calibration
ready only when it matches an existing resolved outcome and carries every
required linkage field plus a local proof artifact.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from outcome_semantics import derive_outcome_semantics


SCHEMA = "auditooor.outcome_calibration_resolved_linkage_validator.v1"
ROW_SCHEMA = "auditooor.outcome_calibration_resolved_linkage.v1"
DEFAULT_OUTCOME_JSON = ".audit_logs/outcome_calibration/outcome_telemetry.json"
DEFAULT_LINKAGE_JSONL = ".audit_logs/outcome_calibration/outcome_calibration_resolved_linkage_rows.jsonl"
DEFAULT_TERMINAL_ROWS_JSONL = ".audit_logs/outcome_calibration/outcome_calibration_terminal_rows.jsonl"
DEFAULT_OUT_JSON = ".audit_logs/outcome_calibration/outcome_calibration_resolved_linkage_validation.json"
DEFAULT_OUT_MD = ".audit_logs/outcome_calibration/outcome_calibration_resolved_linkage_validation.md"
RESOLVED_OUTCOMES = {"accepted", "duplicate", "rejected"}
LINKAGE_FIELDS = (
    "lane",
    "model_route",
    "proof_artifact",
    "production_path_status",
    "production_path_blockers_cleared",
    "final_triager_outcome",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_str(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def resolve_path(workspace: Path, path: Path | None, default: str) -> Path:
    candidate = path or Path(default)
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[outcome-calibration-resolved-linkage-validator] invalid JSON {path}: {exc}") from None


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            rows.append({"_invalid_json": True, "_line": lineno, "_error": str(exc)})
            continue
        if isinstance(row, dict):
            row["_line"] = lineno
            rows.append(row)
        else:
            rows.append({"_invalid_json": True, "_line": lineno, "_error": "row_not_object"})
    return rows


def records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    records = payload.get("records")
    return [row for row in records if isinstance(row, dict)] if isinstance(records, list) else []


def outcome_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        safe_str(row.get("workspace")).lower(),
        safe_str(row.get("finding_id")).lower(),
        safe_str(row.get("title")).lower(),
    )


def terminal_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        safe_str(row.get("workspace")).lower(),
        safe_str(row.get("finding_id")).lower(),
        safe_str(row.get("title")).lower(),
    )


def build_terminal_index(rows: Sequence[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        if row.get("schema") != "auditooor.outcome_calibration_terminal_row.v1":
            continue
        workspace = safe_str(row.get("workspace")).lower()
        finding_id = safe_str(row.get("finding_id")).lower()
        report_id = safe_str(row.get("report_id")).lower()
        title = safe_str(row.get("title")).lower()
        for key in (
            (workspace, finding_id, title),
            (workspace, finding_id, ""),
            (workspace, report_id, ""),
            (workspace, "", title),
        ):
            if workspace and (finding_id or report_id or title) and any(key[1:]):
                index[key] = row
    return index


def build_outcome_index(records: Sequence[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in records:
        if not calibration_eligible_resolved_outcome(row):
            continue
        workspace = safe_str(row.get("workspace")).lower()
        finding_id = safe_str(row.get("finding_id")).lower()
        title = safe_str(row.get("title")).lower()
        for key in (
            (workspace, finding_id, title),
            (workspace, finding_id, ""),
            (workspace, "", title),
        ):
            if any(key):
                index[key] = row
    return index


def calibration_eligible_resolved_outcome(row: dict[str, Any]) -> bool:
    semantics = derive_outcome_semantics(row)
    return semantics.outcome in RESOLVED_OUTCOMES and semantics.eligible_for_learning


def lookup_record(
    row: dict[str, Any],
    outcome_index: dict[tuple[str, str, str], dict[str, Any]],
    terminal_index: dict[tuple[str, str, str], dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    workspace = safe_str(row.get("workspace")).lower()
    finding_id = safe_str(row.get("finding_id")).lower()
    report_id = safe_str(row.get("report_id")).lower()
    title = safe_str(row.get("title")).lower()
    keys = [
        (workspace, finding_id, title),
        (workspace, finding_id, ""),
        (workspace, report_id, ""),
        (workspace, "", title),
    ]
    if not finding_id:
        keys.append((workspace, "unknown", ""))
    terminal_row = next((terminal_index[key] for key in keys if key in terminal_index), None)
    outcome_row = next((outcome_index[key] for key in keys if key in outcome_index), None)
    if outcome_row is None and terminal_row is not None:
        term_finding = safe_str(terminal_row.get("finding_id")).lower()
        term_title = safe_str(terminal_row.get("title")).lower()
        outcome_row = outcome_index.get((workspace, term_finding, term_title)) or outcome_index.get((workspace, term_finding, ""))
    return outcome_row, terminal_row


def row_identity(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        safe_str(row.get("workspace")).lower(),
        safe_str(row.get("finding_id")).lower(),
        safe_str(row.get("title")).lower(),
    )


def proof_artifact_exists(workspace: Path, raw: str) -> bool:
    if not raw or raw.startswith("<") or raw.endswith(">"):
        return False
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = workspace / path
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return resolved.exists()


def validate_linkage_row(
    workspace: Path,
    row: dict[str, Any],
    outcome_index: dict[tuple[str, str, str], dict[str, Any]],
    terminal_index: dict[tuple[str, str, str], dict[str, Any]],
) -> dict[str, Any]:
    problems: list[str] = []
    if row.get("_invalid_json"):
        problems.append("invalid_json")
    if row.get("schema") != ROW_SCHEMA:
        problems.append("schema_mismatch")
    missing = [field for field in LINKAGE_FIELDS if not safe_str(row.get(field))]
    problems.extend(f"missing_{field}" for field in missing)
    if not proof_artifact_exists(workspace, safe_str(row.get("proof_artifact"))):
        problems.append("proof_artifact_missing")
    outcome_row, terminal_row = lookup_record(row, outcome_index, terminal_index)
    if outcome_row is None:
        problems.append("no_matching_resolved_outcome")
    outcome = safe_str(row.get("final_triager_outcome"))
    known_outcome = (
        derive_outcome_semantics(outcome_row).outcome
        if outcome_row
        else safe_str(terminal_row.get("terminal_outcome")) if terminal_row else ""
    )
    if outcome not in RESOLVED_OUTCOMES:
        problems.append("invalid_final_triager_outcome")
    elif known_outcome and outcome != known_outcome:
        problems.append("final_triager_outcome_mismatch")
    production_status = safe_str(row.get("production_path_status")).lower()
    if production_status in {"", "missing", "blocked", "unknown", "not_proven", "unproved"}:
        problems.append("production_path_not_verified")
    blockers_cleared = row.get("production_path_blockers_cleared")
    if blockers_cleared is False or safe_str(blockers_cleared).lower() in {"", "false", "no", "0", "blocked", "unknown"}:
        problems.append("production_path_blockers_not_cleared")
    return {
        "line": row.get("_line"),
        "workspace": safe_str(row.get("workspace")),
        "finding_id": safe_str(row.get("finding_id")),
        "report_id": safe_str(row.get("report_id")),
        "title": safe_str(row.get("title")),
        "final_triager_outcome": outcome,
        "known_outcome": known_outcome,
        "valid_for_calibration": not problems,
        "problem_codes": sorted(set(problems)),
        "matched_outcome": bool(outcome_row),
        "matched_terminal_row": bool(terminal_row),
        "proof_artifact": safe_str(row.get("proof_artifact")),
        "lane": safe_str(row.get("lane")),
        "model_route": safe_str(row.get("model_route")),
        "production_path_status": safe_str(row.get("production_path_status")),
    }


def build_payload(
    *,
    workspace: Path,
    outcome_json: Sequence[Path],
    linkage_jsonl: Path,
    terminal_rows_jsonl: Sequence[Path],
) -> dict[str, Any]:
    outcome_records: list[dict[str, Any]] = []
    for path in outcome_json:
        outcome_records.extend(records_from_payload(read_json(path)))
    terminal_rows: list[dict[str, Any]] = []
    for path in terminal_rows_jsonl:
        terminal_rows.extend(read_jsonl(path))
    linkage_rows = read_jsonl(linkage_jsonl)
    outcome_index = build_outcome_index(outcome_records)
    terminal_index = build_terminal_index(terminal_rows)
    validations = [
        validate_linkage_row(workspace, row, outcome_index, terminal_index)
        for row in linkage_rows
    ]
    resolved_all = [
        row for row in outcome_records
        if derive_outcome_semantics(row).outcome in RESOLVED_OUTCOMES
    ]
    base_rate_only_resolved = [
        row for row in resolved_all
        if derive_outcome_semantics(row).base_rate_only_rejection
    ]
    resolved = [row for row in resolved_all if calibration_eligible_resolved_outcome(row)]
    valid = [row for row in validations if row["valid_for_calibration"]]
    validations_by_identity: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in validations:
        keys = [
            row_identity(row),
            (safe_str(row.get("workspace")).lower(), safe_str(row.get("finding_id")).lower(), ""),
            (safe_str(row.get("workspace")).lower(), "", safe_str(row.get("title")).lower()),
        ]
        for key in keys:
            if any(key):
                validations_by_identity.setdefault(key, []).append(row)

    resolved_units: list[dict[str, Any]] = []
    terminalized = 0
    for record in resolved:
        record_keys = [
            row_identity(record),
            (safe_str(record.get("workspace")).lower(), safe_str(record.get("finding_id")).lower(), ""),
            (safe_str(record.get("workspace")).lower(), "", safe_str(record.get("title")).lower()),
        ]
        matched_valid = next(
            (
                item for key in record_keys
                for item in validations_by_identity.get(key, [])
                if item["valid_for_calibration"]
            ),
            None,
        )
        matched_invalid = [
            item for key in record_keys
            for item in validations_by_identity.get(key, [])
            if not item["valid_for_calibration"]
        ]
        terminal_row = lookup_record(record, outcome_index, terminal_index)[1]
        if any(
            safe_str(item.get("workspace")).lower() == safe_str(record.get("workspace")).lower()
            and (
                safe_str(item.get("finding_id")).lower() == safe_str(record.get("finding_id")).lower()
                or safe_str(item.get("title")).lower() == safe_str(record.get("title")).lower()
            )
            for item in valid
        ):
            resolved_units.append({
                "workspace": safe_str(record.get("workspace")),
                "finding_id": safe_str(record.get("finding_id")),
                "title": safe_str(record.get("title")),
                "known_outcome": safe_str(record.get("outcome")),
                "state": "linked_for_calibration",
                "valid_linkage_line": matched_valid.get("line") if matched_valid else None,
                "problem_codes": [],
                "next_command": "none; strict resolved-outcome linkage is valid for calibration",
            })
            continue
        if terminal_row is not None:
            terminalized += 1
            resolved_units.append({
                "workspace": safe_str(record.get("workspace")),
                "finding_id": safe_str(record.get("finding_id")),
                "title": safe_str(record.get("title")),
                "known_outcome": safe_str(record.get("outcome")),
                "state": "terminalized_missing_linkage_not_calibration",
                "terminal_row_report_id": safe_str(terminal_row.get("report_id")),
                "terminal_row_status": safe_str(terminal_row.get("terminal_row_status")),
                "problem_codes": [],
                "next_command": "do not fabricate linkage; add a strict linkage row only if real platform/proof evidence exists",
            })
            continue
        problem_codes = sorted({problem for item in matched_invalid for problem in item["problem_codes"]})
        resolved_units.append({
            "workspace": safe_str(record.get("workspace")),
            "finding_id": safe_str(record.get("finding_id")),
            "title": safe_str(record.get("title")),
            "known_outcome": safe_str(record.get("outcome")),
            "state": "invalid_strict_linkage_row" if matched_invalid else "missing_strict_linkage_row",
            "invalid_linkage_lines": [item.get("line") for item in matched_invalid],
            "problem_codes": problem_codes,
            "next_command": (
                "repair the strict linkage row with real lane/model/proof/production-path evidence"
                if matched_invalid
                else "create outcome_calibration_resolved_linkage_rows.jsonl only from real platform/proof evidence"
            ),
        })
    valid_keys = {
        (safe_str(row.get("workspace")).lower(), safe_str(row.get("finding_id")).lower(), safe_str(row.get("title")).lower())
        for row in valid
    }
    missing = max(0, len(resolved) - len(valid_keys) - terminalized)
    problem_counts = Counter(problem for row in validations for problem in row["problem_codes"])
    return {
        "schema": SCHEMA,
        "generated_at_utc": now_iso(),
        "workspace": str(workspace),
        "advisory_only": True,
        "promotion_authority": False,
        "no_invented_acceptance_or_rejection": True,
        "inputs": {
            "outcome_json": [str(path) for path in outcome_json],
            "linkage_jsonl": str(linkage_jsonl),
            "terminal_rows_jsonl": [str(path) for path in terminal_rows_jsonl],
        },
        "summary": {
            "resolved_outcome_rows": len(resolved),
            "resolved_outcome_rows_total": len(resolved_all),
            "base_rate_only_resolved_rows": len(base_rate_only_resolved),
            "linkage_rows_seen": len(linkage_rows),
            "valid_linked_rows": len(valid),
            "invalid_linkage_rows": len(validations) - len(valid),
            "terminalized_missing_linkage_rows": terminalized,
            "missing_linkage_rows": missing,
            "all_resolved_rows_accounted_for": missing == 0 and len(resolved) == len(valid_keys) + terminalized,
            "calibration_closure_status": (
                "linked_rows_validated"
                if valid
                else "no_calibration_eligible_resolved_rows"
                if not resolved
                else "terminalized_missing_linkage_not_calibration"
                if missing == 0 and resolved
                else "open_missing_linkage"
            ),
            "problem_counts": dict(sorted(problem_counts.items())),
            "resolved_unit_state_counts": dict(sorted(Counter(row["state"] for row in resolved_units).items())),
        },
        "valid_rows": valid,
        "resolved_row_units": resolved_units,
        "rows": validations,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Outcome Calibration Resolved-Linkage Validation",
        "",
        "Strict import gate for resolved outcome rows. This validates linkage; it does not invent outcomes.",
        "",
        f"- resolved outcome rows: `{summary['resolved_outcome_rows']}`",
        f"- linkage rows seen: `{summary['linkage_rows_seen']}`",
        f"- valid linked rows: `{summary['valid_linked_rows']}`",
        f"- invalid linkage rows: `{summary['invalid_linkage_rows']}`",
        f"- terminalized missing-linkage rows: `{summary['terminalized_missing_linkage_rows']}`",
        f"- missing linkage rows: `{summary['missing_linkage_rows']}`",
        f"- closure status: `{summary['calibration_closure_status']}`",
        "",
        "## Resolved Row Units",
        "",
        "| Workspace | Finding | Outcome | State | Next Command |",
        "|---|---|---|---|---|",
    ]
    for row in payload.get("resolved_row_units", []):
        command = safe_str(row.get("next_command")).replace("|", "\\|")
        lines.append(
            f"| `{row['workspace']}` | `{row['finding_id']}` | `{row['known_outcome']}` | "
            f"`{row['state']}` | {command} |"
        )
    lines.extend([
        "",
        "## Rows",
        "",
        "| Line | Workspace | Finding | Outcome | Valid | Problems |",
        "|---:|---|---|---|---|---|",
    ])
    for row in payload["rows"]:
        problems = ", ".join(row["problem_codes"]) or "-"
        lines.append(
            f"| {row.get('line') or ''} | `{row['workspace']}` | `{row['finding_id'] or row['report_id']}` | "
            f"`{row['final_triager_outcome']}` | `{str(row['valid_for_calibration']).lower()}` | {problems} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def write_outputs(payload: dict[str, Any], out_json: Path, out_md: Path | None) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if out_md is not None:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(payload), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--outcome-json", action="append", type=Path, default=[])
    parser.add_argument("--linkage-jsonl", type=Path)
    parser.add_argument("--terminal-rows-jsonl", action="append", type=Path, default=[])
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    outcome_json = [resolve_path(workspace, path, DEFAULT_OUTCOME_JSON) for path in args.outcome_json] or [resolve_path(workspace, None, DEFAULT_OUTCOME_JSON)]
    terminal_rows = [resolve_path(workspace, path, DEFAULT_TERMINAL_ROWS_JSONL) for path in args.terminal_rows_jsonl] or [resolve_path(workspace, None, DEFAULT_TERMINAL_ROWS_JSONL)]
    payload = build_payload(
        workspace=workspace,
        outcome_json=outcome_json,
        linkage_jsonl=resolve_path(workspace, args.linkage_jsonl, DEFAULT_LINKAGE_JSONL),
        terminal_rows_jsonl=terminal_rows,
    )
    out_json = resolve_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = resolve_path(workspace, args.out_md, DEFAULT_OUT_MD) if args.out_md is not None else resolve_path(workspace, None, DEFAULT_OUT_MD)
    write_outputs(payload, out_json, out_md)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
