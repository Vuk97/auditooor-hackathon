#!/usr/bin/env python3
"""Import real terminal route evidence into outcome-calibration linkage rows.

This is a deliberately narrow gate. Provider/local route verdicts may be
``TRUE``, ``FALSE``, or ``PARTIAL``, but they become resolved-outcome
calibration linkage only when they match an already-resolved triager outcome and
carry durable lane/model/proof/production-path evidence.

Input rows live in
``.audit_logs/outcome_calibration/outcome_calibration_route_evidence_rows.jsonl``.
Valid rows are converted into
``.audit_logs/outcome_calibration/outcome_calibration_resolved_linkage_rows.jsonl``.
The tool never invents accepted/rejected/duplicate outcomes.
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


SCHEMA = "auditooor.outcome_calibration_route_evidence_importer.v1"
INPUT_ROW_SCHEMA = "auditooor.outcome_calibration_route_evidence.v1"
OUTPUT_ROW_SCHEMA = "auditooor.outcome_calibration_resolved_linkage.v1"
DEFAULT_OUTCOME_JSON = ".audit_logs/outcome_calibration/outcome_telemetry.json"
DEFAULT_INPUT_JSONL = ".audit_logs/outcome_calibration/outcome_calibration_route_evidence_rows.jsonl"
DEFAULT_LINKAGE_JSONL = ".audit_logs/outcome_calibration/outcome_calibration_resolved_linkage_rows.jsonl"
DEFAULT_OUT_JSON = ".audit_logs/outcome_calibration/outcome_calibration_route_evidence_import.json"
DEFAULT_OUT_MD = ".audit_logs/outcome_calibration/outcome_calibration_route_evidence_import.md"

RESOLVED_OUTCOMES = {"accepted", "duplicate", "rejected"}
ROUTE_VERDICTS = {"TRUE", "FALSE", "PARTIAL"}
REQUIRED_FIELDS = (
    "workspace",
    "lane",
    "model_route",
    "proof_artifact",
    "production_path_status",
    "production_path_blockers_cleared",
    "terminal_route_verdict",
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
        raise SystemExit(f"[outcome-calibration-route-evidence-importer] invalid JSON {path}: {exc}") from None


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


def build_outcome_index(records: Sequence[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in records:
        semantics = derive_outcome_semantics(row)
        if semantics.base_rate_only_rejection:
            continue
        outcome = semantics.outcome
        if outcome not in RESOLVED_OUTCOMES:
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
            if workspace and (key[1] or key[2]):
                index[key] = row
    return index


def lookup_outcome(row: dict[str, Any], index: dict[tuple[str, str, str], dict[str, Any]]) -> dict[str, Any] | None:
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
        if key in index:
            return index[key]
    return None


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


def truthy(value: Any) -> bool:
    if value is True:
        return True
    return safe_str(value).lower() in {"true", "yes", "1", "cleared", "verified"}


def validate_route_row(
    workspace: Path,
    row: dict[str, Any],
    outcome_index: dict[tuple[str, str, str], dict[str, Any]],
) -> dict[str, Any]:
    problems: list[str] = []
    if row.get("_invalid_json"):
        problems.append("invalid_json")
    if row.get("schema") != INPUT_ROW_SCHEMA:
        problems.append("schema_mismatch")
    missing = [field for field in REQUIRED_FIELDS if not safe_str(row.get(field))]
    problems.extend(f"missing_{field}" for field in missing)
    if not safe_str(row.get("finding_id")) and not safe_str(row.get("report_id")) and not safe_str(row.get("title")):
        problems.append("missing_finding_identity")
    if safe_str(row.get("terminal_route_verdict")).upper() not in ROUTE_VERDICTS:
        problems.append("invalid_terminal_route_verdict")
    final_outcome = safe_str(row.get("final_triager_outcome"))
    if final_outcome not in RESOLVED_OUTCOMES:
        problems.append("invalid_final_triager_outcome")
    matched = lookup_outcome(row, outcome_index)
    if matched is None:
        problems.append("no_matching_resolved_outcome")
    elif final_outcome and final_outcome != derive_outcome_semantics(matched).outcome:
        problems.append("final_triager_outcome_mismatch")
    if not proof_artifact_exists(workspace, safe_str(row.get("proof_artifact"))):
        problems.append("proof_artifact_missing")
    production_status = safe_str(row.get("production_path_status")).lower()
    if production_status in {"", "missing", "blocked", "unknown", "not_proven", "unproved"}:
        problems.append("production_path_not_verified")
    if not truthy(row.get("production_path_blockers_cleared")):
        problems.append("production_path_blockers_not_cleared")
    return {
        "line": row.get("_line"),
        "workspace": safe_str(row.get("workspace")),
        "finding_id": safe_str(row.get("finding_id")),
        "report_id": safe_str(row.get("report_id")),
        "title": safe_str(row.get("title")),
        "lane": safe_str(row.get("lane")),
        "model_route": safe_str(row.get("model_route")),
        "terminal_route_verdict": safe_str(row.get("terminal_route_verdict")).upper(),
        "final_triager_outcome": final_outcome,
        "matched_outcome": bool(matched),
        "proof_artifact": safe_str(row.get("proof_artifact")),
        "production_path_status": safe_str(row.get("production_path_status")),
        "valid_for_import": not problems,
        "problem_codes": sorted(set(problems)),
        "_raw": row,
    }


def linkage_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        safe_str(row.get("workspace")).lower(),
        safe_str(row.get("finding_id") or row.get("report_id")).lower(),
        safe_str(row.get("title")).lower(),
        safe_str(row.get("model_route")).lower(),
    )


def convert_to_linkage(row: dict[str, Any]) -> dict[str, Any]:
    raw = row["_raw"]
    output = {
        "schema": OUTPUT_ROW_SCHEMA,
        "workspace": row["workspace"],
        "finding_id": row["finding_id"],
        "report_id": row["report_id"],
        "title": row["title"],
        "final_triager_outcome": row["final_triager_outcome"],
        "lane": row["lane"],
        "model_route": row["model_route"],
        "proof_artifact": row["proof_artifact"],
        "production_path_status": row["production_path_status"],
        "production_path_blockers_cleared": raw.get("production_path_blockers_cleared"),
        "terminal_route_verdict": row["terminal_route_verdict"],
        "route_evidence_schema": INPUT_ROW_SCHEMA,
    }
    for optional in ("provider", "task_type", "task_id", "production_path_artifact", "notes"):
        if safe_str(raw.get(optional)):
            output[optional] = raw.get(optional)
    return output


def write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def build_payload(
    *,
    workspace: Path,
    outcome_json: Sequence[Path],
    input_jsonl: Path,
    linkage_jsonl: Path,
    write_linkage: bool,
) -> dict[str, Any]:
    outcome_records: list[dict[str, Any]] = []
    for path in outcome_json:
        outcome_records.extend(records_from_payload(read_json(path)))
    outcome_index = build_outcome_index(outcome_records)
    input_rows = read_jsonl(input_jsonl)
    existing_linkage = [
        row for row in read_jsonl(linkage_jsonl)
        if row.get("schema") == OUTPUT_ROW_SCHEMA
    ]
    validations = [validate_route_row(workspace, row, outcome_index) for row in input_rows]
    valid_rows = [row for row in validations if row["valid_for_import"]]
    imported_linkage = [convert_to_linkage(row) for row in valid_rows]
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in existing_linkage + imported_linkage:
        merged[linkage_key(row)] = {k: v for k, v in row.items() if not str(k).startswith("_")}
    merged_rows = list(merged.values())
    if write_linkage:
        write_jsonl(linkage_jsonl, merged_rows)
    problem_counts = Counter(problem for row in validations for problem in row["problem_codes"])
    verdict_counts = Counter(row["terminal_route_verdict"] for row in validations if row["terminal_route_verdict"])
    return {
        "schema": SCHEMA,
        "generated_at_utc": now_iso(),
        "workspace": str(workspace),
        "advisory_only": True,
        "promotion_authority": False,
        "no_invented_acceptance_or_rejection": True,
        "inputs": {
            "outcome_json": [str(path) for path in outcome_json],
            "input_jsonl": str(input_jsonl),
            "linkage_jsonl": str(linkage_jsonl),
        },
        "summary": {
            "resolved_outcome_rows": sum(1 for row in outcome_records if safe_str(row.get("outcome")) in RESOLVED_OUTCOMES),
            "route_evidence_rows_seen": len(input_rows),
            "valid_import_rows": len(valid_rows),
            "invalid_import_rows": len(validations) - len(valid_rows),
            "existing_linkage_rows": len(existing_linkage),
            "linkage_rows_written": len(merged_rows) if write_linkage else 0,
            "terminal_route_verdict_counts": dict(sorted(verdict_counts.items())),
            "problem_counts": dict(sorted(problem_counts.items())),
            "import_status": (
                "valid_route_evidence_imported"
                if valid_rows and write_linkage
                else "valid_route_evidence_dry_run"
                if valid_rows
                else "no_valid_route_evidence_rows"
            ),
        },
        "imported_rows": imported_linkage,
        "rows": [
            {k: v for k, v in row.items() if k != "_raw"}
            for row in validations
        ],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Outcome Calibration Route Evidence Import",
        "",
        "Imports only real terminal route evidence that matches resolved triager outcomes.",
        "",
        f"- route evidence rows seen: `{summary['route_evidence_rows_seen']}`",
        f"- valid import rows: `{summary['valid_import_rows']}`",
        f"- invalid import rows: `{summary['invalid_import_rows']}`",
        f"- linkage rows written: `{summary['linkage_rows_written']}`",
        f"- import status: `{summary['import_status']}`",
        "",
        "## Rows",
        "",
        "| Line | Workspace | Finding | Verdict | Outcome | Import | Problems |",
        "|---:|---|---|---|---|---|---|",
    ]
    for row in payload["rows"]:
        problems = ", ".join(row["problem_codes"]) or "-"
        finding = row["finding_id"] or row["report_id"] or row["title"]
        lines.append(
            f"| {row.get('line') or ''} | `{row['workspace']}` | `{finding}` | "
            f"`{row['terminal_route_verdict']}` | `{row['final_triager_outcome']}` | "
            f"`{str(row['valid_for_import']).lower()}` | {problems} |"
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
    parser.add_argument("--input-jsonl", type=Path)
    parser.add_argument("--linkage-jsonl", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    outcome_json = [resolve_path(workspace, path, DEFAULT_OUTCOME_JSON) for path in args.outcome_json] or [resolve_path(workspace, None, DEFAULT_OUTCOME_JSON)]
    payload = build_payload(
        workspace=workspace,
        outcome_json=outcome_json,
        input_jsonl=resolve_path(workspace, args.input_jsonl, DEFAULT_INPUT_JSONL),
        linkage_jsonl=resolve_path(workspace, args.linkage_jsonl, DEFAULT_LINKAGE_JSONL),
        write_linkage=not args.dry_run,
    )
    out_json = resolve_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = resolve_path(workspace, args.out_md, DEFAULT_OUT_MD) if args.out_md is not None else resolve_path(workspace, None, DEFAULT_OUT_MD)
    write_outputs(payload, out_json, out_md)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
