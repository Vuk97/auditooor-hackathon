#!/usr/bin/env python3
"""Generate or validate fail-closed impact-contract skeletons for blocked high-impact queue rows."""
from __future__ import annotations

import argparse
import importlib.util
import json
import shlex
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.high_impact_impact_contract_skeletons.v1"
SKELETON_SCHEMA_VERSION = "auditooor.high_impact_impact_contract_skeleton.v1"
TASK_SCHEMA_VERSION = "auditooor.high_impact_impact_contract_task.v1"
SAFE_STATUSES = {"required_not_collected", "generated_unvalidated"}
PROOF_BOUNDARY = (
    "Generated impact-contract skeletons and tasks are advisory unblocker artifacts only. "
    "They are not canonical impact contracts, do not prove listed impact, and do not unblock harness work."
)


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"[high-impact-impact-contract-skeletons] ERR could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def slug(value: str) -> str:
    out = []
    prev_dash = False
    for ch in value.strip().lower():
        if ch.isalnum() or ch in "._":
            out.append(ch)
            prev_dash = False
            continue
        if not prev_dash:
            out.append("-")
            prev_dash = True
    result = "".join(out).strip("-")
    return result or "candidate"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _blocked_rows(queue: dict[str, Any], only_row: str | None) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for item in queue.get("queue_items") or []:
        for row in item.get("rows") or []:
            row_id = str(row.get("row_id") or "")
            if only_row and row_id != only_row:
                continue
            if bool(row.get("impact_contract_blocked")):
                rows.append((item, row))
    return rows


def _required_missing_fields(row: dict[str, Any]) -> list[str]:
    summary = row.get("impact_contract")
    if not isinstance(summary, dict):
        return ["selected_impact", "severity_tier", "evidence_class", "oos_traps", "stop_condition"]
    missing: list[str] = []
    if not str(summary.get("selected_impact") or "").strip():
        missing.append("selected_impact")
    if not str(summary.get("severity_tier") or row.get("severity") or "").strip():
        missing.append("severity_tier")
    if not str(summary.get("evidence_class") or "").strip():
        missing.append("evidence_class")
    oos_traps = summary.get("oos_traps")
    if not isinstance(oos_traps, list) or not any(str(item).strip() for item in oos_traps):
        missing.append("oos_traps")
    if not str(summary.get("stop_condition") or "").strip():
        missing.append("stop_condition")
    return missing


def _impact_contract_check_command(workspace: Path, row_id: str) -> str:
    return (
        f"make impact-contract-check WS={shlex.quote(str(workspace))} STRICT=1 "
        f"ROW={shlex.quote(row_id)}"
    )


def _skeleton_payload(workspace: Path, item: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    row_id = str(row.get("row_id") or "")
    return {
        "schema_version": SKELETON_SCHEMA_VERSION,
        "task_id": f"hiq-impact-contract-{slug(row_id)}",
        "workspace": str(workspace),
        "row_id": row_id,
        "candidate_id": row_id,
        "queue_item_id": item.get("queue_item_id") or "",
        "harness_family": item.get("harness_family") or "",
        "severity_tier": str(row.get("severity") or ""),
        "impact_contract_id": f"impact-contract-{slug(row_id)}",
        "selected_impact": "",
        "exact_impact_row": False,
        "listed_impact_proven": False,
        "evidence_class": "",
        "oos_traps": [],
        "stop_condition": "",
        "status": "required_not_collected",
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
        "canonical_gate": "impact_contracts.json remains the only canonical impact-contract source",
        "blocked_reason": "Exact impact contract is still missing or incomplete for this high-impact queue row.",
        "required_missing_fields": _required_missing_fields(row),
        "next_commands": [
            _impact_contract_check_command(workspace, row_id),
            f"make harness-plan WS={shlex.quote(str(workspace))} ROW={shlex.quote(row_id)}",
        ],
    }


def _task_payload(workspace: Path, item: dict[str, Any], row: dict[str, Any], skeleton_path: Path) -> dict[str, Any]:
    row_id = str(row.get("row_id") or "")
    impact_status = (
        row.get("impact_contract", {}).get("status")
        if isinstance(row.get("impact_contract"), dict)
        else "unknown"
    )
    return {
        "schema_version": TASK_SCHEMA_VERSION,
        "workspace": str(workspace),
        "row_id": row_id,
        "queue_item_id": item.get("queue_item_id") or "",
        "task_type": "impact_contract_skeleton_required",
        "harness_family": item.get("harness_family") or "",
        "severity": row.get("severity") or "",
        "impact_contract_status": impact_status,
        "skeleton_path": str(skeleton_path),
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "proof_boundary": PROOF_BOUNDARY,
        "required_manual_follow_up": [
            "Select one exact listed-impact sentence from the program rubric.",
            "Bind row-specific OOS traps and stop condition.",
            "Record real proof later in canonical impact_contracts.json only after evidence exists.",
        ],
        "next_commands": [
            _impact_contract_check_command(workspace, row_id),
            f"make high-impact-impact-contract-skeletons WS={shlex.quote(str(workspace))} ROW={shlex.quote(row_id)}",
        ],
    }


def _task_markdown(task: dict[str, Any]) -> str:
    lines = [
        f"# High-Impact Impact-Contract Task: {task['row_id']}",
        "",
        f"- queue_item_id: `{task['queue_item_id']}`",
        f"- task_type: `{task['task_type']}`",
        f"- harness_family: `{task['harness_family']}`",
        f"- severity: `{task['severity']}`",
        f"- impact_contract_status: `{task['impact_contract_status']}`",
        f"- skeleton_path: `{task['skeleton_path']}`",
        f"- submission_posture: `{task['submission_posture']}`",
        f"- promotion_allowed: `{str(task['promotion_allowed']).lower()}`",
        f"- proof_boundary: {task['proof_boundary']}",
        "",
        "## Manual Follow-Up",
        "",
    ]
    for entry in task.get("required_manual_follow_up") or []:
        lines.append(f"- {entry}")
    lines.extend(["", "## Next Commands", ""])
    for command in task.get("next_commands") or []:
        lines.append(f"- `{command}`")
    return "\n".join(lines)


def _validate_skeleton_payload(payload: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    if str(payload.get("schema_version") or "") != SKELETON_SCHEMA_VERSION:
        violations.append("schema_version_mismatch")
    if bool(payload.get("promotion_allowed")):
        violations.append("promotion_allowed_must_be_false")
    if str(payload.get("submission_posture") or "") != "NOT_SUBMIT_READY":
        violations.append("submission_posture_must_be_not_submit_ready")
    if bool(payload.get("listed_impact_proven")):
        violations.append("listed_impact_proven_must_be_false")
    if bool(payload.get("exact_impact_row")):
        violations.append("exact_impact_row_must_be_false")
    if str(payload.get("selected_impact") or "").strip():
        violations.append("selected_impact_must_be_blank")
    if str(payload.get("evidence_class") or "").strip():
        violations.append("evidence_class_must_be_blank")
    oos_traps = payload.get("oos_traps")
    if isinstance(oos_traps, list) and any(str(item).strip() for item in oos_traps):
        violations.append("oos_traps_must_remain_empty")
    if str(payload.get("stop_condition") or "").strip():
        violations.append("stop_condition_must_be_blank")
    if str(payload.get("status") or "") not in SAFE_STATUSES:
        violations.append("status_must_remain_fail_closed")
    return violations


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# High-Impact Impact-Contract Skeletons",
        "",
        "Generated by `tools/high-impact-impact-contract-skeletons.py`.",
        "",
        f"- workspace: `{payload['workspace']}`",
        f"- blocked queue rows: {payload['blocked_queue_rows']}",
        f"- processed rows: {payload['processed_rows']}",
        f"- generated skeletons: {payload['summary']['generated_skeletons']}",
        f"- validated skeletons: {payload['summary']['validated_skeletons']}",
        f"- missing skeletons: {payload['summary']['missing_skeletons']}",
        f"- invalid skeletons: {payload['summary']['invalid_skeletons']}",
        f"- validation_rc: {payload['validation_rc']}",
        f"- proof_boundary: {payload['proof_boundary']}",
        "",
        "## Queue-Level Next Commands",
        "",
    ]
    for command in payload.get("queue_next_commands") or []:
        lines.append(f"- `{command}`")
    lines.extend(["", "## Rows", "", "| row | queue item | status | skeleton | validate |", "|---|---|---|---|---|"])
    for row in payload.get("rows") or []:
        lines.append(
            f"| `{row['row_id']}` | `{row['queue_item_id']}` | `{row['validation_status']}` | "
            f"`{row['skeleton_path']}` | `{row['validation_command']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--queue", type=Path, default=None)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--row", default=None)
    parser.add_argument("--validate-existing", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    tools_dir = Path(__file__).resolve().parent
    planner = _load_module("high_impact_skeletons_planner", tools_dir / "invariant-harness-planner.py")

    queue_path = (
        args.queue.expanduser().resolve()
        if args.queue
        else workspace / ".auditooor" / "high_impact_harness_queue.json"
    )
    if queue_path.is_file():
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
    else:
        ledger_path = workspace / ".auditooor" / "invariant_ledger.json"
        if not ledger_path.is_file():
            raise SystemExit(
                "[high-impact-impact-contract-skeletons] ERR missing queue and ledger; "
                "run `make harness-plan WS=<workspace>` first."
            )
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        queue = planner.build_high_impact_queue(ledger, workspace)

    out_json = (
        args.out_json.expanduser().resolve()
        if args.out_json
        else workspace / ".auditooor" / "high_impact_impact_contract_skeletons.json"
    )
    out_md = out_json.with_suffix(".md")
    out_dir = out_json.parent / "high_impact_impact_contract_skeletons"
    rows = _blocked_rows(queue, args.row)

    rows_out: list[dict[str, Any]] = []
    missing_skeletons = 0
    invalid_skeletons = 0
    generated_skeletons = 0
    validated_skeletons = 0

    for item, row in rows:
        row_id = str(row.get("row_id") or "")
        skeleton_path = out_dir / "skeletons" / f"{slug(row_id)}.json"
        task_json_path = out_dir / "tasks" / f"{slug(row_id)}.json"
        task_md_path = out_dir / "tasks" / f"{slug(row_id)}.md"
        validation_errors: list[str] = []
        validation_status = "missing_skeleton"

        if not args.validate_existing:
            write_json(skeleton_path, _skeleton_payload(workspace, item, row))
            task_payload = _task_payload(workspace, item, row, skeleton_path)
            write_json(task_json_path, task_payload)
            write_text(task_md_path, _task_markdown(task_payload))
            generated_skeletons += 1

        if skeleton_path.is_file():
            try:
                skeleton_payload = json.loads(skeleton_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                validation_errors = ["invalid_json"]
            else:
                validation_errors = _validate_skeleton_payload(skeleton_payload)
            if validation_errors:
                invalid_skeletons += 1
                validation_status = "invalid_fail_closed_skeleton"
            else:
                validated_skeletons += 1
                validation_status = "validated_fail_closed_skeleton"
        else:
            missing_skeletons += 1

        rows_out.append(
            {
                "row_id": row_id,
                "queue_item_id": item.get("queue_item_id") or "",
                "impact_contract_status": (
                    row.get("impact_contract", {}).get("status")
                    if isinstance(row.get("impact_contract"), dict)
                    else "unknown"
                ),
                "skeleton_path": str(skeleton_path),
                "task_json_path": str(task_json_path),
                "task_md_path": str(task_md_path),
                "validation_status": validation_status,
                "validation_errors": validation_errors,
                "validation_command": (
                    f"make high-impact-impact-contract-skeletons "
                    f"WS={shlex.quote(str(workspace))} ROW={shlex.quote(row_id)} VALIDATE=1"
                ),
            }
        )

    validation_rc = 0 if missing_skeletons == 0 and invalid_skeletons == 0 else 1
    payload = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "queue_path": str(queue_path),
        "blocked_queue_rows": len(rows),
        "processed_rows": len(rows_out),
        "proof_boundary": PROOF_BOUNDARY,
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "validation_rc": validation_rc,
        "queue_next_commands": [
            f"make harness-plan WS={workspace}",
            f"make high-impact-impact-contract-skeletons WS={workspace}",
            f"make impact-contract-check WS={workspace} STRICT=1",
        ],
        "summary": {
            "generated_skeletons": generated_skeletons,
            "validated_skeletons": validated_skeletons,
            "missing_skeletons": missing_skeletons,
            "invalid_skeletons": invalid_skeletons,
        },
        "rows": rows_out,
    }
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"[high-impact-impact-contract-skeletons] OK rows={payload['processed_rows']} "
            f"validated={validated_skeletons} missing={missing_skeletons} invalid={invalid_skeletons} "
            f"json={out_json}"
        )
    return validation_rc


if __name__ == "__main__":
    raise SystemExit(main())
