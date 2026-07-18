#!/usr/bin/env python3
"""Bridge queued High/Critical harness rows into scaffold attempts and execution-record handoffs.

This is an execution-readiness bridge, not proof generation.

It reuses the canonical High/Critical queue ergonomics from
`tools/invariant-harness-planner.py` and the actual scaffold emission logic
from `tools/harness-scaffold-emitter.py`, then writes a bridge report with:

  * per-row scaffold emission attempt results
  * exact handoff brief paths for future execution bookkeeping
  * exact `make poc-execution-record ...` next commands
  * an explicit fail-closed status for impact-contract-blocked rows

Rows that are still blocked on an exact impact contract are never promoted to
"runnable harness" here. They get follow-up commands only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.high_impact_execution_bridge.v1"
PROOF_BOUNDARY = (
    "Bridge output is execution-readiness evidence only. Scaffold attempts, "
    "handoff briefs, and next commands are not exploit proof."
)


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"[high-impact-execution-bridge] ERR could not load module: {path}")
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


def row_id_safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value).strip("_").lower() or "row"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _load_ledger(workspace: Path) -> dict[str, Any]:
    path = workspace / ".auditooor" / "invariant_ledger.json"
    if not path.is_file():
        raise SystemExit(
            f"[high-impact-execution-bridge] ERR missing ledger: {path}\n"
            f"  run `make invariant-ledger WS={workspace}` first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _brief_path(out_dir: Path, row_id: str) -> Path:
    return out_dir / "briefs" / f"{slug(row_id)}.md"


def _candidate_id(row_id: str) -> str:
    return slug(row_id)


def _poc_execution_record_path(workspace: Path, row_id: str) -> str:
    return str(workspace / "poc_execution" / _candidate_id(row_id) / "execution_manifest.json")


def _scaffold_artifact_paths(workspace: Path, row_id: str) -> dict[str, str]:
    candidates = [
        workspace / "poc-tests" / row_id_safe(row_id) / "attempt_manifest.json",
        workspace / f"poc-tests-{row_id_safe(row_id)}" / "attempt_manifest.json",
    ]
    manifest_path = next((path for path in candidates if path.is_file()), candidates[0])
    return {
        "attempt_manifest": str(manifest_path),
        "scaffold_dir": str(manifest_path.parent),
    }


def _build_record_command(workspace: Path, brief_path: Path, row_id: str, compile_command: str) -> str:
    return (
        "make poc-execution-record "
        f"WS={shlex.quote(str(workspace))} "
        f"BRIEF={shlex.quote(str(brief_path))} "
        f"CANDIDATE_ID={shlex.quote(_candidate_id(row_id))} "
        f"BRIDGE_ROW={shlex.quote(row_id)} "
        f"CMD={shlex.quote(compile_command)} "
        "RESULT=needs_human IMPACT=unknown"
    )


def _impact_contract_check_command(workspace: Path, row_id: str) -> str:
    return (
        f"make impact-contract-check "
        f"WS={shlex.quote(str(workspace))} ROW={shlex.quote(row_id)}"
    )


def _impact_contract_skeleton_command(workspace: Path, row_id: str) -> str:
    return (
        f"make high-impact-impact-contract-skeletons "
        f"WS={shlex.quote(str(workspace))} ROW={shlex.quote(row_id)}"
    )


def _impact_contract_skeleton_path(out_json: Path, row_id: str) -> str:
    return str(
        out_json.parent / "high_impact_impact_contract_skeletons" / "skeletons" / f"{slug(row_id)}.json"
    )


def _attach_poc_execution_record_linkage(
    bridge_row: dict[str, Any],
    workspace: Path,
    row_id: str,
    *,
    blocked_reason: str = "",
) -> None:
    if blocked_reason:
        bridge_row["poc_execution_record_status"] = "blocked"
        bridge_row["poc_execution_record_path"] = ""
        bridge_row["poc_execution_record_blocked_reason"] = blocked_reason
        return
    record_path = _poc_execution_record_path(workspace, row_id)
    bridge_row["poc_execution_record_status"] = "present" if Path(record_path).is_file() else "expected_missing"
    bridge_row["poc_execution_record_path"] = record_path
    bridge_row["poc_execution_record_blocked_reason"] = ""


def _validate_poc_execution_record_linkage(rows: list[dict[str, Any]]) -> None:
    invalid: list[str] = []
    for row in rows:
        row_id = str(row.get("row_id") or "<missing-row-id>")
        status = str(row.get("poc_execution_record_status") or "").strip()
        record_path = str(row.get("poc_execution_record_path") or "").strip()
        blocked_reason = str(row.get("poc_execution_record_blocked_reason") or "").strip()
        if status == "blocked":
            if record_path or not blocked_reason:
                invalid.append(f"{row_id}:blocked_linkage_invalid")
        elif status in {"present", "expected_missing"}:
            if not record_path or blocked_reason:
                invalid.append(f"{row_id}:record_path_linkage_invalid")
        else:
            invalid.append(f"{row_id}:missing_linkage_status")
    if invalid:
        raise SystemExit(
            "[high-impact-execution-bridge] ERR every High/Critical bridge row "
            "must carry an explicit PoC execution record path or blocked reason: "
            + ", ".join(invalid)
        )


def _render_handoff_brief(
    row: dict[str, Any],
    plan: dict[str, Any],
    bridge_row: dict[str, Any],
) -> str:
    return "\n".join(
        [
            f"# High-Impact Execution Handoff: {row['row_id']}",
            "",
            "This handoff is scaffold/execution-readiness only.",
            "",
            f"- proof_boundary: {PROOF_BOUNDARY}",
            f"- queue_item_id: `{bridge_row['queue_item_id']}`",
            f"- harness_family: `{bridge_row['harness_family']}`",
            f"- severity: `{row.get('severity') or 'unknown'}`",
            f"- invariant_family: `{row.get('invariant_family') or 'unknown'}`",
            f"- blocker_class: `{row.get('blocker_class') or 'unknown'}`",
            f"- target_entrypoint: `{plan.get('target_entrypoint') or 'TBD'}`",
            f"- compile_command: `{bridge_row.get('compile_command') or ''}`",
            f"- scaffold_dir: `{bridge_row.get('scaffold_dir') or ''}`",
            f"- attempt_manifest: `{bridge_row.get('attempt_manifest') or ''}`",
            f"- poc_execution_record_status: `{bridge_row.get('poc_execution_record_status') or ''}`",
            f"- poc_execution_record_path: `{bridge_row.get('poc_execution_record_path') or ''}`",
            "",
            "## Next Step",
            "",
            "Run the emitted scaffold or spec command, inspect the result, then",
            "record the outcome with the exact `make poc-execution-record`",
            "command below. Do not upgrade severity or claim proof from this",
            "brief alone.",
            "",
            "```bash",
            bridge_row["poc_execution_record_command"],
            "```",
        ]
    )


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# High-Impact Execution Bridge",
        "",
        "Generated by `tools/high-impact-execution-bridge.py`.",
        "",
        f"- workspace: `{payload['workspace']}`",
        f"- High/Critical queue rows: {payload['high_impact_missing']}",
        f"- processed rows: {payload['processed_rows']}",
        f"- scaffold attempts: {payload['summary']['scaffold_attempts']}",
        f"- runnable harness rows: {payload['summary']['runnable_harness_rows']}",
        f"- blocked_missing_impact_contract: {payload['summary']['blocked_missing_impact_contract']}",
        f"- blocked_other: {payload['summary']['blocked_other']}",
        f"- poc_execution_records_present: {payload['summary']['poc_execution_records_present']}",
        f"- poc_execution_records_expected_missing: {payload['summary']['poc_execution_records_expected_missing']}",
        f"- poc_execution_records_blocked: {payload['summary']['poc_execution_records_blocked']}",
        f"- proof_boundary: {payload['proof_boundary']}",
        "",
        "## Queue-Level Next Commands",
        "",
    ]
    for command in payload.get("queue_next_commands") or []:
        lines.append(f"- `{command}`")
    lines.extend(["", "## Rows", ""])
    lines.append("| row | family | status | runnable | attempt | record linkage |")
    lines.append("|---|---|---|---|---|---|")
    for row in payload.get("rows") or []:
        record_link = row.get("poc_execution_record_path") or row.get("poc_execution_record_blocked_reason") or ""
        lines.append(
            f"| `{row['row_id']}` | `{row['harness_family']}` | `{row['bridge_status']}` | "
            f"`{str(row['runnable_harness']).lower()}` | `{row.get('attempt_status') or ''}` | "
            f"`{record_link}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--fixture-kits-root", type=Path, default=None)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--row", default=None, help="Process only one row_id from the High/Critical queue.")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    out_json = (
        args.out_json.expanduser().resolve()
        if args.out_json
        else workspace / ".auditooor" / "high_impact_execution_bridge.json"
    )
    out_md = out_json.with_suffix(".md")
    out_dir = out_json.parent / "high_impact_execution_bridge"

    tools_dir = Path(__file__).resolve().parent
    planner = _load_module("invariant_harness_planner_bridge", tools_dir / "invariant-harness-planner.py")
    emitter = _load_module("harness_scaffold_emitter_bridge", tools_dir / "harness-scaffold-emitter.py")
    fixture_root = (
        args.fixture_kits_root.expanduser().resolve()
        if args.fixture_kits_root
        else emitter.default_fixture_kits_root()
    )

    ledger = _load_ledger(workspace)
    manifest = planner.build_manifest(ledger, workspace)
    queue = planner.build_high_impact_queue(ledger, workspace)
    plan_map = {str(plan.get("row_id") or ""): plan for plan in manifest.get("plans") or []}

    rows_out: list[dict[str, Any]] = []
    for item in queue.get("queue_items") or []:
        for row in item.get("rows") or []:
            row_id = str(row.get("row_id") or "")
            if args.row and row_id != args.row:
                continue
            plan = plan_map.get(row_id)
            if plan is None:
                ledger_row = next(
                    (candidate for candidate in ledger.get("rows") or [] if str(candidate.get("id") or "") == row_id),
                    None,
                )
                if ledger_row is None:
                    continue
                plan = planner.plan_for_row(ledger_row, workspace)
            bridge_row: dict[str, Any] = {
                "row_id": row_id,
                "queue_item_id": item.get("queue_item_id") or "",
                "harness_family": item.get("harness_family") or plan.get("harness_family") or "",
                "severity": row.get("severity") or "",
                "invariant_family": row.get("invariant_family") or "",
                "compile_command": str(plan.get("compile_command") or "").strip(),
                "proof_boundary": PROOF_BOUNDARY,
                "impact_contract_status": (
                    row.get("impact_contract", {}).get("status")
                    if isinstance(row.get("impact_contract"), dict)
                    else "unknown"
                ),
                "impact_contract_command": "",
                "bridge_status": "blocked_other",
                "runnable_harness": False,
                "attempt_status": "",
                "attempt_manifest": "",
                "scaffold_dir": "",
                "handoff_brief": "",
                "poc_execution_record_command": "",
                "poc_execution_record_status": "",
                "poc_execution_record_path": "",
                "poc_execution_record_blocked_reason": "",
                "impact_contract_skeleton_command": "",
                "impact_contract_skeleton_path": "",
            }

            if bool(row.get("impact_contract_blocked")):
                bridge_row["bridge_status"] = "blocked_missing_impact_contract"
                # Search planner-emitted next_commands first; fall back to
                # generating the canonical impact-contract-check command so the
                # field is never empty for blocked rows.
                bridge_row["impact_contract_command"] = next(
                    (
                        command["command"]
                        for command in item.get("next_commands") or []
                        if command.get("row_id") == row_id and command.get("kind") == "impact-contract"
                    ),
                    _impact_contract_check_command(workspace, row_id),
                )
                bridge_row["impact_contract_skeleton_command"] = _impact_contract_skeleton_command(
                    workspace, row_id
                )
                bridge_row["impact_contract_skeleton_path"] = _impact_contract_skeleton_path(out_json, row_id)
                _attach_poc_execution_record_linkage(
                    bridge_row,
                    workspace,
                    row_id,
                    blocked_reason="missing_exact_impact_contract",
                )
                rows_out.append(bridge_row)
                continue

            attempt = emitter.emit_for_plan(
                plan,
                workspace,
                fixture_root,
                manifest.get("ledger_generated_at"),
                force=args.force,
            )
            artifacts = _scaffold_artifact_paths(workspace, row_id)
            bridge_row["attempt_status"] = str(attempt.get("status") or "")
            bridge_row["attempt_manifest"] = artifacts["attempt_manifest"]
            bridge_row["scaffold_dir"] = artifacts["scaffold_dir"]

            if bridge_row["attempt_status"] == "scaffolded_unverified" and bridge_row["compile_command"]:
                brief_path = _brief_path(out_dir, row_id)
                bridge_row["poc_execution_record_command"] = _build_record_command(
                    workspace,
                    brief_path,
                    row_id,
                    bridge_row["compile_command"],
                )
                bridge_row["handoff_brief"] = str(brief_path)
                bridge_row["bridge_status"] = "scaffolded_ready_for_execution_record"
                bridge_row["runnable_harness"] = True
                _attach_poc_execution_record_linkage(bridge_row, workspace, row_id)
                write_text(brief_path, _render_handoff_brief(row, plan, bridge_row))
            elif bridge_row["attempt_status"] == "blocked":
                bridge_row["bridge_status"] = "blocked_other"
                _attach_poc_execution_record_linkage(
                    bridge_row,
                    workspace,
                    row_id,
                    blocked_reason="scaffold_emission_blocked",
                )
            else:
                bridge_row["bridge_status"] = "blocked_no_compile_command"
                _attach_poc_execution_record_linkage(
                    bridge_row,
                    workspace,
                    row_id,
                    blocked_reason="missing_compile_command",
                )

            rows_out.append(bridge_row)

    _validate_poc_execution_record_linkage(rows_out)
    summary = {
        "scaffold_attempts": sum(1 for row in rows_out if row.get("attempt_status")),
        "runnable_harness_rows": sum(1 for row in rows_out if row.get("runnable_harness")),
        "blocked_missing_impact_contract": sum(
            1 for row in rows_out if row.get("bridge_status") == "blocked_missing_impact_contract"
        ),
        "blocked_other": sum(
            1
            for row in rows_out
            if row.get("bridge_status") in {"blocked_other", "blocked_no_compile_command"}
        ),
        "poc_execution_records_present": sum(
            1 for row in rows_out if row.get("poc_execution_record_status") == "present"
        ),
        "poc_execution_records_expected_missing": sum(
            1 for row in rows_out if row.get("poc_execution_record_status") == "expected_missing"
        ),
        "poc_execution_records_blocked": sum(
            1 for row in rows_out if row.get("poc_execution_record_status") == "blocked"
        ),
    }

    payload = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "ledger_generated_at": ledger.get("generated_at"),
        "high_impact_missing": queue.get("high_impact_missing", 0),
        "processed_rows": len(rows_out),
        "proof_boundary": PROOF_BOUNDARY,
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
        "queue_next_commands": [
            f"make harness-plan WS={workspace}",
            f"make harness-scaffold WS={workspace}",
            f"make high-impact-impact-contract-skeletons WS={workspace}",
            f"make high-impact-execution-bridge WS={workspace}",
        ],
        "summary": summary,
        "rows": rows_out,
    }
    write_json(out_json, payload)
    write_text(out_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            f"[high-impact-execution-bridge] OK rows={payload['processed_rows']} "
            f"runnable={summary['runnable_harness_rows']} blocked_impact={summary['blocked_missing_impact_contract']} "
            f"json={out_json}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
