#!/usr/bin/env python3
"""Build a runnable command manifest from execution proof task queues.

The source queue is intentionally high level: many rows contain placeholders
such as ``<generated-test>`` or ``<brief>``. This tool makes the next step
operator-safe by replacing the workspace placeholder, surfacing unresolved
bindings, and refusing to auto-run anything that could accidentally record
``RESULT=proved`` without a real PoC execution manifest.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from execution_manifest_proof import (  # noqa: E402
    command_evidence_counts,
    is_strict_proved_execution_manifest,
    strict_proof_blockers,
)


SCHEMA = "auditooor.execution_proof_command_manifest.v1"
SCAFFOLDED_EVIDENCE_CLASS = "scaffolded_unverified"
PLACEHOLDER_RE = re.compile(r"<[^>]+>")
SOURCE_REF_RE = re.compile(r"^(?P<file>.+?):L?(?P<line>[1-9][0-9]*)$")
SAFE_EXECUTION_KINDS = {"harness_plan_inventory"}
SAFE_RESULT = "RESULT=needs_human IMPACT=unknown"
SOURCE_REF_KEYS = {
    "candidate_bound_project_source_citation",
    "candidate_bound_project_source_citations",
    "current_workspace_source_ref",
    "current_workspace_source_refs",
    "evidence_ref",
    "evidence_refs",
    "source_line_hit",
    "source_line_hits",
    "source_ref",
    "source_refs",
    "source_reference",
    "source_references",
}
PROOF_ARTIFACT_KEYS = {
    "execution_manifest_path",
    "manifest_path",
    "outcome_manifest_path",
    "poc_execution_manifest",
    "proof_artifact",
    "proof_artifact_path",
    "proof_artifact_paths",
    "proof_artifacts",
}
BLOCKER_LIST_KEYS = {
    "blocked_reason",
    "blocker_category",
    "blockers",
    "blocking_unknowns",
    "errors",
    "failures",
    "proof_blockers",
    "promotion_blockers",
    "safety_blockers",
    "terminal_blockers",
}
BLOCKER_BOOL_KEYS = {"blocked", "blocking"}
ADVISORY_BOOL_KEYS = {"advisory", "advisory_only"}
ADVISORY_STATUS_KEYS = {"claim", "posture", "status", "submission_posture", "verdict"}
ADVISORY_STATUS_VALUES = {
    "advisory",
    "advisory-only",
    "advisory_only",
    "blocked",
    "not submit ready",
    "not-submit-ready",
    "not_submit_ready",
}
PROOF_COMPLETE_BOOL_KEYS = {"execution_proof_ready", "proof_complete", "proof_ready", "proof_counted"}
PROOF_COMPLETE_STATUS_VALUES = {
    "execution_proof_ready",
    "proof_complete",
    "proof_ready",
    "proved",
}
RUNNABLE_BOOL_KEYS = {"runnable", "safe_to_execute"}
RUNNABLE_STATUS_VALUES = {"ready_to_run", "runnable", "safe_to_execute"}
COMMAND_PLACEHOLDER_TEXT_RE = re.compile(r"\b(replace with|todo|tbd|unknown command|exact command already executed)\b", re.I)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"[execution-proof] ERR queue not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[execution-proof] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def workspace_path(workspace: Path, path: Path | None, default: Path) -> Path:
    candidate = path or default
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    return value.strip("-") or "task"


def unresolved_placeholders(command: str) -> list[str]:
    return sorted(set(PLACEHOLDER_RE.findall(command)))


def workspace_command(template: str, workspace: Path) -> str:
    return template.replace("<workspace>", shlex.quote(str(workspace)))


def is_truthy_marker(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    if isinstance(value, int) and not isinstance(value, bool):
        return value != 0
    return False


def has_items(value: object) -> bool:
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None


def compact_marker_value(value: object) -> object:
    if isinstance(value, list):
        return [str(item) for item in value[:5]]
    if isinstance(value, dict):
        return {str(key): value[key] for key in list(value)[:5]}
    return value


def collect_keyed_values(value: object, keys: set[str], *, prefix: str = "") -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            if key_text.lower() in keys:
                found.append({"path": path, "value": item})
            found.extend(collect_keyed_values(item, keys, prefix=path))
    elif isinstance(value, list):
        for idx, item in enumerate(value[:200]):
            path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            found.extend(collect_keyed_values(item, keys, prefix=path))
    return found


def flatten_values(value: object) -> list[object]:
    if isinstance(value, list):
        flattened: list[object] = []
        for item in value:
            flattened.extend(flatten_values(item))
        return flattened
    return [value]


def blocker_advisory_markers(value: object, *, prefix: str = "") -> list[dict[str, Any]]:
    markers: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            path = f"{prefix}.{key_text}" if prefix else key_text
            if lowered in BLOCKER_LIST_KEYS and has_items(item):
                markers.append({"kind": "blocker", "path": path, "value": compact_marker_value(item)})
                continue
            if lowered in BLOCKER_BOOL_KEYS and is_truthy_marker(item):
                markers.append({"kind": "blocker", "path": path, "value": item})
                continue
            if lowered in ADVISORY_BOOL_KEYS and is_truthy_marker(item):
                markers.append({"kind": "advisory_only", "path": path, "value": item})
                continue
            if lowered in ADVISORY_STATUS_KEYS and str(item).strip().lower() in ADVISORY_STATUS_VALUES:
                markers.append({"kind": "advisory_only", "path": path, "value": item})
                continue
            markers.extend(blocker_advisory_markers(item, prefix=path))
    elif isinstance(value, list):
        for idx, item in enumerate(value[:200]):
            path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            markers.extend(blocker_advisory_markers(item, prefix=path))
    return markers


def parse_source_ref(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        file_text = value.get("file") or value.get("path") or value.get("source_file")
        line_value = value.get("line") or value.get("line_no") or value.get("line_number")
        try:
            line = int(line_value)
        except (TypeError, ValueError):
            line = 0
        if file_text and line > 0:
            return {"file": str(file_text), "line": line, "raw": value}
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    match = SOURCE_REF_RE.match(text)
    if not match:
        return None
    return {"file": match.group("file"), "line": int(match.group("line")), "raw": text}


def validate_source_ref(workspace: Path, ref: dict[str, Any]) -> dict[str, Any]:
    file_text = str(ref["file"])
    raw_path = Path(file_text).expanduser()
    workspace_resolved = workspace.resolve()
    path = raw_path if raw_path.is_absolute() else workspace_resolved / raw_path
    try:
        resolved = path.resolve()
        rel = resolved.relative_to(workspace_resolved).as_posix()
    except (OSError, ValueError):
        return {
            "raw": ref["raw"],
            "file": file_text,
            "line": ref["line"],
            "valid": False,
            "reason": "source_ref_outside_current_workspace",
        }
    try:
        with resolved.open("r", encoding="utf-8", errors="ignore") as handle:
            line_count = sum(1 for _ in handle)
    except OSError:
        return {
            "raw": ref["raw"],
            "file": rel,
            "line": ref["line"],
            "valid": False,
            "reason": "source_ref_file_missing",
        }
    if int(ref["line"]) > line_count:
        return {
            "raw": ref["raw"],
            "file": rel,
            "line": ref["line"],
            "valid": False,
            "reason": "source_ref_line_missing",
            "line_count": line_count,
        }
    return {"raw": ref["raw"], "file": rel, "line": ref["line"], "valid": True}


def source_ref_status(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    parsed_refs: list[dict[str, Any]] = []
    for item in collect_keyed_values(row, SOURCE_REF_KEYS):
        for value in flatten_values(item["value"]):
            parsed = parse_source_ref(value)
            if parsed:
                parsed_refs.append(parsed)
    validation = [validate_source_ref(workspace, ref) for ref in parsed_refs]
    stale_refs = [item for item in validation if not item["valid"]]
    if not parsed_refs:
        status = "missing_source_refs"
    elif stale_refs:
        status = "stale_workspace_source_refs"
    else:
        status = "current_workspace_source_refs_ready"
    return {
        "status": status,
        "source_ref_count": len(parsed_refs),
        "valid_ref_count": sum(1 for item in validation if item["valid"]),
        "stale_ref_count": len(stale_refs),
        "stale_refs": stale_refs[:10],
    }


def command_status(command: str, placeholders: list[str]) -> dict[str, Any]:
    text = command.strip()
    concrete = bool(text) and not placeholders and not COMMAND_PLACEHOLDER_TEXT_RE.search(text)
    missing_inputs: list[str] = []
    if not text:
        missing_inputs.append("command")
    if placeholders:
        missing_inputs.append("unresolved_placeholders")
    if text and COMMAND_PLACEHOLDER_TEXT_RE.search(text):
        missing_inputs.append("concrete_command_text")
    return {"concrete": concrete, "missing_inputs": missing_inputs}


def artifact_path_text(value: object) -> str:
    if isinstance(value, dict):
        for key in ("path", "artifact_path", "manifest_path", "proof_artifact_path", "execution_manifest_path"):
            if value.get(key):
                return str(value[key])
        return ""
    if isinstance(value, str):
        return value.strip()
    return ""


def resolve_workspace_artifact(workspace: Path, path_text: str) -> tuple[Path | None, str]:
    if not path_text:
        return None, "proof_artifact_path_missing"
    raw_path = Path(path_text).expanduser()
    workspace_resolved = workspace.resolve()
    candidate = raw_path if raw_path.is_absolute() else workspace_resolved / raw_path
    try:
        resolved = candidate.resolve()
        resolved.relative_to(workspace_resolved)
    except (OSError, ValueError):
        return None, "proof_artifact_outside_current_workspace"
    return resolved, ""


def read_json_or_none(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def proof_artifact_status(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    statuses: list[dict[str, Any]] = []
    markers: list[dict[str, Any]] = []
    for item in collect_keyed_values(row, PROOF_ARTIFACT_KEYS):
        for value in flatten_values(item["value"]):
            path_text = artifact_path_text(value)
            resolved, reason = resolve_workspace_artifact(workspace, path_text)
            if resolved is None:
                statuses.append({"path": path_text, "exists": False, "valid": False, "reason": reason})
                continue
            if not resolved.is_file():
                statuses.append({"path": str(resolved), "exists": False, "valid": False, "reason": "proof_artifact_missing"})
                continue
            payload = read_json_or_none(resolved)
            status: dict[str, Any] = {
                "path": str(resolved),
                "exists": True,
                "valid": True,
                "strict_proved": False,
            }
            if isinstance(payload, dict):
                markers.extend(blocker_advisory_markers(payload, prefix=f"proof_artifact:{resolved.name}"))
                status["source_ref_status"] = source_ref_status(payload, workspace)
                if any(key in payload for key in ("commands_attempted", "evidence_class", "final_result", "impact_assertion")):
                    status["strict_proved"] = is_strict_proved_execution_manifest(payload)
                    status["strict_proof_blockers"] = strict_proof_blockers(payload)
                    status["command_evidence_counts"] = command_evidence_counts(payload)
            statuses.append(status)
    existing = [item for item in statuses if item.get("exists")]
    strict_proved = [item for item in existing if item.get("strict_proved")]
    return {
        "artifact_count": len(statuses),
        "existing_artifact_count": len(existing),
        "strict_proved_artifact_count": len(strict_proved),
        "artifacts": statuses,
        "blocker_advisory_markers": markers,
    }


def combined_source_ref_status(row_status: dict[str, Any], artifact_status: dict[str, Any]) -> dict[str, Any]:
    statuses = [row_status]
    statuses.extend(
        artifact.get("source_ref_status") or {}
        for artifact in artifact_status.get("artifacts") or []
        if isinstance(artifact, dict) and artifact.get("source_ref_status")
    )
    stale_refs: list[dict[str, Any]] = []
    for status_row in statuses:
        if isinstance(status_row, dict):
            stale_refs.extend(item for item in status_row.get("stale_refs", []) if isinstance(item, dict))
    source_ref_count = sum(int(status.get("source_ref_count") or 0) for status in statuses if isinstance(status, dict))
    valid_ref_count = sum(int(status.get("valid_ref_count") or 0) for status in statuses if isinstance(status, dict))
    if stale_refs:
        status = "stale_workspace_source_refs"
    elif source_ref_count > 0:
        status = "current_workspace_source_refs_ready"
    else:
        status = "missing_source_refs"
    return {
        "status": status,
        "source_ref_count": source_ref_count,
        "valid_ref_count": valid_ref_count,
        "stale_ref_count": len(stale_refs),
        "stale_refs": stale_refs[:10],
        "row_source_ref_status": row_status,
    }


def bool_field_present(row: dict[str, Any], keys: set[str]) -> bool:
    return any(is_truthy_marker(row.get(key)) for key in keys)


def status_field_matches(row: dict[str, Any], values: set[str]) -> bool:
    for key in ("claim", "readiness", "readiness_status", "status", "verdict"):
        if str(row.get(key) or "").strip().lower() in values:
            return True
    return False


def proof_complete_claimed(row: dict[str, Any]) -> bool:
    return bool_field_present(row, PROOF_COMPLETE_BOOL_KEYS) or status_field_matches(row, PROOF_COMPLETE_STATUS_VALUES)


def runnable_claimed(row: dict[str, Any], proof_kind: str, concrete_command: bool) -> bool:
    return (
        concrete_command
        or proof_kind in SAFE_EXECUTION_KINDS
        or bool_field_present(row, RUNNABLE_BOOL_KEYS)
        or status_field_matches(row, RUNNABLE_STATUS_VALUES)
    )


def strict_evidence_status(
    row: dict[str, Any],
    workspace: Path,
    proof_kind: str,
    command: str,
    placeholders: list[str],
) -> dict[str, Any]:
    command_info = command_status(command, placeholders)
    artifact_info = proof_artifact_status(row, workspace)
    source_info = combined_source_ref_status(source_ref_status(row, workspace), artifact_info)
    row_markers = blocker_advisory_markers(row)
    markers = row_markers + artifact_info["blocker_advisory_markers"]
    proof_complete = proof_complete_claimed(row)
    runnable = runnable_claimed(row, proof_kind, bool(command_info["concrete"]))
    required = proof_complete or runnable
    reasons: list[dict[str, Any]] = []
    if required and source_info["status"] == "missing_source_refs":
        reasons.append({"code": "missing_source_refs", "detail": source_info})
    if required and source_info["status"] == "stale_workspace_source_refs":
        reasons.append({"code": "stale_workspace_source_refs", "detail": source_info})
    if required:
        if proof_complete:
            proof_evidence_ready = artifact_info["strict_proved_artifact_count"] > 0
        else:
            proof_evidence_ready = bool(command_info["concrete"]) or artifact_info["existing_artifact_count"] > 0
        if not proof_evidence_ready:
            reasons.append(
                {
                    "code": "missing_proof_evidence",
                    "detail": {
                        "command": command_info,
                        "proof_artifacts": artifact_info,
                        "proof_complete_claimed": proof_complete,
                    },
                }
            )
    if required and markers:
        reasons.append({"code": "blocker_or_advisory_marker", "detail": {"markers": markers[:20]}})
    if not required:
        status = "not_required"
    elif reasons:
        status = "blocked"
    else:
        status = "pass"
    return {
        "status": status,
        "required": required,
        "runnable_claimed": runnable,
        "proof_complete_claimed": proof_complete,
        "source_refs": source_info,
        "command": command_info,
        "proof_artifacts": artifact_info,
        "blocker_advisory_markers": markers[:20],
        "reasons": reasons,
    }


def proof_record_template(row: dict[str, Any], workspace: Path) -> str:
    task_id = str(row.get("task_id") or "execution-proof-task")
    return (
        f"make poc-execution-record WS={shlex.quote(str(workspace))} "
        f"BRIEF=<brief> CANDIDATE_ID={shlex.quote(task_id)} "
        f"CMD='<forge command>' {SAFE_RESULT}"
    )


def classify_row(row: dict[str, Any], workspace: Path) -> dict[str, Any]:
    proof_kind = str(row.get("proof_kind") or "unknown")
    task_id = str(row.get("task_id") or "")
    raw_command = str(row.get("next_command") or "")
    command = workspace_command(raw_command, workspace)
    placeholders = unresolved_placeholders(command)
    proof_recording_command = proof_record_template(row, workspace)
    strict_status = strict_evidence_status(row, workspace, proof_kind, command, placeholders)
    strict_reason_codes = [str(reason["code"]) for reason in strict_status["reasons"]]
    auto_execution_allowed = proof_kind in SAFE_EXECUTION_KINDS and not placeholders and strict_status["status"] == "pass"
    blocks: list[str] = []
    if placeholders:
        blocks.append("unresolved_placeholders")
    if "RESULT=proved" in command or "--final-result proved" in command:
        blocks.append("proved_result_requires_manual_manifest_review")
    if proof_kind in {"forge_execution", "execution_manifest_gate"}:
        blocks.append("requires_real_forge_run_and_impact_assertions")
    if proof_kind == "strict_closeout_gate":
        blocks.append("closeout_may_fail_until_manifests_or_named_blockers_exist")
    if proof_kind == "counterexample_replay":
        blocks.append("replay_queue_can_be_run_but_each_replay_still_needs_manifest")
    for code in strict_reason_codes:
        if code not in blocks:
            blocks.append(code)

    if auto_execution_allowed:
        readiness = "safe_to_execute"
    elif placeholders:
        readiness = "needs_binding"
    else:
        readiness = "manual_validation"

    return {
        "task_id": task_id,
        "limitation_id": row.get("limitation_id") or "",
        "proof_kind": proof_kind,
        "title": row.get("title") or "",
        "acceptance_gate": row.get("acceptance_gate") or "",
        "source_stop_condition": row.get("source_stop_condition") or "",
        "raw_next_command": raw_command,
        "runnable_command": command,
        "unresolved_placeholders": placeholders,
        "proof_recording_command_template": proof_recording_command,
        "auto_execution_allowed": auto_execution_allowed,
        "readiness": readiness,
        "safety_blocks": blocks,
        "strict_validation_status": strict_status["status"],
        "strict_evidence_required": strict_status["required"],
        "strict_evidence_reasons": strict_status["reasons"],
        "source_ref_status": strict_status["source_refs"],
        "proof_evidence_status": strict_status["proof_artifacts"],
        "blocker_advisory_markers": strict_status["blocker_advisory_markers"],
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "submit_ready": False,
        "proof_boundary": (
            "Command readiness is not exploit proof. Count proof only from "
            "poc_execution/**/execution_manifest.json with final_result=proved, "
            "impact_assertion=exploit_impact, evidence_class=executed_with_manifest, "
            "and a structured commands_attempted row with status=pass and exit_code=0."
        ),
    }


def command_log_path(out_dir: Path, task_id: str, stream: str) -> Path:
    return out_dir / "command_logs" / f"{slug(task_id)}.{stream}.log"


def outcome_path(out_dir: Path, task_id: str) -> Path:
    return out_dir / "execution_proof_outcomes" / f"{slug(task_id)}.json"


def binding_path(out_dir: Path, task_id: str) -> Path:
    return out_dir / "execution_proof_bindings" / f"{slug(task_id)}.json"


def brief_path(out_dir: Path, task_id: str) -> Path:
    return out_dir / "execution_proof_briefs" / f"{slug(task_id)}.md"


def write_outcome(path: Path, row: dict[str, Any], outcome: dict[str, Any]) -> None:
    payload = {
        "schema": "auditooor.execution_proof_outcome.v1",
        "generated_at_unix": int(time.time()),
        "task_id": row.get("task_id") or "",
        "limitation_id": row.get("limitation_id") or "",
        "proof_kind": row.get("proof_kind") or "",
        "readiness": row.get("readiness") or "",
        "runnable_command": row.get("runnable_command") or "",
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "submit_ready": False,
        "proof_boundary": row.get("proof_boundary") or "",
        "outcome": outcome,
    }
    write_json(path, payload)


def load_outcome_status(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    outcome = payload.get("outcome")
    if not isinstance(outcome, dict):
        return ""
    return str(outcome.get("status") or "")


def blocked_outcome(row: dict[str, Any]) -> dict[str, Any]:
    readiness = str(row.get("readiness") or "unknown")
    blocks = list(row.get("safety_blocks") or [])
    if readiness == "needs_binding":
        status = "blocked_needs_binding"
    elif readiness == "manual_validation":
        status = "blocked_manual_validation"
    else:
        status = "blocked_not_auto_executable"
    return {
        "status": status,
        "safe_to_execute": False,
        "executed": False,
        "unresolved_placeholders": list(row.get("unresolved_placeholders") or []),
        "safety_blocks": blocks,
        "strict_validation_status": row.get("strict_validation_status") or "",
        "strict_evidence_reasons": list(row.get("strict_evidence_reasons") or []),
        "source_ref_status": row.get("source_ref_status") or {},
        "proof_evidence_status": row.get("proof_evidence_status") or {},
        "blocker_advisory_markers": list(row.get("blocker_advisory_markers") or []),
        "reason": (
            "Row was not executed by the safe executor. Bind placeholders, run the "
            "real local proof command, and record any result through poc-execution-record "
            "without using RESULT=proved unless exact exploit impact is asserted."
        ),
    }


def concrete_commands(row: dict[str, Any], workspace: Path, row_brief_path: Path) -> list[str]:
    task_id = str(row.get("task_id") or "execution-proof-task")
    proof_kind = str(row.get("proof_kind") or "")
    quoted_ws = shlex.quote(str(workspace))
    quoted_brief = shlex.quote(str(row_brief_path))
    quoted_task = shlex.quote(task_id)
    candidate_record = (
        f"make poc-execution-record WS={quoted_ws} BRIEF={quoted_brief} "
        f"CANDIDATE_ID={quoted_task} CMD='<replace with executed local command>' {SAFE_RESULT}"
    )
    if proof_kind == "solidity_harness_scaffold":
        return [
            f"make harness-task-queue WS={quoted_ws} JSON=1",
            f"python3 tools/invariant-harness-planner.py --workspace {quoted_ws} --all",
            f"make harness-scaffold WS={quoted_ws} ALL=1",
            candidate_record,
        ]
    if proof_kind == "base_dlt_harness_scaffold":
        return [
            f"make harness-task-queue WS={quoted_ws} JSON=1",
            f"make harness-plan WS={quoted_ws}",
            f"make harness-scaffold WS={quoted_ws} ALL=1",
            f"python3 tools/engage.py --workspace {quoted_ws} --stage scan-rust",
            candidate_record,
        ]
    if proof_kind == "forge_execution":
        generated_var = (
            "GENERATED_TEST=$(find "
            f"{shlex.quote(str(workspace / 'poc-tests'))} "
            f"{shlex.quote(str(workspace / f'poc-tests-{slug(task_id)}'))} "
            "-name '*.t.sol' -type f 2>/dev/null | sort | head -1)"
        )
        forge_cmd = "$GENERATED_TEST"
        return [
            f"{generated_var}; test -n \"$GENERATED_TEST\"; forge test --match-path \"{forge_cmd}\" -vvv",
            (
                f"{generated_var}; test -n \"$GENERATED_TEST\"; "
                f"make poc-execution-record WS={quoted_ws} BRIEF={quoted_brief} "
                f"CANDIDATE_ID={quoted_task} CMD=\"forge test --match-path '$GENERATED_TEST' -vvv\" "
                f"{SAFE_RESULT}"
            ),
        ]
    if proof_kind == "execution_manifest_gate":
        return [
            (
                f"make poc-execution-record WS={quoted_ws} BRIEF={quoted_brief} "
                f"CANDIDATE_ID={quoted_task} CMD='<exact forge command already executed>' {SAFE_RESULT}"
            ),
            "Do not change final-result or impact fields until the exact command output proves exploit impact.",
        ]
    if proof_kind == "counterexample_replay":
        return [
            f"make deep-counterexample-queue WS={quoted_ws}",
            (
                "find "
                f"{shlex.quote(str(workspace / 'deep_counterexamples'))} "
                "-name 'deep_counterexample.v1.json' -type f | sort"
            ),
            candidate_record,
        ]
    if proof_kind == "strict_closeout_gate":
        return [
            f"find {shlex.quote(str(workspace / 'poc_execution'))} -name execution_manifest.json -type f | sort",
            f"REQUIRE_REPLAY_EXECUTED=1 make audit-closeout WS={quoted_ws} STRICT=1",
        ]
    return [str(row.get("runnable_command") or ""), candidate_record]


def fixture_prerequisites(row: dict[str, Any], workspace: Path, row_brief_path: Path) -> list[dict[str, Any]]:
    proof_kind = str(row.get("proof_kind") or "")
    prerequisites = [
        {
            "kind": "brief",
            "path": str(row_brief_path),
            "exists": row_brief_path.is_file(),
            "required": True,
            "description": "Local brief used by poc-execution-record; not submission proof.",
        },
        {
            "kind": "semantic_graph",
            "path": str(workspace / ".auditooor" / "semantic_graph.json"),
            "exists": (workspace / ".auditooor" / "semantic_graph.json").is_file(),
            "required": False,
            "description": "Optional source graph hash captured by poc-execution-record when present.",
        },
    ]
    if proof_kind in {"solidity_harness_scaffold", "base_dlt_harness_scaffold"}:
        prerequisites.extend(
            [
                {
                    "kind": "harness_tasks",
                    "path": str(workspace / ".auditooor" / "harness_tasks.json"),
                    "exists": (workspace / ".auditooor" / "harness_tasks.json").is_file(),
                    "required": True,
                    "description": "Queue rows that select concrete harness candidates.",
                },
                {
                    "kind": "harness_plans",
                    "path": str(workspace / ".auditooor" / "harness_plans.json"),
                    "exists": (workspace / ".auditooor" / "harness_plans.json").is_file(),
                    "required": True,
                    "description": "Planner output consumed by harness-scaffold-emitter.",
                },
                {
                    "kind": "impact_contracts",
                    "path": str(workspace / ".auditooor" / "impact_contracts.json"),
                    "exists": (workspace / ".auditooor" / "impact_contracts.json").is_file(),
                    "required": True,
                    "description": "Exact impact-contract lock required before generated harnesses become proof candidates.",
                },
            ]
        )
    if proof_kind == "forge_execution":
        prerequisites.append(
            {
                "kind": "generated_test",
                "path": str(workspace / "poc-tests"),
                "exists": (workspace / "poc-tests").exists(),
                "required": True,
                "description": "A generated Forge test path must exist before the command can be run.",
            }
        )
    if proof_kind == "counterexample_replay":
        prerequisites.append(
            {
                "kind": "deep_counterexample_queue",
                "path": str(workspace / "deep_counterexamples" / "execution_queue.json"),
                "exists": (workspace / "deep_counterexamples" / "execution_queue.json").is_file(),
                "required": True,
                "description": "Replay queue must name the counterexample record and generated Forge replay path.",
            }
        )
    if proof_kind == "strict_closeout_gate":
        prerequisites.append(
            {
                "kind": "poc_execution_manifest",
                "path": str(workspace / "poc_execution"),
                "exists": (workspace / "poc_execution").exists(),
                "required": True,
                "description": "Closeout proof requires real poc_execution/**/execution_manifest.json rows or named blockers.",
            }
        )
    return prerequisites


def write_binding_brief(path: Path, row: dict[str, Any], commands: list[str]) -> None:
    lines = [
        f"# Execution Proof Binding: {row.get('task_id') or 'task'}",
        "",
        "This brief is local execution plumbing, not a submission draft.",
        "",
        "## Proof Boundary",
        "",
        "Do not mark this task proved unless a matching `poc_execution/**/execution_manifest.json` records `final_result=proved`, `impact_assertion=exploit_impact`, `evidence_class=executed_with_manifest`, and a structured `commands_attempted` row with `status=pass` and `exit_code=0`.",
        "",
        "## Candidate Commands",
        "",
    ]
    for command in commands:
        lines.append(f"- `{command}`")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_binding_manifest(row: dict[str, Any], workspace: Path, out_dir: Path) -> dict[str, Any]:
    task_id = str(row.get("task_id") or "execution-proof-task")
    row_outcome_path = outcome_path(out_dir, task_id)
    row_brief_path = brief_path(out_dir, task_id)
    commands = concrete_commands(row, workspace, row_brief_path)
    write_binding_brief(row_brief_path, row, commands)
    prior_status = load_outcome_status(row_outcome_path)
    readiness = str(row.get("readiness") or "")
    if readiness == "safe_to_execute":
        reduction_status = "safe_validator_already_executed" if prior_status == "pass" else "safe_validator_ready"
    elif readiness == "needs_binding":
        reduction_status = "binding_manifest_generated"
    else:
        reduction_status = "manual_next_command_generated"
    return {
        "schema": "auditooor.execution_proof_binding.v1",
        "generated_at_unix": int(time.time()),
        "task_id": task_id,
        "limitation_id": row.get("limitation_id") or "",
        "proof_kind": row.get("proof_kind") or "",
        "readiness": readiness,
        "prior_outcome_status": prior_status,
        "reduction_status": reduction_status,
        "source_outcome_path": str(row_outcome_path),
        "brief_path": str(row_brief_path),
        "fixture_prerequisites": fixture_prerequisites(row, workspace, row_brief_path),
        "source_prerequisites": [
            {
                "path": str(workspace / ".auditooor" / "execution_proof_command_manifest.json"),
                "exists": (workspace / ".auditooor" / "execution_proof_command_manifest.json").is_file(),
                "description": "Source command manifest row consumed by this binding reducer.",
            },
            {
                "path": str(row_outcome_path),
                "exists": row_outcome_path.is_file(),
                "description": "Prior safe-executor outcome consumed by this binding reducer.",
            },
        ],
        "concrete_next_commands": commands,
        "submit_ready": False,
        "proof_boundary": row.get("proof_boundary") or "",
    }


def generated_binding_outcome(row: dict[str, Any], binding_manifest: dict[str, Any], path: Path) -> dict[str, Any]:
    readiness = str(row.get("readiness") or "")
    if readiness == "needs_binding":
        status = "binding_manifest_generated"
    elif readiness == "manual_validation":
        status = "manual_next_command_generated"
    else:
        status = "safe_validator_binding_available"
    return {
        "status": status,
        "safe_to_execute": False,
        "executed": False,
        "binding_manifest_path": str(path),
        "brief_path": binding_manifest.get("brief_path") or "",
        "concrete_next_commands": binding_manifest.get("concrete_next_commands") or [],
        "fixture_prerequisites": binding_manifest.get("fixture_prerequisites") or [],
        "unresolved_placeholders": list(row.get("unresolved_placeholders") or []),
        "safety_blocks": list(row.get("safety_blocks") or []),
        "strict_validation_status": row.get("strict_validation_status") or "",
        "strict_evidence_reasons": list(row.get("strict_evidence_reasons") or []),
        "source_ref_status": row.get("source_ref_status") or {},
        "proof_evidence_status": row.get("proof_evidence_status") or {},
        "blocker_advisory_markers": list(row.get("blocker_advisory_markers") or []),
        "reason": (
            "Blocked execution row was reduced to concrete local binding work. "
            "This is not exploit proof; record proof only through poc-execution-record after a real run."
        ),
    }


def generate_binding_manifests(rows: list[dict[str, Any]], workspace: Path, out_dir: Path) -> None:
    for row in rows:
        task_id = str(row.get("task_id") or "task")
        path = binding_path(out_dir, task_id)
        manifest = build_binding_manifest(row, workspace, out_dir)
        write_json(path, manifest)
        row["binding_manifest_path"] = str(path)
        row["binding_reduction_status"] = manifest["reduction_status"]
        if row.get("readiness") in {"needs_binding", "manual_validation"}:
            row_outcome_path = outcome_path(out_dir, task_id)
            row["outcome_manifest_path"] = str(row_outcome_path)
            write_outcome(row_outcome_path, row, generated_binding_outcome(row, manifest, path))


def execute_safe_commands(rows: list[dict[str, Any]], workspace: Path, out_dir: Path) -> None:
    for row in rows:
        task_id = str(row.get("task_id") or "task")
        row_outcome_path = outcome_path(out_dir, task_id)
        if not row.get("auto_execution_allowed"):
            row["outcome_manifest_path"] = str(row_outcome_path)
            write_outcome(row_outcome_path, row, blocked_outcome(row))
            continue
        stdout_path = command_log_path(out_dir, task_id, "stdout")
        stderr_path = command_log_path(out_dir, task_id, "stderr")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        started = int(time.time())
        proc = subprocess.run(
            str(row["runnable_command"]),
            cwd=str(workspace),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout_path.write_text(proc.stdout, encoding="utf-8")
        stderr_path.write_text(proc.stderr, encoding="utf-8")
        row["execution_attempt"] = {
            "started_at_unix": started,
            "exit_code": proc.returncode,
            "status": "pass" if proc.returncode == 0 else "fail",
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
        row["outcome_manifest_path"] = str(row_outcome_path)
        write_outcome(
            row_outcome_path,
            row,
            {
                "status": row["execution_attempt"]["status"],
                "safe_to_execute": True,
                "executed": True,
                "exit_code": proc.returncode,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "strict_validation_status": row.get("strict_validation_status") or "",
                "source_ref_status": row.get("source_ref_status") or {},
                "proof_evidence_status": row.get("proof_evidence_status") or {},
            },
        )


def build_manifest(
    queue_path: Path,
    workspace: Path,
    *,
    execute_safe: bool = False,
    generate_bindings: bool = False,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    queue = load_json(queue_path)
    if not isinstance(queue, dict):
        raise SystemExit("[execution-proof] ERR queue JSON must be an object")
    rows = queue.get("rows")
    if not isinstance(rows, list):
        raise SystemExit("[execution-proof] ERR queue JSON missing rows[]")
    command_rows = [classify_row(row, workspace) for row in rows if isinstance(row, dict)]
    output_dir = out_dir or workspace / ".auditooor"
    if execute_safe:
        execute_safe_commands(command_rows, workspace, output_dir)
    if generate_bindings:
        generate_binding_manifests(command_rows, workspace, output_dir)

    readiness_counts = Counter(str(row.get("readiness") or "unknown") for row in command_rows)
    proof_kind_counts = Counter(str(row.get("proof_kind") or "unknown") for row in command_rows)
    safety_block_counts = Counter(
        block
        for row in command_rows
        for block in row.get("safety_blocks", [])
    )
    strict_reason_counts = Counter(
        str(reason.get("code") or "unknown")
        for row in command_rows
        for reason in row.get("strict_evidence_reasons", [])
        if isinstance(reason, dict)
    )
    auto_rows = [row for row in command_rows if row.get("auto_execution_allowed")]
    executed_rows = [row for row in command_rows if row.get("execution_attempt")]
    outcome_rows = [row for row in command_rows if row.get("outcome_manifest_path")]
    binding_rows = [row for row in command_rows if row.get("binding_manifest_path")]
    reduced_blocked_rows = [
        row for row in command_rows
        if row.get("binding_reduction_status") in {"binding_manifest_generated", "manual_next_command_generated"}
    ]
    strict_required_rows = [row for row in command_rows if row.get("strict_evidence_required")]
    strict_blocked_rows = [row for row in command_rows if row.get("strict_validation_status") == "blocked"]
    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "workspace": str(workspace),
        "source_queue": str(queue_path),
        "source_queue_status": queue.get("status") or "",
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "submit_ready": False,
        "proof_boundary": (
            "This manifest validates task execution readiness only. It never "
            "marks a candidate proved and never auto-runs RESULT=proved commands."
        ),
        "summary": {
            "task_count": len(command_rows),
            "auto_executable_count": len(auto_rows),
            "executed_count": len(executed_rows),
            "outcome_manifest_count": len(outcome_rows),
            "binding_manifest_count": len(binding_rows),
            "blocked_reduction_count": len(reduced_blocked_rows),
            "needs_binding_count": readiness_counts.get("needs_binding", 0),
            "manual_validation_count": readiness_counts.get("manual_validation", 0),
            "strict_evidence_required_count": len(strict_required_rows),
            "strict_evidence_blocked_count": len(strict_blocked_rows),
            "readiness_counts": dict(sorted(readiness_counts.items())),
            "proof_kind_counts": dict(sorted(proof_kind_counts.items())),
            "safety_block_counts": dict(sorted(safety_block_counts.items())),
            "strict_reason_counts": dict(sorted(strict_reason_counts.items())),
        },
        "rows": command_rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Execution Proof Command Manifest",
        "",
        payload["proof_boundary"],
        "",
        "## Summary",
        "",
        f"- Tasks: `{summary['task_count']}`",
        f"- Auto-executable safe validators: `{summary['auto_executable_count']}`",
        f"- Executed in this run: `{summary['executed_count']}`",
        f"- Outcome manifests: `{summary.get('outcome_manifest_count', 0)}`",
        f"- Binding manifests: `{summary.get('binding_manifest_count', 0)}`",
        f"- Blocked rows reduced to binding work: `{summary.get('blocked_reduction_count', 0)}`",
        f"- Needs binding: `{summary['needs_binding_count']}`",
        f"- Manual validation: `{summary['manual_validation_count']}`",
        f"- Strict evidence required: `{summary.get('strict_evidence_required_count', 0)}`",
        f"- Strict evidence blocked: `{summary.get('strict_evidence_blocked_count', 0)}`",
        "",
        "## Commands",
        "",
        "| Task | Proof kind | Readiness | Safety blocks | Command |",
        "|---|---|---|---|---|",
    ]
    for row in payload["rows"]:
        blocks = ", ".join(row.get("safety_blocks") or []) or "_none_"
        lines.append(
            f"| `{row['task_id']}` | `{row['proof_kind']}` | `{row['readiness']}` | "
            f"{blocks} | `{row['runnable_command']}` |"
        )
    if not payload["rows"]:
        lines.append("| _none_ | _none_ | _none_ | _none_ | _none_ |")
    lines.extend(
        [
            "",
            "## Proof Boundary",
            "",
            "A row is submission proof only after a matching `poc_execution/**/execution_manifest.json` records `final_result=proved`, `impact_assertion=exploit_impact`, `evidence_class=executed_with_manifest`, and a structured `commands_attempted` row with `status=pass` and `exit_code=0`.",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--queue", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--execute-safe", action="store_true", help="Run only placeholder-free safe validator commands.")
    parser.add_argument("--generate-bindings", action="store_true", help="Write per-row binding manifests and safe next-command briefs.")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    queue_path = workspace_path(workspace, args.queue, Path(".auditooor/execution_proof_task_queue.json"))
    out_json = workspace_path(workspace, args.out_json, Path(".auditooor/execution_proof_command_manifest.json"))
    out_md = workspace_path(workspace, args.out_md, Path(".auditooor/execution_proof_command_manifest.md"))
    payload = build_manifest(
        queue_path,
        workspace,
        execute_safe=args.execute_safe,
        generate_bindings=args.generate_bindings,
        out_dir=out_json.parent,
    )
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[execution-proof] OK tasks={payload['summary']['task_count']} "
        f"safe={payload['summary']['auto_executable_count']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
