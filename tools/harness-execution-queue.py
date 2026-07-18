#!/usr/bin/env python3
"""Convert harness binding manifest rows into a safe local execution queue."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.harness_execution_queue.v0"
MANIFEST_SCHEMA = "auditooor.harness_binding_manifest.v0"
STATUS_SCHEMA = "auditooor.harness_binding_manifest_status.v0"
EXECUTION_CONTRACT_SCHEMA = "auditooor.harness_execution_contract.v1"
DEFAULT_MAX_READY = 50
DEFAULT_MAX_BLOCKED = 200
DEFAULT_MAX_ROWS = 200
DEFAULT_EXECUTION_TIMEOUT_SECONDS = 300
LOCAL_EXECUTABLES = {
    "python",
    "python3",
    "make",
    "forge",
    "cargo",
    "go",
    "bash",
    "sh",
    "zsh",
    "pytest",
    "jq",
}
NETWORK_TOKENS = ("http://", "https://", "curl ", "wget ", "gh ", "git clone", "pip install ", "npm install ")
DISALLOWED_TOKENS = ("llm-dispatch", "semantic-provider-batch.py")
SUPPORTED_SHELL_TOKENS = {"&&", "||", ";"}
SHELL_EXECUTABLES = {"bash", "sh", "zsh"}
VAGUE_COMMAND_TOKENS = (
    " tbd",
    " todo",
    " needs_human",
    " must emit",
    " should emit",
    " emits either",
    " plus ",
    ", with ",
    " proving ",
    " where one ",
    " event-to-aggregate",
)
BLOCKED_REASON_BY_INPUT = {
    "harness_command": "add one exact local harness command",
    "gating_test": "add one exact local gating command",
    "target_entrypoint": "bind the target entrypoint",
    "actor_setup": "bind the actor/setup path or template",
    "fixture_source": "bind the fixture source or fixture kit",
    "impact_contract_id": "bind the impact contract id",
    "generated_test_path": "bind or derive the generated harness path",
}
HARNESS_PATH_KEYS = ("generated_test_path", "test_path", "harness_path")
PROOF_SEMANTIC_KEYS = (
    "negative_control",
    "negative_controls",
    "first_negative_control",
    "required_negative_controls",
    "expected_verdict",
    "expected_passing_property",
    "fixture_role",
    "blocked_reason",
    "blocked_reasons",
    "proof_gate_blockers",
)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON at {path}: {exc}") from exc


def _nonempty_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _text_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return []


def _path_inside_workspace(path: Path, workspace: Path) -> bool:
    try:
        resolved = path.expanduser().resolve(strict=False)
        root = workspace.expanduser().resolve(strict=False)
        return resolved == root or root in resolved.parents
    except OSError:
        return False


def _split_segments(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return [command.strip()] if command.strip() else []

    parts: list[str] = []
    current: list[str] = []
    for token in tokens:
        if token in {"&&", "||", ";"}:
            if current:
                parts.append(shlex.join(current))
                current = []
            continue
        current.append(token)
    if current:
        parts.append(shlex.join(current))
    return parts


def _unsupported_shell_tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []

    unsupported = [token for token in tokens if set(token) <= set("|&<>") and token not in SUPPORTED_SHELL_TOKENS]
    return list(dict.fromkeys(unsupported))


def _skip_env_assignments(tokens: list[str]) -> list[str]:
    out = list(tokens)
    while out and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", out[0]):
        out.pop(0)
    return out


def _execution_segments(command: str) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    for segment in _split_segments(command):
        tokens = shlex.split(segment)
        env_delta: dict[str, str] = {}
        while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
            key, value = tokens.pop(0).split("=", 1)
            env_delta[key] = value
        if not tokens:
            raise ValueError("missing executable after environment assignments")
        segments.append({"argv": tokens, "env_delta": env_delta})
    if not segments:
        raise ValueError("missing executable command")
    return segments


def assess_local_command(command: str | None) -> dict[str, Any]:
    if not command:
        return {"safe": False, "command": None, "blockers": ["missing_command"]}

    text = command.strip()
    lowered = text.lower()
    blockers: list[str] = []

    if any(token in lowered for token in DISALLOWED_TOKENS):
        blockers.append("disallowed_llm_dispatch")
    if any(token in lowered for token in NETWORK_TOKENS):
        blockers.append("network_access_not_allowed")
    if any(token in lowered for token in VAGUE_COMMAND_TOKENS):
        blockers.append("vague_command")
    unsupported_shell_tokens = _unsupported_shell_tokens(text)
    if unsupported_shell_tokens:
        blockers.append("unsupported_shell_token:" + ",".join(unsupported_shell_tokens))

    segments = _split_segments(text)
    if not segments:
        blockers.append("missing_command")
    for segment in segments:
        try:
            tokens = shlex.split(segment)
        except ValueError:
            blockers.append("unparseable_command")
            continue
        tokens = _skip_env_assignments(tokens)
        if not tokens:
            blockers.append("missing_command")
            continue
        executable = tokens[0]
        if executable in SHELL_EXECUTABLES and "-c" in tokens[1:]:
            blockers.append("unsupported_shell_inline_command")
        if executable in LOCAL_EXECUTABLES:
            continue
        if executable.startswith("./") or executable.startswith("../") or executable.startswith("/"):
            continue
        if executable.endswith(".py") or executable.endswith(".sh"):
            continue
        blockers.append(f"unsupported_executable:{executable}")

    return {"safe": not blockers, "command": text if not blockers else None, "blockers": sorted(set(blockers))}


def load_binding_rows(path: Path) -> tuple[str, str | None, list[dict[str, Any]]]:
    payload = _read_json(path)
    schema = _nonempty_text(payload.get("schema")) if isinstance(payload, dict) else ""
    if schema == MANIFEST_SCHEMA:
        rows = payload.get("rows")
        if not isinstance(rows, list):
            raise ValueError(f"manifest rows are missing from {path}")
        return schema, payload.get("workspace"), [row for row in rows if isinstance(row, dict)]

    if schema == STATUS_SCHEMA:
        rows: list[dict[str, Any]] = []
        for key, value in payload.items():
            if not isinstance(value, dict):
                continue
            probe = value.get("local_queue_probe")
            if not isinstance(probe, dict):
                continue
            rows.append(
                {
                    "row_id": _nonempty_text(probe.get("row_id")) or key,
                    "title": _nonempty_text(value.get("state_delta")) or _nonempty_text(value.get("previous_queue_status")),
                    "binding_scope": _nonempty_text(probe.get("binding_scope")) or "harness",
                    "row_kind": "status_probe",
                    "harness_family": None,
                    "status": _nonempty_text(probe.get("status")) or "blocked_missing_inputs",
                    "has_executable_harness_command": bool(probe.get("has_executable_harness_command")),
                    "harness_command": None,
                    "gating_test": None,
                    "required_inputs": {},
                    "missing_inputs": list(probe.get("missing_inputs", [])),
                    "bindings": {},
                    "blockers": list(probe.get("blockers", [])),
                    "execution_contract": probe.get("execution_contract"),
                }
            )
        return schema, None, rows

    raise ValueError(
        f"unsupported input schema in {path}: expected {MANIFEST_SCHEMA} or {STATUS_SCHEMA}, got {schema or 'missing'}"
    )


def _priority_for_row(row: dict[str, Any]) -> int:
    status = _nonempty_text(row.get("status"))
    blockers = set(row.get("blockers", []))
    missing_inputs = set(row.get("missing_inputs", []))
    if status == "ready_executable_binding":
        return 10
    if "gating_test" in missing_inputs and row.get("has_executable_harness_command"):
        return 20
    if status == "blocked_missing_inputs":
        return 30
    if status == "blocked_vague_plan":
        return 60
    if status == "blocked_disallowed_command":
        return 90 if "network_access_not_allowed" in blockers or "disallowed_llm_dispatch" in blockers else 80
    return 70


def _next_action_reason(row: dict[str, Any]) -> str:
    status = _nonempty_text(row.get("status"))
    blockers = set(row.get("blockers", []))
    missing_inputs = [item for item in row.get("missing_inputs", []) if isinstance(item, str)]
    if status == "ready_executable_binding":
        return "run the exact local gating and harness commands in dry-run order"
    if "vague_command" in blockers:
        return "replace prose-only plan text with one exact local command"
    if "disallowed_llm_dispatch" in blockers:
        return "replace llm-dispatch usage with an offline local command"
    if "network_access_not_allowed" in blockers:
        return "replace network-dependent steps with offline local commands"
    if missing_inputs:
        return BLOCKED_REASON_BY_INPUT.get(missing_inputs[0], f"bind missing input {missing_inputs[0]}")
    if blockers:
        return f"resolve blocker {sorted(blockers)[0]}"
    return "inspect row and add one exact safe local command"


def _command_rows(row: dict[str, Any], *, workspace: str, cwd: str, priority: int) -> list[dict[str, Any]]:
    commands: list[tuple[str, str]] = []
    gating = _nonempty_text(row.get("gating_test"))
    harness = _nonempty_text(row.get("harness_command"))
    if gating:
        commands.append(("gating_test", gating))
    if harness and harness != gating:
        commands.append(("harness_command", harness))

    queue_rows = []
    composition_metadata = _composition_metadata(row)
    for command_kind, command in commands:
        assessed = assess_local_command(command)
        if not assessed["safe"]:
            continue
        command_row = {
            "row_id": row["row_id"],
            "title": row.get("title") or "",
            "command_kind": command_kind,
            "command": assessed["command"],
            "priority": priority,
            "cwd": cwd,
            "workspace": workspace,
            "expected_artifacts": _expected_artifacts(row),
            "proof_boundary": _proof_boundary(row),
            "dry_run": True,
            "would_execute": False,
            "safety_caveats": [
                "local-only command derived from a binding manifest row",
                "planning artifact only; command execution is not performed here",
            ],
        }
        harness_paths, _ = _harness_paths(row, Path(workspace))
        if harness_paths:
            command_row["harness_paths"] = harness_paths
        command_row.update(_proof_semantics(row))
        command_row.update(composition_metadata)
        queue_rows.append(command_row)
    return queue_rows


def _contract_claim(row: dict[str, Any]) -> str:
    contract = row.get("execution_contract")
    if isinstance(contract, dict):
        return _nonempty_text(contract.get("claim")) or "missing_contract"
    binding_scope = _nonempty_text(row.get("binding_scope"))
    status = _nonempty_text(row.get("status"))
    if status == "ready_executable_binding" and binding_scope not in {"harness", "composed_chain_harness"}:
        return "advisory_only"
    if binding_scope in {"harness", "composed_chain_harness"}:
        return "missing_contract"
    return "advisory_only"


def _expected_artifacts(row: dict[str, Any]) -> list[str]:
    contract = row.get("execution_contract")
    if isinstance(contract, dict):
        artifacts = contract.get("expected_artifacts")
        if isinstance(artifacts, list):
            return [str(item) for item in artifacts if isinstance(item, str) and item.strip()]
    artifacts = row.get("expected_artifacts")
    if isinstance(artifacts, list):
        return [str(item) for item in artifacts if isinstance(item, str) and item.strip()]
    artifacts = row.get("local_evidence")
    if isinstance(artifacts, list):
        return [str(item) for item in artifacts if isinstance(item, str) and item.strip() and ("/" in item or item.startswith("."))]
    local_status_packet = _nonempty_text(row.get("local_status_packet"))
    if local_status_packet:
        return [local_status_packet]
    return []


def _proof_boundary(row: dict[str, Any]) -> str:
    contract = row.get("execution_contract")
    if isinstance(contract, dict):
        boundary = _nonempty_text(contract.get("proof_boundary"))
        if boundary:
            return boundary
    boundary = _nonempty_text(row.get("proof_boundary"))
    if boundary:
        return boundary
    boundary = _nonempty_text(row.get("status_notes"))
    if boundary:
        return boundary
    return "Status refresh or advisory evidence only; not runnable harness evidence."


def _contract(row: dict[str, Any]) -> dict[str, Any]:
    contract = row.get("execution_contract")
    return contract if isinstance(contract, dict) else {}


def _binding_value(row: dict[str, Any], key: str) -> Any:
    bindings = row.get("bindings") if isinstance(row.get("bindings"), dict) else {}
    contract = _contract(row)
    if row.get(key) not in (None, "", []):
        return row.get(key)
    if bindings.get(key) not in (None, "", []):
        return bindings.get(key)
    if contract.get(key) not in (None, "", []):
        return contract.get(key)
    return None


def _harness_paths(row: dict[str, Any], workspace: Path) -> tuple[list[str], list[str]]:
    paths: list[str] = []
    blockers: list[str] = []
    for key in HARNESS_PATH_KEYS:
        value = _binding_value(row, key)
        for item in _text_list(value):
            paths.append(item)
    paths = list(dict.fromkeys(paths))
    if not paths:
        return [], ["missing_generated_test_path"]

    valid_paths: list[str] = []
    for item in paths:
        path = Path(item).expanduser()
        candidate = path if path.is_absolute() else workspace / path
        if not _path_inside_workspace(candidate, workspace):
            blockers.append("generated_test_path_outside_workspace")
            continue
        if not candidate.resolve(strict=False).is_file():
            blockers.append("generated_test_path_missing")
            continue
        valid_paths.append(str(candidate.resolve(strict=False)))
    return valid_paths, sorted(set(blockers))


def _blocked_reasons(row: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    contract = _contract(row)
    for source in (row, contract):
        reasons.extend(_text_list(source.get("blocked_reason")))
        reasons.extend(_text_list(source.get("blocked_reasons")))
    return list(dict.fromkeys(reasons))


def _proof_semantics(row: dict[str, Any]) -> dict[str, Any]:
    contract = _contract(row)
    out: dict[str, Any] = {}
    for key in PROOF_SEMANTIC_KEYS:
        value = row.get(key)
        if value in (None, "", []):
            value = contract.get(key)
        if value not in (None, "", []):
            out[key] = value
    reasons = _blocked_reasons(row)
    if reasons:
        out["blocked_reasons"] = reasons
    return out


def _source_backing_blockers(
    *,
    source_schema: str,
    source_path: Path | None,
    workspace: Path,
    manifest_workspace: str | None,
) -> list[str]:
    blockers: list[str] = []
    if source_schema != MANIFEST_SCHEMA:
        blockers.append("input_not_binding_manifest")
    if source_path is None:
        blockers.append("missing_source_path")
    elif not source_path.expanduser().resolve(strict=False).is_file():
        blockers.append("source_path_missing")
    if not manifest_workspace:
        blockers.append("missing_manifest_workspace")
    else:
        manifest_path = Path(manifest_workspace).expanduser().resolve(strict=False)
        if manifest_path != workspace.expanduser().resolve(strict=False):
            blockers.append("manifest_workspace_mismatch")
    return sorted(set(blockers))


def _next_action_from_blockers(blockers: list[str], fallback: str) -> str:
    blocker_set = set(blockers)
    if "manifest_workspace_mismatch" in blocker_set:
        return "regenerate the binding manifest for the current workspace"
    if "missing_manifest_workspace" in blocker_set:
        return "regenerate the binding manifest with its workspace field populated"
    if "input_not_binding_manifest" in blocker_set or "missing_source_path" in blocker_set:
        return "regenerate the queue from a source-backed binding manifest"
    if "source_path_missing" in blocker_set:
        return "restore or regenerate the binding manifest source file"
    if "generated_test_path_outside_workspace" in blocker_set:
        return "bind a generated_test_path under the current workspace"
    if "generated_test_path_missing" in blocker_set or "missing_generated_test_path" in blocker_set:
        return "bind one concrete local generated_test_path before execution"
    if "runnable_contract_has_blocked_reasons" in blocker_set:
        return "clear the blocked_reason path before exposing executable commands"
    return fallback


def _composition_metadata(row: dict[str, Any]) -> dict[str, Any]:
    if _nonempty_text(row.get("binding_scope")) != "composed_chain_harness":
        return {}
    bindings = row.get("bindings") if isinstance(row.get("bindings"), dict) else {}
    out: dict[str, Any] = {"binding_scope": "composed_chain_harness"}
    for key in (
        "chain_id",
        "producer_lead_id",
        "consumer_lead_id",
        "bridging_state",
        "producer_source_artifact",
    ):
        value = row.get(key)
        if value not in (None, "", []):
            out[key] = value
    producer_state_artifact = row.get("producer_state_artifact") or bindings.get("producer_state_artifact")
    fixture_source = row.get("fixture_source") or bindings.get("fixture_source")
    consumer_entrypoint = row.get("consumer_entrypoint") or bindings.get("consumer_entrypoint")
    if producer_state_artifact:
        out["producer_state_artifact"] = producer_state_artifact
    if fixture_source:
        out["fixture_source"] = fixture_source
    if consumer_entrypoint:
        out["consumer_entrypoint"] = consumer_entrypoint
    return out


def _claimed_runnable_without_contract(row: dict[str, Any]) -> bool:
    status = _nonempty_text(row.get("status"))
    binding_scope = _nonempty_text(row.get("binding_scope"))
    has_command = bool(row.get("has_executable_harness_command"))
    return status == "ready_executable_binding" and binding_scope in {"harness", "composed_chain_harness"} and has_command


def validate_execution_contract(row: dict[str, Any]) -> dict[str, Any]:
    """Validate the row-level contract before any ready command is exposed."""
    contract = row.get("execution_contract")
    status = _nonempty_text(row.get("status"))
    binding_scope = _nonempty_text(row.get("binding_scope"))
    result = {
        "valid": False,
        "claim": _contract_claim(row),
        "runnable_harness": False,
        "advisory_only": False,
        "blockers": [],
    }

    if not isinstance(contract, dict):
        if _claimed_runnable_without_contract(row):
            result["blockers"] = ["missing_execution_contract"]
            return result
        if result["claim"] == "advisory_only":
            result["valid"] = True
            result["advisory_only"] = True
            return result
        return result

    blockers: list[str] = []
    claim = _nonempty_text(contract.get("claim"))
    if contract.get("schema") != EXECUTION_CONTRACT_SCHEMA:
        blockers.append("invalid_execution_contract_schema")
    if claim not in {"runnable_harness", "blocked_harness", "advisory_only"}:
        blockers.append("invalid_execution_contract_claim")
    if contract.get("fail_closed") is not True:
        blockers.append("execution_contract_not_fail_closed")
    if _nonempty_text(contract.get("binding_scope")) != binding_scope:
        blockers.append("execution_contract_binding_scope_mismatch")
    if _nonempty_text(contract.get("status_snapshot")) != status:
        blockers.append("execution_contract_status_mismatch")

    commands = contract.get("commands")
    if not isinstance(commands, dict):
        blockers.append("execution_contract_missing_commands")
        commands = {}
    if commands.get("harness_command") != row.get("harness_command"):
        blockers.append("execution_contract_harness_command_mismatch")
    if commands.get("gating_test") != row.get("gating_test"):
        blockers.append("execution_contract_gating_test_mismatch")

    row_missing = sorted(str(item) for item in row.get("missing_inputs", []) if isinstance(item, str))
    row_blockers = sorted(str(item) for item in row.get("blockers", []) if isinstance(item, str))
    contract_missing = sorted(str(item) for item in contract.get("missing_inputs", []) if isinstance(item, str))
    contract_blockers = sorted(str(item) for item in contract.get("blockers", []) if isinstance(item, str))
    if contract_blockers != row_blockers:
        blockers.append("execution_contract_blockers_mismatch")

    if claim == "runnable_harness":
        if status != "ready_executable_binding":
            blockers.append("runnable_contract_requires_ready_status")
        if binding_scope not in {"harness", "composed_chain_harness"}:
            blockers.append("runnable_contract_requires_harness_scope")
        harness_command = _nonempty_text(row.get("harness_command"))
        gating_test = _nonempty_text(row.get("gating_test"))
        harness_assessment = assess_local_command(harness_command)
        if not harness_assessment["safe"]:
            blockers.extend(f"harness_command_{item}" for item in harness_assessment["blockers"])
        if gating_test:
            gating_assessment = assess_local_command(gating_test)
            if not gating_assessment["safe"]:
                blockers.extend(f"gating_test_{item}" for item in gating_assessment["blockers"])
        if row_missing:
            blockers.append("runnable_contract_has_missing_inputs")
        if row_blockers:
            blockers.append("runnable_contract_has_blockers")
        if contract_missing:
            blockers.append("runnable_contract_missing_inputs_not_empty")
        if contract.get("runnable") is not True:
            blockers.append("runnable_contract_flag_false")
        if contract.get("advisory_only") is True:
            blockers.append("runnable_contract_marked_advisory")
        if _blocked_reasons(row):
            blockers.append("runnable_contract_has_blocked_reasons")
    elif claim == "blocked_harness":
        if binding_scope not in {"harness", "composed_chain_harness"}:
            blockers.append("blocked_contract_requires_harness_scope")
        if contract.get("runnable") is True:
            blockers.append("blocked_contract_marked_runnable")
        if contract_missing != row_missing:
            blockers.append("execution_contract_missing_inputs_mismatch")
    elif claim == "advisory_only":
        if contract.get("runnable") is True:
            blockers.append("advisory_contract_marked_runnable")
        if contract.get("advisory_only") is not True:
            blockers.append("advisory_contract_flag_false")

    result["valid"] = not blockers
    result["claim"] = claim or result["claim"]
    result["runnable_harness"] = result["valid"] and claim == "runnable_harness"
    result["advisory_only"] = result["valid"] and claim == "advisory_only"
    result["blockers"] = sorted(set(blockers))
    return result


def _prereq_command_rows(row: dict[str, Any], *, workspace: str, cwd: str, priority: int) -> list[dict[str, Any]]:
    commands: list[tuple[str, str]] = []
    gating = _nonempty_text(row.get("gating_test"))
    harness = _nonempty_text(row.get("harness_command"))
    if gating:
        commands.append(("gating_test", gating))
    if harness and harness != gating:
        commands.append(("harness_command", harness))

    prereq_rows = []
    composition_metadata = _composition_metadata(row)
    for command_kind, command in commands:
        assessed = assess_local_command(command)
        if not assessed["safe"]:
            continue
        command_row = {
            "row_id": row["row_id"],
            "title": row.get("title") or "",
            "command_kind": command_kind,
            "command": assessed["command"],
            "priority": priority,
            "cwd": cwd,
            "workspace": workspace,
            "expected_artifacts": _expected_artifacts(row),
            "proof_boundary": _proof_boundary(row),
            "dry_run": True,
            "would_execute": False,
            "command_status": "blocked_row_prereq",
            "safety_caveats": [
                "safe local prerequisite command from a still-blocked row",
                "running this command does not clear missing bindings by itself",
            ],
        }
        harness_paths, _ = _harness_paths(row, Path(workspace))
        if harness_paths:
            command_row["harness_paths"] = harness_paths
        command_row.update(_proof_semantics(row))
        command_row.update(composition_metadata)
        prereq_rows.append(command_row)
    return prereq_rows


def execute_command_row(command_row: dict[str, Any], *, timeout_seconds: int) -> dict[str, Any]:
    command = _nonempty_text(command_row.get("command"))
    assessed = assess_local_command(command)
    result: dict[str, Any] = {
        "row_id": command_row.get("row_id"),
        "command_kind": command_row.get("command_kind"),
        "command": command,
        "cwd": command_row.get("cwd"),
        "expected_artifacts": list(command_row.get("expected_artifacts") or []),
        "proof_boundary": _nonempty_text(command_row.get("proof_boundary")) or "Status refresh or advisory evidence only; not runnable harness evidence.",
        "dry_run": False,
        "would_execute": True,
        "timeout_seconds": timeout_seconds,
        "status": "blocked_unsafe_command",
        "returncode": None,
        "elapsed_seconds": 0.0,
        "segment_results": [],
    }
    if command_row.get("harness_paths"):
        result["harness_paths"] = list(command_row.get("harness_paths") or [])
    result.update(_proof_semantics(command_row))
    result.update(_composition_metadata(command_row))
    if not assessed["safe"]:
        result["blockers"] = assessed["blockers"]
        return result

    cwd = Path(str(command_row.get("cwd") or ".")).expanduser().resolve()
    if not cwd.exists():
        result["status"] = "blocked_missing_cwd"
        result["blockers"] = [f"missing_cwd:{cwd}"]
        return result

    try:
        segments = _execution_segments(command)
    except ValueError as exc:
        result["status"] = "blocked_unparseable_command"
        result["blockers"] = [str(exc)]
        return result

    started = time.monotonic()
    env = os.environ.copy()
    for index, segment in enumerate(segments, start=1):
        remaining_timeout = max(1, timeout_seconds - int(time.monotonic() - started))
        segment_env = env.copy()
        segment_env.update(segment["env_delta"])
        segment_result: dict[str, Any] = {
            "index": index,
            "argv": segment["argv"],
            "env_delta_keys": sorted(segment["env_delta"]),
            "returncode": None,
            "status": "running",
            "stdout_tail": "",
            "stderr_tail": "",
        }
        try:
            completed = subprocess.run(
                segment["argv"],
                cwd=cwd,
                env=segment_env,
                text=True,
                capture_output=True,
                timeout=remaining_timeout,
                check=False,
            )
        except FileNotFoundError:
            segment_result["status"] = "missing_executable"
            segment_result["returncode"] = 127
            result["segment_results"].append(segment_result)
            result["status"] = "failed"
            result["returncode"] = 127
            break
        except subprocess.TimeoutExpired as exc:
            segment_result["status"] = "timed_out"
            segment_result["stdout_tail"] = (exc.stdout or "")[-4000:]
            segment_result["stderr_tail"] = (exc.stderr or "")[-4000:]
            result["segment_results"].append(segment_result)
            result["status"] = "timed_out"
            result["returncode"] = None
            break

        segment_result["returncode"] = completed.returncode
        segment_result["stdout_tail"] = completed.stdout[-4000:]
        segment_result["stderr_tail"] = completed.stderr[-4000:]
        segment_result["status"] = "passed" if completed.returncode == 0 else "failed"
        result["segment_results"].append(segment_result)
        if completed.returncode != 0:
            result["status"] = "failed"
            result["returncode"] = completed.returncode
            break
    else:
        result["status"] = "passed"
        result["returncode"] = 0

    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def _execution_identity(command_row: dict[str, Any]) -> tuple[str, str]:
    return (
        str(command_row.get("cwd") or ""),
        _nonempty_text(command_row.get("command")),
    )


def _dedupe_ready_commands(
    ready_commands: list[dict[str, Any]],
    *,
    max_execute: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    skipped_duplicates: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for command_row in ready_commands:
        identity = _execution_identity(command_row)
        first = seen.get(identity)
        if first is not None:
            skipped_duplicates.append(
                {
                    "row_id": command_row.get("row_id"),
                    "command_kind": command_row.get("command_kind"),
                    "command": command_row.get("command"),
                    "cwd": command_row.get("cwd"),
                    "duplicate_of": {
                        "row_id": first.get("row_id"),
                        "command_kind": first.get("command_kind"),
                    },
                }
            )
            continue
        seen[identity] = command_row
        if len(selected) < max_execute:
            selected.append(command_row)
    return selected, skipped_duplicates


def execute_ready_commands(
    queue: dict[str, Any],
    *,
    max_execute: int,
    timeout_seconds: int,
    row_id: str | None = None,
) -> dict[str, Any]:
    candidate_commands = [
        row
        for row in queue.get("ready_commands", [])
        if isinstance(row, dict) and (row_id is None or row.get("row_id") == row_id)
    ]
    ready_commands, skipped_duplicates = _dedupe_ready_commands(
        candidate_commands,
        max_execute=max_execute,
    )
    results = [
        execute_command_row(command_row, timeout_seconds=timeout_seconds) for command_row in ready_commands
    ]
    status_counts = Counter(result["status"] for result in results)
    return {
        "executed": True,
        "requested_row_id": row_id,
        "max_execute": max_execute,
        "timeout_seconds": timeout_seconds,
        "candidate_command_count": len(candidate_commands),
        "skipped_duplicate_command_count": len(skipped_duplicates),
        "selected_command_count": len(ready_commands),
        "result_count": len(results),
        "status_counts": dict(sorted(status_counts.items())),
        "all_passed": bool(results) and all(result["status"] == "passed" for result in results),
        "skipped_duplicate_commands": skipped_duplicates[:20],
        "results": results,
    }


def build_execution_queue(
    rows: list[dict[str, Any]],
    *,
    workspace: Path | None = None,
    manifest_workspace: str | None = None,
    source_schema: str,
    source_path: Path | None = None,
    max_ready: int = DEFAULT_MAX_READY,
    max_blocked: int = DEFAULT_MAX_BLOCKED,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> dict[str, Any]:
    base_path = (workspace or Path(".")).expanduser().resolve()
    base = str(base_path)
    source_backing_blockers = _source_backing_blockers(
        source_schema=source_schema,
        source_path=source_path,
        workspace=base_path,
        manifest_workspace=manifest_workspace,
    )
    all_rows = [row for row in rows if isinstance(row, dict)]
    # A blocked prefix must not hide executable rows later in a source manifest.
    # Keep the ready claims for validation, while retaining the existing bound for
    # non-ready intake rows that only provide bounded diagnostic context.
    ready_input_rows = [
        row for row in all_rows if row.get("status") == "ready_executable_binding"
    ]
    nonready_input_rows = [
        row for row in all_rows if row.get("status") != "ready_executable_binding"
    ]
    normalized_rows = ready_input_rows + (
        nonready_input_rows[:max_rows] if max_rows > 0 else []
    )
    queue_rows = []
    command_rows: list[dict[str, Any]] = []
    ready_commands: list[dict[str, Any]] = []
    advisory_commands: list[dict[str, Any]] = []
    blocked_commands: list[dict[str, Any]] = []

    for row in normalized_rows:
        row_id = _nonempty_text(row.get("row_id")) or "unknown-row"
        composition_metadata = _composition_metadata(row)
        priority = _priority_for_row(row)
        next_action_reason = _next_action_reason(row)
        raw_status = _nonempty_text(row.get("status")) or "blocked_missing_inputs"
        contract_check = validate_execution_contract(row)
        contract_claim = contract_check["claim"]
        status = raw_status
        harness_paths, harness_path_blockers = _harness_paths(row, base_path)
        eligibility_blockers = list(source_backing_blockers)
        if contract_claim == "runnable_harness" or (
            raw_status == "ready_executable_binding" and not contract_check["advisory_only"]
        ):
            eligibility_blockers.extend(harness_path_blockers)
        if _blocked_reasons(row) and raw_status == "ready_executable_binding":
            eligibility_blockers.append("runnable_contract_has_blocked_reasons")
        eligibility_blockers = sorted(set(eligibility_blockers))
        row_blockers = sorted(
            set(
                [
                    item for item in row.get("blockers", [])
                    if isinstance(item, str) and item.strip()
                ]
                + contract_check["blockers"]
                + eligibility_blockers
            )
        )
        row_missing_inputs = list(
            dict.fromkeys(
                [
                    item for item in row.get("missing_inputs", [])
                    if isinstance(item, str) and item.strip()
                ]
            )
        )
        if contract_check["blockers"] and "execution_contract" not in row_missing_inputs:
            row_missing_inputs.append("execution_contract")
        if any(item in eligibility_blockers for item in ("missing_generated_test_path", "generated_test_path_missing", "generated_test_path_outside_workspace")):
            if "generated_test_path" not in row_missing_inputs:
                row_missing_inputs.append("generated_test_path")
        if any(item in eligibility_blockers for item in ("missing_manifest_workspace", "manifest_workspace_mismatch")):
            if "manifest_workspace" not in row_missing_inputs:
                row_missing_inputs.append("manifest_workspace")
        if any(item in eligibility_blockers for item in ("input_not_binding_manifest", "missing_source_path", "source_path_missing")):
            if "source_backed_manifest" not in row_missing_inputs:
                row_missing_inputs.append("source_backed_manifest")
        if "runnable_contract_has_blocked_reasons" in eligibility_blockers:
            if "blocked_reasons" not in row_missing_inputs:
                row_missing_inputs.append("blocked_reasons")
        if raw_status == "ready_executable_binding" and not contract_check["runnable_harness"]:
            if contract_check["advisory_only"]:
                status = "advisory_only"
                next_action_reason = "treat as advisory/status evidence; do not execute as runnable harness"
            else:
                status = "blocked_ambiguous_execution_contract"
                next_action_reason = _next_action_from_blockers(
                    row_blockers,
                    "add a valid runnable_harness execution_contract before exposing ready commands",
                )
        elif raw_status == "ready_executable_binding" and eligibility_blockers:
            status = "blocked_execution_prerequisites"
            next_action_reason = _next_action_from_blockers(eligibility_blockers, next_action_reason)
        else:
            next_action_reason = _next_action_from_blockers(row_blockers, next_action_reason)
        row_commands = _command_rows(row, workspace=base, cwd=base, priority=priority)
        prereq_commands = _prereq_command_rows(row, workspace=base, cwd=base, priority=priority)
        if status == "ready_executable_binding" and contract_check["runnable_harness"]:
            for item in row_commands:
                item["command_status"] = "ready_now"
                item["execution_contract_claim"] = contract_claim
                item["expected_artifacts"] = _expected_artifacts(row)
                item["proof_boundary"] = _proof_boundary(row)
            ready_commands.extend(row_commands)
            command_rows.extend(row_commands)
        elif status == "advisory_only":
            for item in prereq_commands:
                item["command_status"] = "advisory_only"
                item["execution_contract_claim"] = contract_claim
                item["expected_artifacts"] = _expected_artifacts(row)
                item["proof_boundary"] = _proof_boundary(row)
            advisory_commands.extend(prereq_commands)
            command_rows.extend(prereq_commands)
        else:
            command_rows.extend(prereq_commands)
            blocked_row = {
                "row_id": row_id,
                "title": row.get("title") or "",
                "status": status,
                "priority": priority,
                "execution_contract_claim": contract_claim,
                "execution_contract_valid": contract_check["valid"],
                "blockers": row_blockers,
                "missing_inputs": row_missing_inputs,
                "attempted_harness_command": _nonempty_text(row.get("harness_command")) or None,
                "attempted_gating_test": _nonempty_text(row.get("gating_test")) or None,
                "safe_local_prereq_commands": prereq_commands,
                "can_run_local_prereq_now": bool(prereq_commands),
                "expected_next_action": next_action_reason,
            }
            if harness_paths:
                blocked_row["harness_paths"] = harness_paths
            blocked_row.update(_proof_semantics(row))
            blocked_row.update(composition_metadata)
            blocked_commands.append(blocked_row)

        queue_row = {
            "row_id": row_id,
            "title": row.get("title") or "",
            "status": status,
            "binding_scope": row.get("binding_scope"),
            "harness_family": row.get("harness_family"),
            "execution_contract_claim": contract_claim,
            "execution_contract_valid": contract_check["valid"],
            "expected_artifacts": _expected_artifacts(row),
            "proof_boundary": _proof_boundary(row),
            "priority": priority,
            "ready_command_count": len(row_commands) if status == "ready_executable_binding" and contract_check["runnable_harness"] else 0,
            "advisory_command_count": len(prereq_commands) if status == "advisory_only" else 0,
            "prereq_command_count": len(prereq_commands) if status not in {"ready_executable_binding", "advisory_only"} else 0,
            "blockers": row_blockers,
            "missing_inputs": row_missing_inputs,
            "expected_next_action": next_action_reason,
        }
        if harness_paths:
            queue_row["harness_paths"] = harness_paths
        queue_row.update(_proof_semantics(row))
        queue_row.update(composition_metadata)
        queue_rows.append(queue_row)

    queue_rows.sort(key=lambda item: (item["priority"], item["row_id"]))
    command_rows.sort(key=lambda item: (item["priority"], item["row_id"], item["command_kind"], item["command_status"]))
    ready_commands.sort(key=lambda item: (item["priority"], item["row_id"], item["command_kind"]))
    advisory_commands.sort(key=lambda item: (item["priority"], item["row_id"], item["command_kind"]))
    blocked_commands.sort(key=lambda item: (item["priority"], item["row_id"]))
    ready_commands = ready_commands[:max_ready]
    advisory_commands = advisory_commands[:max_ready]
    blocked_commands = blocked_commands[:max_blocked]
    command_rows = command_rows[: max_ready + max_blocked]
    counts_by_status = Counter(row["status"] for row in queue_rows)
    counts_by_contract_claim = Counter(row["execution_contract_claim"] for row in queue_rows)

    next_action_priority = queue_rows[0] if queue_rows else None
    return {
        "schema": SCHEMA,
        "source_schema": source_schema,
        "source_path": str(source_path) if source_path is not None else None,
        "workspace": base,
        "manifest_workspace": manifest_workspace,
        "source_backing": {
            "source_backed": not source_backing_blockers,
            "blockers": source_backing_blockers,
            "source_schema": source_schema,
            "source_path": str(source_path) if source_path is not None else None,
            "manifest_workspace": manifest_workspace,
            "current_workspace": base,
        },
        "row_count": len(queue_rows),
        "input_row_count": len(all_rows),
        "retained_ready_row_count": len(ready_input_rows),
        "retention_policy": "all_ready_plus_bounded_nonready",
        "ready_row_count": sum(1 for row in queue_rows if row["status"] == "ready_executable_binding"),
        "advisory_row_count": sum(1 for row in queue_rows if row["status"] == "advisory_only"),
        "blocked_row_count": sum(1 for row in queue_rows if row["status"] not in {"ready_executable_binding", "advisory_only"}),
        "ready_command_count": len(ready_commands),
        "advisory_command_count": len(advisory_commands),
        "blocked_command_count": len(blocked_commands),
        "command_row_count": len(command_rows),
        "counts_by_status": dict(sorted(counts_by_status.items())),
        "counts_by_contract_claim": dict(sorted(counts_by_contract_claim.items())),
        "safety_caveats": [
            "bounded dry-run queue only; this tool never executes commands",
            "local-only posture; network, llm-dispatch, and remote fetch flows stay blocked",
            "ready runnable harness rows require a valid auditooor.harness_execution_contract.v1 contract",
            "ready runnable harness rows require a source-backed manifest for the current workspace",
            "ready runnable harness rows require one concrete generated_test_path under the current workspace",
            "ready commands are re-validated against the local executable allowlist",
            "blocked rows surface explicit missing inputs instead of speculative command synthesis",
        ],
        "next_action_priority": next_action_priority,
        "command_rows": command_rows,
        "ready_commands": ready_commands,
        "advisory_commands": advisory_commands,
        "blocked_commands": blocked_commands,
        "rows": queue_rows,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Harness binding manifest JSON or status packet.")
    parser.add_argument("--workspace", default=".", help="Workspace root for emitted command context.")
    parser.add_argument("--out", default=None, help="Optional output JSON path.")
    parser.add_argument("--print-json", action="store_true", help="Print JSON to stdout even when --out is used.")
    parser.add_argument("--max-ready", type=int, default=DEFAULT_MAX_READY, help="Maximum ready command rows to emit.")
    parser.add_argument("--max-blocked", type=int, default=DEFAULT_MAX_BLOCKED, help="Maximum blocked command rows to emit.")
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS, help="Maximum input rows to retain.")
    parser.add_argument(
        "--execute-ready",
        action="store_true",
        help="Execute bounded ready command rows after queue construction; default remains dry-run only.",
    )
    parser.add_argument("--execute-row-id", default=None, help="When executing, restrict ready commands to one row id.")
    parser.add_argument(
        "--max-execute",
        type=int,
        default=DEFAULT_MAX_READY,
        help="Maximum ready commands to execute when --execute-ready is set.",
    )
    parser.add_argument(
        "--execution-timeout",
        type=int,
        default=DEFAULT_EXECUTION_TIMEOUT_SECONDS,
        help="Per-command execution timeout in seconds when --execute-ready is set.",
    )
    parser.add_argument(
        "--fail-on-execution-failure",
        action="store_true",
        help="Return exit code 1 when --execute-ready records any non-passing command.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    input_path = Path(args.input).expanduser().resolve()
    workspace = Path(args.workspace).expanduser().resolve()
    source_schema, manifest_workspace, rows = load_binding_rows(input_path)
    queue = build_execution_queue(
        rows,
        workspace=workspace,
        manifest_workspace=manifest_workspace,
        source_schema=source_schema,
        source_path=input_path,
        max_ready=args.max_ready,
        max_blocked=args.max_blocked,
        max_rows=args.max_rows,
    )
    if args.execute_ready:
        queue["execution_summary"] = execute_ready_commands(
            queue,
            max_execute=args.max_execute,
            timeout_seconds=args.execution_timeout,
            row_id=args.execute_row_id,
        )
        queue["safety_caveats"] = [
            caveat for caveat in queue["safety_caveats"] if caveat != "bounded dry-run queue only; this tool never executes commands"
        ] + [
            "execution mode was explicitly requested; only ready rows that pass local command validation are invoked",
            "commands run without a shell and stop on the first failing segment",
        ]
    else:
        queue["execution_summary"] = {
            "executed": False,
            "reason": "default dry-run mode; pass --execute-ready to run ready command rows",
        }
    payload = json.dumps(queue, indent=2, sort_keys=True) + "\n"

    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload, encoding="utf-8")
    if args.print_json or not args.out:
        print(payload, end="")
    if args.execute_ready and args.fail_on_execution_failure and not queue["execution_summary"]["all_passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
