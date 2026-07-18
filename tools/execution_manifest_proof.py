#!/usr/bin/env python3
"""Shared strict proof predicates for ``poc_execution`` manifests.

The strict boundary is intentionally narrower than the generic
``executed_with_manifest`` evidence class. A manifest only proves exploit impact
when it records an actual passing command, not merely an attempted or scaffolded
run.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import os
from pathlib import Path
from typing import Any


STRICT_EVIDENCE_CLASS = "executed_with_manifest"


def bound_source_validation(manifest: dict[str, Any], workspace: Path) -> dict[str, Any]:
    """Validate optional replay-input bindings against their workspace files.

    ``poc-execution-record`` emits an empty list when no explicit source or
    harness was bound. That remains backward-compatible. Once a binding is
    present, however, strict consumers must reject it when the recorded file
    cannot be re-read as the same regular workspace file.
    """

    if "bound_sources" not in manifest:
        return {"supplied": False, "valid": True, "entries": [], "errors": []}
    rows = manifest.get("bound_sources")
    if not isinstance(rows, list):
        return {"supplied": True, "valid": False, "entries": [], "errors": ["bound_sources_malformed"]}

    root = workspace.resolve()
    entries: list[dict[str, Any]] = []
    errors: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            errors.append("bound_source_malformed")
            continue
        relative = row.get("path")
        expected_hash = row.get("sha256")
        expected_size = row.get("size")
        if (
            not isinstance(relative, str)
            or not relative
            or "\x00" in relative
            or Path(relative).is_absolute()
            or not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or not expected_hash.isascii()
            or any(char not in "0123456789abcdefABCDEF" for char in expected_hash)
            or isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            errors.append("bound_source_malformed")
            continue

        path = root / relative
        try:
            path.relative_to(root)
        except ValueError:
            errors.append("bound_source_outside_workspace")
            continue
        current = root
        symlinked = False
        for component in Path(relative).parts:
            current /= component
            try:
                if os.lstat(current).st_mode & 0o170000 == 0o120000:
                    symlinked = True
                    break
            except FileNotFoundError:
                break
        if symlinked:
            errors.append("bound_source_symlink")
            continue
        if not path.is_file():
            errors.append("bound_source_missing")
            continue
        if path.stat().st_size != expected_size:
            errors.append("bound_source_size_mismatch")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest().lower() != expected_hash.lower():
            errors.append("bound_source_hash_mismatch")
            continue
        entries.append({"path": relative, "sha256": expected_hash.lower(), "size": expected_size})

    return {
        "supplied": True,
        "valid": not errors,
        "entries": entries,
        "errors": sorted(set(errors)),
    }


def commands_attempted(value: object) -> list[Any]:
    if isinstance(value, dict):
        commands = value.get("commands_attempted")
    else:
        commands = value
    return commands if isinstance(commands, list) else []


def is_zero_exit_code(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 0
    if isinstance(value, str):
        return value.strip() == "0"
    return False


def command_status_counts(value: object) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for row in commands_attempted(value):
        if isinstance(row, dict):
            status = str(row.get("status") or "unknown").strip().lower() or "unknown"
            counts[status] += 1
        else:
            counts["unstructured"] += 1
    return dict(sorted(counts.items()))


def command_evidence_counts(value: object) -> dict[str, int]:
    commands = commands_attempted(value)
    structured = 0
    passing = 0
    command_with_text = 0
    missing_exit_code = 0
    bool_exit_code = 0
    for row in commands:
        if not isinstance(row, dict):
            continue
        structured += 1
        raw_command = row.get("command")
        command = raw_command.strip() if isinstance(raw_command, str) else ""
        status = str(row.get("status") or "").strip().lower()
        if command:
            command_with_text += 1
        if "exit_code" not in row or row.get("exit_code") is None:
            missing_exit_code += 1
        if isinstance(row.get("exit_code"), bool):
            bool_exit_code += 1
        if command and status == "pass" and is_zero_exit_code(row.get("exit_code")):
            passing += 1
    return {
        "commands_attempted_count": len(commands),
        "structured_command_count": structured,
        "unstructured_command_count": len(commands) - structured,
        "command_with_text_count": command_with_text,
        "passing_command_count": passing,
        "missing_exit_code_count": missing_exit_code,
        "bool_exit_code_count": bool_exit_code,
    }


def passing_command_count(value: object) -> int:
    return command_evidence_counts(value)["passing_command_count"]


def has_passing_structured_command(value: object) -> bool:
    return passing_command_count(value) > 0


def is_strict_proved_execution_manifest(manifest: dict[str, Any]) -> bool:
    return (
        isinstance(manifest, dict)
        and str(manifest.get("final_result") or "") == "proved"
        and str(manifest.get("impact_assertion") or "") == "exploit_impact"
        and str(manifest.get("evidence_class") or "") == STRICT_EVIDENCE_CLASS
        and has_passing_structured_command(manifest)
    )


def strict_proof_blockers(manifest: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if str(manifest.get("final_result") or "") != "proved":
        blockers.append("final_result_proved")
    if str(manifest.get("impact_assertion") or "") != "exploit_impact":
        blockers.append("impact_assertion_exploit_impact")
    if str(manifest.get("evidence_class") or "") != STRICT_EVIDENCE_CLASS:
        blockers.append("evidence_class_executed_with_manifest")
    commands = commands_attempted(manifest)
    counts = command_evidence_counts(commands)
    if not isinstance(manifest.get("commands_attempted"), list) or not commands:
        blockers.append("commands_attempted")
    elif counts["structured_command_count"] == 0:
        blockers.append("commands_attempted_structured")
    elif counts["command_with_text_count"] == 0:
        blockers.append("commands_attempted_nonempty_command")
    if counts["passing_command_count"] == 0:
        blockers.append("commands_attempted_pass_exit_0")
    return blockers


def command_exit_code_nonzero(row: dict[str, Any]) -> bool:
    value = row.get("exit_code")
    if value is None or value == "":
        return False
    if isinstance(value, bool):
        return False
    return not is_zero_exit_code(value)


def strict_terminal_blockers(manifest: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    final_result = str(manifest.get("final_result") or "missing")
    impact_assertion = str(manifest.get("impact_assertion") or "missing")
    if final_result != "proved":
        blockers.append(f"final_result_{final_result}")
    if impact_assertion != "exploit_impact":
        blockers.append(f"impact_assertion_{impact_assertion}")
    if str(manifest.get("evidence_class") or "") != STRICT_EVIDENCE_CLASS:
        blockers.append("evidence_class_executed_with_manifest")

    commands = commands_attempted(manifest)
    counts = command_evidence_counts(manifest)
    structured = [row for row in commands if isinstance(row, dict)]
    if not isinstance(manifest.get("commands_attempted"), list) or not commands:
        blockers.append("commands_attempted")
    elif counts["structured_command_count"] == 0:
        blockers.append("commands_attempted_structured")
    elif counts["command_with_text_count"] == 0:
        blockers.append("commands_attempted_nonempty_command")
    if counts["passing_command_count"] == 0:
        blockers.append("commands_attempted_pass_exit_0")
    if counts["passing_command_count"] == 0 and any(command_exit_code_nonzero(row) for row in structured):
        blockers.append("command_exit_nonzero")
    if counts["passing_command_count"] == 0 and counts["missing_exit_code_count"]:
        blockers.append("command_exit_code_missing")
    if counts["passing_command_count"] == 0 and counts["bool_exit_code_count"]:
        blockers.append("command_exit_code_bool")
    return blockers
