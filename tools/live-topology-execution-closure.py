#!/usr/bin/env python3
"""Summarize live-topology execution closure blockers.

This is an accounting layer for the live-topology closure lane. It does not
execute RPC and does not mark proof as collected. It consumes the canonical
skeleton, the runnable live-check output, and proof-executor outputs to produce
exact grouped terminal blockers when local address/RPC/block/manual-proof data
is absent.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_execution_closure.v1"
SOURCE_REF_KEYS = (
    "source_refs",
    "source_ref",
    "file_line",
    "file_lines",
    "target_file",
    "source_file",
    "source_path",
    "workspace_source_refs",
    "configured_source_refs",
)
TOPOLOGY_PATH_KEYS = (
    "topology_path",
    "topology_paths",
    "configured_topology_path",
    "configured_topology_paths",
    "deployment_topology_path",
    "deployment_topology_paths",
    "configuration_source_ref",
    "topology_source_ref",
)
TOPOLOGY_EVIDENCE_KEYS = (
    "configured_topology_evidence",
    "topology_evidence",
    "deployment_topology",
    "deployment_topology_evidence",
    "configuration_precondition",
    "configuration_evidence",
)
PROOF_COMMAND_KEYS = (
    "proof_command",
    "proof_commands",
    "exact_proof_command",
    "harness_command",
    "gating_test",
    "capture_command",
    "test_command",
)
PROOF_EVIDENCE_KEYS = (
    "proof_evidence",
    "harness_evidence",
    "execution_contract",
    "execution_manifest",
    "pass_evidence_lines",
    "test_transcript",
    "proof_transcript",
    "execution_evidence",
    "capture_evidence",
)
PROOF_PATH_KEYS = (
    "proof_file",
    "proof_artifact",
    "proof_artifacts",
    "proof_artifact_path",
    "poc_path",
    "test_path",
    "generated_test_path",
    "harness_path",
    "execution_manifest_path",
)
BLOCKER_KEYS = (
    "blockers",
    "promotion_blockers",
    "proof_blockers",
    "terminal_blockers",
    "required_unblockers",
    "pair_validation_blockers",
    "blocking_markers",
)
REF_DICT_KEYS = (
    "ref",
    "path",
    "file",
    "source_ref",
    "source_path",
    "target_file",
    "configured_topology_path",
    "proof_artifact_path",
    "harness_path",
)
SOURCE_REF_RE = re.compile(
    r"(?P<path>(?:~|/|\.{1,2}/|[A-Za-z0-9_.-])"
    r"[A-Za-z0-9_./@%+,\-]*\."
    r"(?:sol|vy|go|rs|move|cairo|tsx|ts|jsx|json|js|py|md|yaml|yml|toml|txt|log))"
    r"(?:(?::|#L)(?P<line>\d+))?"
)
MISSING_TEXT = {"", "n/a", "na", "none", "null", "unknown", "todo", "tbd", "advisory", "advisory_only"}
ADVISORY_POSTURE = {
    "coverage_claim": "live_topology_execution_closure_accounting_only",
    "advisory_only": True,
    "promotion_allowed": False,
    "severity": "none",
    "selected_impact": "",
    "submission_posture": "NOT_SUBMIT_READY",
    "impact_contract_required": True,
}


def _load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[live-topology-execution-closure] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-execution-closure] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-execution-closure] expected object JSON for {label}: {path}")
    return payload


def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def _reason_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        for reason in row.get("closure_readiness_reasons") or []:
            text = str(reason).strip()
            if text:
                counts[text] = counts.get(text, 0) + 1
    return dict(sorted(counts.items()))


def _list_rows(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return [row for row in payload.get(key) or [] if isinstance(row, dict)]


def _index_by_id(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row.get("id") or "").strip(): row for row in rows if str(row.get("id") or "").strip()}


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def _is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text.lower() in MISSING_TEXT or text.startswith("<") or text.endswith(">")


def _text_values(value: Any, *, ref_fields_only: bool = False) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, bool):
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_text_values(item, ref_fields_only=ref_fields_only))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        if ref_fields_only:
            for key in REF_DICT_KEYS:
                out.extend(_text_values(value.get(key), ref_fields_only=False))
            return out
        for item in value.values():
            out.extend(_text_values(item, ref_fields_only=False))
        return out
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _collect_values(
    payloads: list[dict[str, Any]],
    keys: tuple[str, ...],
    *,
    ref_fields_only: bool = False,
) -> list[str]:
    values: list[str] = []
    for payload in payloads:
        for key in keys:
            values.extend(_text_values(payload.get(key), ref_fields_only=ref_fields_only))
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = value.strip()
        if text and text not in seen:
            out.append(text)
            seen.add(text)
    return out


def _clean_ref(value: str) -> str:
    text = value.strip().strip("`'\"()[]{}<>,.;")
    if text.startswith("workspace:"):
        text = text[len("workspace:") :]
    return text.strip()


def _line_exists(path: Path, line_no: int) -> bool:
    if line_no <= 0:
        return False
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for index, _line in enumerate(handle, 1):
                if index >= line_no:
                    return True
    except OSError:
        return False
    return False


def _resolve_workspace_ref(workspace: Path, raw_ref: str, *, missing_reason: str) -> dict[str, Any]:
    text = _clean_ref(raw_ref)
    match = SOURCE_REF_RE.search(text)
    if not match:
        return {"ref": raw_ref, "current": False, "reason": missing_reason}
    raw_path = match.group("path")
    if raw_path.startswith(f"{workspace.name}/"):
        raw_path = raw_path[len(workspace.name) + 1 :]
    path = Path(raw_path).expanduser()
    line = int(match.group("line")) if match.group("line") else None
    try:
        resolved = path.resolve(strict=False) if path.is_absolute() else (workspace / path).resolve(strict=False)
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return {
            "ref": raw_ref,
            "current": False,
            "reason": "ref_outside_current_workspace",
            "path": raw_path,
            "line": line,
        }
    display = str(resolved.relative_to(workspace))
    if line is not None:
        display = f"{display}:{line}"
    if not resolved.is_file():
        return {
            "ref": raw_ref,
            "current": False,
            "reason": "stale_workspace_ref",
            "path": display,
            "line": line,
        }
    if line is not None and not _line_exists(resolved, line):
        return {
            "ref": raw_ref,
            "current": False,
            "reason": "stale_workspace_ref",
            "path": display,
            "line": line,
        }
    return {
        "ref": raw_ref,
        "current": True,
        "reason": "current_workspace_ref",
        "path": display,
        "line": line,
    }


def _ref_status(workspace: Path, refs: list[str], *, missing_reason: str) -> dict[str, Any]:
    resolved = [_resolve_workspace_ref(workspace, ref, missing_reason=missing_reason) for ref in refs]
    return {
        "raw_refs": refs,
        "current_refs": [item for item in resolved if item["current"]],
        "stale_refs": [item for item in resolved if not item["current"]],
        "resolved_refs": resolved,
    }


def _has_advisory_payload(payloads: list[dict[str, Any]]) -> bool:
    for payload in payloads:
        if _truthy(payload.get("advisory_only")) or _truthy(payload.get("advisory")):
            return True
        for key in (*TOPOLOGY_EVIDENCE_KEYS, *PROOF_COMMAND_KEYS, *PROOF_EVIDENCE_KEYS, *PROOF_PATH_KEYS):
            value = payload.get(key)
            if isinstance(value, dict) and (_truthy(value.get("advisory_only")) or _truthy(value.get("advisory"))):
                return True
            if isinstance(value, str) and "advisory only" in value.lower():
                return True
    return False


def _blocker_values(payloads: list[dict[str, Any]]) -> list[str]:
    blockers: list[str] = []
    for payload in payloads:
        for key in BLOCKER_KEYS:
            for item in _text_values(payload.get(key)):
                if not _is_placeholder(item):
                    blockers.append(item)
    return sorted(set(blockers))


def _has_concrete_proof_command(value: str) -> bool:
    text = value.strip()
    if _is_placeholder(text):
        return False
    return not text.startswith("#")


def _proof_artifact_status(workspace: Path, raw_path: str) -> dict[str, Any]:
    text = _clean_ref(raw_path)
    match = SOURCE_REF_RE.search(text)
    path_text = match.group("path") if match else text
    path = Path(path_text).expanduser()
    try:
        resolved = path.resolve(strict=False) if path.is_absolute() else (workspace / path).resolve(strict=False)
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return {
            "ref": raw_path,
            "current": False,
            "reason": "proof_artifact_outside_current_workspace",
            "path": path_text,
        }
    display = str(resolved.relative_to(workspace))
    return {
        "ref": raw_path,
        "current": resolved.is_file(),
        "reason": "current_workspace_proof_artifact" if resolved.is_file() else "stale_workspace_proof_artifact",
        "path": display,
    }


def _closure_readiness(
    *,
    workspace: Path,
    payloads: list[dict[str, Any]],
    depth_closure_candidate: bool,
) -> dict[str, Any]:
    reasons: list[str] = []
    if not depth_closure_candidate:
        reasons.append("execution_pair_not_closed")

    source_refs = _collect_values(payloads, SOURCE_REF_KEYS, ref_fields_only=True)
    source_status = _ref_status(workspace, source_refs, missing_reason="missing_current_workspace_source_ref")
    if not source_refs:
        reasons.append("missing_source_refs")
    elif source_status["stale_refs"]:
        reasons.append("stale_source_refs")

    topology_refs = _collect_values(payloads, TOPOLOGY_PATH_KEYS, ref_fields_only=True)
    topology_status = _ref_status(workspace, topology_refs, missing_reason="missing_configured_topology_ref")
    topology_evidence = [
        value for value in _collect_values(payloads, TOPOLOGY_EVIDENCE_KEYS) if not _is_placeholder(value)
    ]
    if topology_status["stale_refs"]:
        reasons.append("stale_topology_evidence")
    if not topology_evidence and not topology_status["current_refs"]:
        reasons.append("missing_topology_evidence")

    proof_commands = [
        command
        for command in _collect_values(payloads, PROOF_COMMAND_KEYS)
        if _has_concrete_proof_command(command)
    ]
    proof_artifact_checks = [
        _proof_artifact_status(workspace, path_value)
        for path_value in _collect_values(payloads, PROOF_PATH_KEYS, ref_fields_only=True)
        if not _is_placeholder(path_value)
    ]
    current_proof_artifacts = [item for item in proof_artifact_checks if item["current"]]
    stale_proof_artifacts = [item for item in proof_artifact_checks if not item["current"]]
    proof_evidence = [
        value for value in _collect_values(payloads, PROOF_EVIDENCE_KEYS) if not _is_placeholder(value)
    ]
    if stale_proof_artifacts:
        reasons.append("stale_execution_proof_artifact")
    if not proof_commands and not current_proof_artifacts and not proof_evidence:
        reasons.append("missing_execution_proof")

    blocking_markers = _blocker_values(payloads)
    if blocking_markers:
        reasons.append("blocker_present")
    if _has_advisory_payload(payloads):
        reasons.append("advisory_only")

    ready = not reasons
    return {
        "closure_ready": ready,
        "closure_readiness_status": "closure_ready" if ready else "blocked_closure_readiness_inputs",
        "closure_readiness_reasons": sorted(set(reasons)),
        "current_source_refs": source_status["current_refs"],
        "source_ref_blockers": source_status["stale_refs"],
        "configured_topology_refs": topology_status["current_refs"],
        "configured_topology_ref_blockers": topology_status["stale_refs"],
        "configured_topology_evidence": topology_evidence,
        "proof_commands": proof_commands,
        "proof_evidence": proof_evidence,
        "proof_artifacts": current_proof_artifacts,
        "proof_artifact_blockers": stale_proof_artifacts,
        "blocking_markers": blocking_markers,
    }


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value.strip().strip("'").strip('"')
    return values


def _workspace_env_keys(workspace: Path) -> set[str]:
    keys: set[str] = set()
    candidates = [
        workspace / ".env",
        workspace / ".env.local",
        workspace / "env" / ".env",
        workspace / "env" / ".env.local",
    ]
    env_dir = workspace / "env"
    if env_dir.is_dir():
        candidates.extend(sorted(env_dir.glob("*.env")))
    for candidate in candidates:
        if candidate.is_file():
            keys.update(_parse_env_file(candidate))
    return keys


def _rpc_env_var(network: str) -> str:
    env_map = {
        "mainnet": "MAINNET_RPC_URL",
        "polygon": "POLYGON_RPC_URL",
        "arbitrum": "ARBITRUM_RPC_URL",
        "optimism": "OPTIMISM_RPC_URL",
        "base": "BASE_RPC_URL",
    }
    return env_map.get(network.lower(), f"{network.upper()}_RPC_URL")


def _shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def _manual_import_command(workspace: Path, row_ids: list[str]) -> str:
    parts = [
        "python3",
        "tools/live-check-runner.py",
        str(workspace),
        "--import-manual-proofs",
    ]
    for row_id in row_ids:
        parts.extend(["--manual-proof-id", row_id])
    parts.extend(["--out-json", str(workspace / "live_topology_checks.json")])
    return _shell_join(parts)


def _runner_command(workspace: Path) -> str:
    return _shell_join(
        [
            "python3",
            "tools/live-check-runner.py",
            str(workspace),
            "--spec",
            str(workspace / "monitoring" / "live_topology_proof_requirements.generated.json"),
            "--out-json",
            str(workspace / ".auditooor" / "live_topology_runner_eo.json"),
            "--out-md",
            str(workspace / ".auditooor" / "live_topology_runner_eo.md"),
        ]
    )


def _executor_command(workspace: Path) -> str:
    return _shell_join(
        [
            "python3",
            "tools/live-topology-proof-executor.py",
            "--workspace",
            str(workspace),
            "--requirements",
            str(workspace / ".auditooor" / "live_topology_proof_requirements.json"),
            "--live-topology",
            str(workspace / ".auditooor" / "live_topology_runner_eo.json"),
            "--out-json",
            str(workspace / ".auditooor" / "live_topology_proof_executor_eo_runner.json"),
            "--out-md",
            str(workspace / ".auditooor" / "live_topology_proof_executor_eo_runner.md"),
            "--demo-fixture",
        ]
    )


def _live_state_capture_command(workspace: Path, row: dict[str, Any], *, same_block_placeholder: str) -> str:
    row_id = str(row.get("id") or "").strip()
    contract = str(row.get("contract") or "UNKNOWN").strip() or "UNKNOWN"
    network = str(row.get("network") or "mainnet").strip() or "mainnet"
    pair_id = str(row.get("proof_pair_id") or row.get("pair_id") or "").strip()
    title = str(row.get("title") or row_id).strip() or row_id
    check = row.get("check") if isinstance(row.get("check"), dict) else {}
    call = str(check.get("call") or "owner()").strip()
    expect = str(check.get("expect") or "<expected-owner-or-wiring>").strip()
    address_placeholder = f"<{contract}-address>"
    parts = [
        "python3",
        "tools/live-state-checker.py",
        "--workspace",
        str(workspace),
        "--address",
        address_placeholder,
        "--network",
        network,
        "--block",
        same_block_placeholder,
        "--call",
        call,
        "--expect",
        expect,
        "--save-workspace-proof",
        row_id,
        "--contract-name",
        contract,
        "--title",
        title,
        "--evidence-class",
        "topology-relation",
    ]
    for angle_id in row.get("related_angle_ids") or []:
        text = str(angle_id).strip()
        if text:
            parts.extend(["--related-angle-id", text])
    if pair_id:
        parts.extend(["--pair-id", pair_id, "--proof-pair-id", pair_id])
    parts.extend(["--json"])
    return _shell_join(parts)


def _contract_group_items(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        contract = str(row.get("contract") or "UNKNOWN").strip() or "UNKNOWN"
        item = groups.setdefault(
            contract,
            {
                "contract": contract,
                "row_count": 0,
                "requirement_count": 0,
                "requirements": [],
                "row_ids": [],
                "networks": [],
            },
        )
        requirement_id = str(row.get("requirement_id") or "").strip()
        network = str(row.get("network") or "mainnet").strip() or "mainnet"
        item["row_count"] += 1
        if requirement_id and requirement_id not in item["requirements"]:
            item["requirements"].append(requirement_id)
            item["requirement_count"] += 1
        row_id = str(row.get("id") or "").strip()
        if row_id:
            item["row_ids"].append(row_id)
        if network not in item["networks"]:
            item["networks"].append(network)
    return sorted(groups.values(), key=lambda item: (-int(item["row_count"]), str(item["contract"])))


def _network_groups(
    rows: list[dict[str, Any]],
    *,
    workspace_env_keys: set[str],
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for row in rows:
        network = str(row.get("network") or "mainnet").strip() or "mainnet"
        env_var = _rpc_env_var(network)
        item = groups.setdefault(
            network,
            {
                "network": network,
                "row_count": 0,
                "requirements": [],
                "rpc_env_var": env_var,
                "workspace_env_present": env_var in workspace_env_keys,
                "process_env_present": bool(os.environ.get(env_var)),
                "runner_rpc_sources": [],
                "primary_blocker": "address_unresolved_before_rpc",
            },
        )
        item["row_count"] += 1
        requirement_id = str(row.get("requirement_id") or "").strip()
        if requirement_id and requirement_id not in item["requirements"]:
            item["requirements"].append(requirement_id)
        rpc_source = str(row.get("rpc_source") or "").strip()
        if rpc_source and rpc_source not in item["runner_rpc_sources"]:
            item["runner_rpc_sources"].append(rpc_source)
    return sorted(groups.values(), key=lambda item: (-int(item["row_count"]), str(item["network"])))


def _terminal_blocker_counts(requirements: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for requirement in requirements:
        for blocker in requirement.get("terminal_blockers") or []:
            family = str(blocker).split(":", 1)[0]
            if family:
                counts[family] = counts.get(family, 0) + 1
    return dict(sorted(counts.items()))


def _collect_manual_proof_row_ids(workspace: Path) -> tuple[set[str], list[Path], list[dict[str, str]]]:
    proof_dir = workspace / "manual_proofs"
    files = sorted(proof_dir.glob("*.json")) if proof_dir.is_dir() else []
    existing: set[str] = set()
    errors: list[dict[str, str]] = []
    for path in files:
        existing.add(path.stem)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        rows = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_id = str(row.get("id") or "").strip()
            if row_id:
                existing.add(row_id)
    return existing, files, errors


def _manual_proof_summary(workspace: Path, row_ids: list[str]) -> dict[str, Any]:
    proof_dir = workspace / "manual_proofs"
    existing, files, errors = _collect_manual_proof_row_ids(workspace)
    missing = [row_id for row_id in row_ids if row_id not in existing]
    return {
        "path": str(proof_dir),
        "exists": proof_dir.is_dir(),
        "files_scanned": len(files),
        "row_ids_discovered": len(existing),
        "expected_row_ids": len(row_ids),
        "missing_row_ids": len(missing),
        "present_row_ids": len(row_ids) - len(missing),
        "present_row_id_sample": sorted(existing)[:25],
        "errors": errors,
    }


def _manual_proof_row_ids(workspace: Path) -> set[str]:
    existing, _, _ = _collect_manual_proof_row_ids(workspace)
    return existing


def _local_data_summary(workspace: Path, spec: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    deployment_topology = workspace / "deployment_topology.json"
    topology_entries = 0
    if deployment_topology.is_file():
        try:
            payload = json.loads(deployment_topology.read_text(encoding="utf-8"))
            entries = payload.get("entries") if isinstance(payload, dict) else []
            topology_entries = len(entries) if isinstance(entries, list) else 0
        except (OSError, json.JSONDecodeError):
            topology_entries = 0
    checks = _list_rows(spec, "checks")
    row_ids = [str(row.get("id") or "").strip() for row in rows if str(row.get("id") or "").strip()]
    workspace_env_keys = _workspace_env_keys(workspace)
    networks = sorted({str(row.get("network") or "mainnet").strip() or "mainnet" for row in rows})
    return {
        "deployment_topology": {
            "path": str(deployment_topology),
            "exists": deployment_topology.is_file(),
            "entry_count": topology_entries,
        },
        "spec": {
            "path": str(workspace / "monitoring" / "live_topology_proof_requirements.generated.json"),
            "check_count": len(checks),
            "checks_with_explicit_address": sum(1 for check in checks if str(check.get("address") or "").strip()),
            "checks_with_explicit_block": sum(1 for check in checks if str(check.get("block") or "").strip()),
        },
        "manual_proofs": _manual_proof_summary(workspace, row_ids),
        "rpc_env": {
            network: {
                "env_var": _rpc_env_var(network),
                "workspace_env_present": _rpc_env_var(network) in workspace_env_keys,
                "process_env_present": bool(os.environ.get(_rpc_env_var(network))),
            }
            for network in networks
        },
    }


def build_closure(
    *,
    workspace: Path,
    requirements: dict[str, Any],
    canonical_live: dict[str, Any],
    runner_live: dict[str, Any],
    executor_before: dict[str, Any],
    executor_after: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any]:
    reqs = _list_rows(requirements, "requirements")
    runner_rows = _list_rows(runner_live, "results")
    runner_by_id = _index_by_id(runner_rows)
    before_by_req = _index_by_id(
        [
            {**row, "id": str(row.get("requirement_id") or "").strip()}
            for row in _list_rows(executor_before, "rows")
        ]
    )
    after_by_req = _index_by_id(
        [
            {**row, "id": str(row.get("requirement_id") or "").strip()}
            for row in _list_rows(executor_after, "rows")
        ]
    )
    workspace_env_keys = _workspace_env_keys(workspace)
    reduced_requirements: list[dict[str, Any]] = []
    requirement_blockers: list[dict[str, Any]] = []
    missing_address_rows: list[dict[str, Any]] = []
    missing_block_requirements: list[dict[str, Any]] = []
    missing_manual_rows: list[dict[str, Any]] = []
    all_runner_requirement_rows: list[dict[str, Any]] = []
    manual_proof_ids = _manual_proof_row_ids(workspace)

    for req in reqs:
        requirement_id = str(req.get("requirement_id") or "").strip()
        pair_id = str(req.get("required_proof_pair_id") or "").strip()
        required_live_rows = [row for row in req.get("required_live_rows") or [] if isinstance(row, dict)]
        row_ids = [str(row.get("id") or "").strip() for row in required_live_rows if str(row.get("id") or "").strip()]
        observed_rows = [runner_by_id.get(row_id, {}) for row_id in row_ids]
        observed_rows = [row for row in observed_rows if row]
        all_runner_requirement_rows.extend(observed_rows)
        before_status = str((before_by_req.get(requirement_id) or {}).get("status") or "").strip()
        after_row = after_by_req.get(requirement_id) or {}
        after_status = str(after_row.get("status") or "").strip()
        row_statuses = {
            row_id: str((runner_by_id.get(row_id) or {}).get("status") or "missing").strip()
            for row_id in row_ids
        }
        row_blocks = sorted(
            {
                str((runner_by_id.get(row_id) or {}).get("block") or "").strip()
                for row_id in row_ids
                if str((runner_by_id.get(row_id) or {}).get("block") or "").strip()
            }
        )
        missing_manual_ids = [row_id for row_id in row_ids if row_id not in manual_proof_ids]
        missing_rpc_env_vars = sorted(
            {
                _rpc_env_var(str((runner_by_id.get(row_id) or {}).get("network") or "mainnet"))
                for row_id in row_ids
                if not os.environ.get(_rpc_env_var(str((runner_by_id.get(row_id) or {}).get("network") or "mainnet")))
                and _rpc_env_var(str((runner_by_id.get(row_id) or {}).get("network") or "mainnet")) not in workspace_env_keys
            }
        )
        if before_status == "terminal_required_not_collected_pair" and after_status == "blocked_pair_not_exact":
            reduced_requirements.append(
                {
                    "requirement_id": requirement_id,
                    "proof_pair_id": pair_id,
                    "before_status": before_status,
                    "after_status": after_status,
                    "row_statuses": row_statuses,
                    "reduction": "skeleton_not_collected_to_executable_address_blocker",
                }
            )

        same_block_placeholder = f"<same-block-for-{requirement_id}>"
        capture_commands = [
            _live_state_capture_command(workspace, row, same_block_placeholder=same_block_placeholder)
            for row in observed_rows
        ]
        missing_contracts: list[str] = []
        for row in observed_rows:
            row_id = str(row.get("id") or "").strip()
            contract = str(row.get("contract") or "UNKNOWN").strip() or "UNKNOWN"
            network = str(row.get("network") or "mainnet").strip() or "mainnet"
            status = str(row.get("status") or "").strip()
            if status == "blocked_unresolved_address" or not row.get("address"):
                missing_contracts.append(contract)
                missing_address_rows.append(
                    {
                        "requirement_id": requirement_id,
                        "proof_pair_id": pair_id,
                        "row_id": row_id,
                        "contract": contract,
                        "network": network,
                        "requirement_role": row.get("requirement_role"),
                        "source_item_id": row.get("source_item_id"),
                        "blocked_reason": row.get("blocked_reason") or "missing resolved address",
                        "address_ref": row.get("address_ref"),
                        "candidate_address_count": len(row.get("candidate_addresses") or []),
                        "next_capture_command": _live_state_capture_command(
                            workspace,
                            row,
                            same_block_placeholder=same_block_placeholder,
                        ),
                    }
                )
            if row_id:
                if row_id not in manual_proof_ids:
                    missing_manual_rows.append(
                        {
                            "requirement_id": requirement_id,
                            "proof_pair_id": pair_id,
                            "row_id": row_id,
                            "contract": contract,
                            "manual_proof_path": str(workspace / "manual_proofs" / f"{row_id}.json"),
                            "terminal_blocker": f"manual_proof_missing:{row_id}",
                            "next_import_command": _manual_import_command(workspace, [row_id]),
                        }
                    )
        missing_same_block = str(req.get("same_block_required")).lower() == "true" and len(row_blocks) != 1
        if missing_same_block:
            missing_block_requirements.append(
                {
                    "requirement_id": requirement_id,
                    "proof_pair_id": pair_id,
                    "row_ids": row_ids,
                    "required_block": "<one shared block>",
                    "observed_blocks": row_blocks,
                    "terminal_blocker": f"same_block_unpinned:{pair_id}",
                    "next_runner_command_after_block_known": _shell_join(
                        [
                            "python3",
                            "tools/live-check-runner.py",
                            str(workspace),
                            "--spec",
                            str(workspace / "monitoring" / "live_topology_proof_requirements.generated.json"),
                            "--pin-block",
                            same_block_placeholder,
                            "--out-json",
                            str(workspace / "live_topology_checks.json"),
                        ]
                    ),
                }
            )
        terminal_blockers = [
            f"address_unresolved:{item['row_id']}:{item['contract']}"
            for item in missing_address_rows
            if item.get("requirement_id") == requirement_id
        ]
        if missing_same_block:
            terminal_blockers.append(f"same_block_unpinned:{pair_id}")
        terminal_blockers.extend(f"manual_proof_missing:{row_id}" for row_id in missing_manual_ids)
        terminal_blockers.extend(f"rpc_env_missing:{env_var}" for env_var in missing_rpc_env_vars)
        depth_closure_candidate = (
            _truthy(after_row.get("depth_closure_candidate"))
            or after_status == "closure_candidate_same_block_pair_validated"
        )
        readiness_payloads = [
            req,
            *required_live_rows,
            *observed_rows,
            after_row,
        ]
        closure_readiness = _closure_readiness(
            workspace=workspace,
            payloads=[payload for payload in readiness_payloads if isinstance(payload, dict)],
            depth_closure_candidate=depth_closure_candidate,
        )
        requirement_blockers.append(
            {
                "requirement_id": requirement_id,
                "source_item_id": req.get("source_item_id"),
                "source_component": req.get("source_component"),
                "target_component": req.get("target_component"),
                "proof_pair_id": pair_id,
                "required_contracts": req.get("required_contracts") or [],
                "required_row_ids": row_ids,
                "row_statuses": row_statuses,
                "observed_blocks": row_blocks,
                "missing_address_contracts": sorted(set(missing_contracts)),
                "missing_manual_proof_ids": missing_manual_ids,
                "missing_same_block": missing_same_block,
                "missing_private_rpc_env_vars": missing_rpc_env_vars,
                "terminal_blockers": sorted(set(terminal_blockers)),
                "depth_closure_candidate": depth_closure_candidate,
                **closure_readiness,
                "next_commands": [
                    *capture_commands,
                    _manual_import_command(workspace, missing_manual_ids or row_ids),
                    _executor_command(workspace),
                ],
            }
        )

    local_data = _local_data_summary(workspace, spec, runner_rows)
    hermetic_demo = executor_after.get("demo_fixture") if isinstance(executor_after.get("demo_fixture"), dict) else {}
    closure_ready_requirements = [row for row in requirement_blockers if row.get("closure_ready")]
    closure_non_ready_requirements = [row for row in requirement_blockers if not row.get("closure_ready")]
    closure_readiness_reason_counts = _reason_counts(closure_non_ready_requirements)
    depth_closure_candidate_count = int(executor_after.get("depth_closure_candidate_count") or 0)
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "requirements": str(workspace / ".auditooor" / "live_topology_proof_requirements.json"),
            "canonical_live_topology": str(workspace / "live_topology_checks.json"),
            "runner_live_topology": str(workspace / ".auditooor" / "live_topology_runner_eo.json"),
            "executor_before": str(workspace / ".auditooor" / "live_topology_proof_executor.json"),
            "executor_after": str(workspace / ".auditooor" / "live_topology_proof_executor_eo_runner.json"),
            "spec": str(workspace / "monitoring" / "live_topology_proof_requirements.generated.json"),
        },
        "before": {
            "canonical_live_status_counts": canonical_live.get("summary") or _status_counts(_list_rows(canonical_live, "results")),
            "canonical_proof_pair_summary": canonical_live.get("proof_pair_summary") or {},
            "executor_status_counts": executor_before.get("status_counts") or {},
            "executor_blocker_kind_counts": executor_before.get("blocker_kind_counts") or {},
        },
        "after": {
            "runner_live_status_counts": runner_live.get("summary") or _status_counts(runner_rows),
            "runner_proof_pair_summary": runner_live.get("proof_pair_summary") or {},
            "executor_status_counts": executor_after.get("status_counts") or {},
            "executor_blocker_kind_counts": executor_after.get("blocker_kind_counts") or {},
            "executor_blocker_reason_counts": executor_after.get("blocker_reason_counts") or {},
        },
        "closure": {
            "closed_requirement_count": len(closure_ready_requirements),
            "depth_closure_candidate_count": depth_closure_candidate_count,
            "closure_ready_requirement_count": len(closure_ready_requirements),
            "closure_non_ready_requirement_count": len(closure_non_ready_requirements),
            "reduced_requirement_count": len(reduced_requirements),
            "row_attempt_count": len(runner_rows),
            "manual_imported_rows": int((runner_live.get("manual_imports") or {}).get("imported_rows") or 0),
            "exact_same_block_pair_ids": executor_after.get("exact_same_block_pair_ids") or [],
            "reduced_requirements": reduced_requirements,
            "terminal_blocker_counts": _terminal_blocker_counts(requirement_blockers),
            "closure_readiness_reason_counts": closure_readiness_reason_counts,
        },
        "local_data": local_data,
        "groups": {
            "missing_address": {
                "row_count": len(missing_address_rows),
                "contract_count": len({item["contract"] for item in missing_address_rows}),
                "items": missing_address_rows,
            },
            "missing_rpc": {
                "network_count": len(_network_groups(all_runner_requirement_rows, workspace_env_keys=workspace_env_keys)),
                "items": _network_groups(all_runner_requirement_rows, workspace_env_keys=workspace_env_keys),
            },
            "missing_block": {
                "requirement_count": len(missing_block_requirements),
                "items": missing_block_requirements,
            },
            "missing_manual_proof_id": {
                "row_count": len(missing_manual_rows),
                "items": missing_manual_rows,
            },
            "by_contract": {
                "contract_count": len(_contract_group_items(all_runner_requirement_rows)),
                "items": _contract_group_items(all_runner_requirement_rows),
            },
            "by_requirement": {
                "requirement_count": len(requirement_blockers),
                "items": requirement_blockers,
            },
            "closure_readiness": {
                "ready_requirement_count": len(closure_ready_requirements),
                "non_ready_requirement_count": len(closure_non_ready_requirements),
                "reason_counts": closure_readiness_reason_counts,
                "ready_rows": closure_ready_requirements,
                "non_ready_rows": closure_non_ready_requirements,
            },
        },
        "commands_executed_or_replayable": [
            _runner_command(workspace),
            _executor_command(workspace),
        ],
        "hermetic_non_base_demo": {
            "present": bool(hermetic_demo),
            "fixture_kind": hermetic_demo.get("fixture_kind"),
            "depth_closure_candidate_count": hermetic_demo.get("depth_closure_candidate_count", 0),
            "status_counts": hermetic_demo.get("status_counts") or {},
            "validated_contracts": (
                ((hermetic_demo.get("rows") or [{}])[0].get("validated_contracts") or [])
                if isinstance(hermetic_demo.get("rows"), list)
                else []
            ),
        },
        "residual_blocker": (
            "No locally resolved deployment addresses, no canonical deployment_topology.json entries, "
            "no manual_proofs cache, no same-block pin, and no private RPC env were available. "
            "Rows cannot become executed same-block topology proof without those inputs."
        ),
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    before = payload["before"]
    after = payload["after"]
    closure = payload["closure"]
    groups = payload["groups"]
    local_data = payload["local_data"]
    lines = [
        "# Live Topology Execution Closure",
        "",
        "Executable closure accounting for same-block topology proof-pair rows.",
        "This artifact does not contain live proof and is not submission-ready evidence.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- reduced requirements: `{closure['reduced_requirement_count']}`",
        f"- closed requirements: `{closure['closed_requirement_count']}`",
        f"- depth closure candidates: `{closure.get('depth_closure_candidate_count', 0)}`",
        f"- closure non-ready requirements: `{closure.get('closure_non_ready_requirement_count', 0)}`",
        f"- row attempts: `{closure['row_attempt_count']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Before / After",
        "",
        f"- canonical live statuses before: `{json.dumps(before['canonical_live_status_counts'], sort_keys=True)}`",
        f"- executor statuses before: `{json.dumps(before['executor_status_counts'], sort_keys=True)}`",
        f"- runner live statuses after execution attempt: `{json.dumps(after['runner_live_status_counts'], sort_keys=True)}`",
        f"- executor statuses after runner attempt: `{json.dumps(after['executor_status_counts'], sort_keys=True)}`",
        "",
        "## Local Data",
        "",
        f"- deployment topology exists: `{local_data['deployment_topology']['exists']}` entries=`{local_data['deployment_topology']['entry_count']}`",
        f"- manual proofs exists: `{local_data['manual_proofs']['exists']}` files=`{local_data['manual_proofs']['files_scanned']}` missing row ids=`{local_data['manual_proofs']['missing_row_ids']}`",
        f"- spec checks with explicit address: `{local_data['spec']['checks_with_explicit_address']}`",
        f"- spec checks with explicit block: `{local_data['spec']['checks_with_explicit_block']}`",
        "",
        "## Blocker Groups",
        "",
        f"- missing address rows: `{groups['missing_address']['row_count']}`",
        f"- missing same-block requirements: `{groups['missing_block']['requirement_count']}`",
        f"- missing manual proof row ids: `{groups['missing_manual_proof_id']['row_count']}`",
        f"- RPC prerequisite groups: `{groups['missing_rpc']['network_count']}`",
        f"- contract groups: `{groups['by_contract']['contract_count']}`",
        "",
        "## Terminal Blocker Counts",
        "",
    ]
    for blocker, count in (closure.get("terminal_blocker_counts") or {}).items():
        lines.append(f"- `{blocker}`: {count}")
    lines.extend([
        "",
        "## Closure Readiness Reasons",
        "",
    ])
    for reason, count in (closure.get("closure_readiness_reason_counts") or {}).items():
        lines.append(f"- `{reason}`: {count}")
    lines.extend([
        "",
        "## Top Contract Groups",
        "",
        "| Contract | Rows | Requirements | Networks |",
        "|---|---:|---:|---|",
    ])
    for item in groups["by_contract"]["items"][:25]:
        lines.append(
            f"| `{item['contract']}` | {item['row_count']} | {item['requirement_count']} | "
            f"`{','.join(item['networks'])}` |"
        )
    lines.extend([
        "",
        "## Replay Commands",
        "",
    ])
    for command in payload.get("commands_executed_or_replayable") or []:
        lines.append(f"- `{command}`")
    demo = payload.get("hermetic_non_base_demo") or {}
    lines.extend([
        "",
        "## Hermetic Non-Base Demo",
        "",
        f"- present: `{demo.get('present')}`",
        f"- fixture kind: `{demo.get('fixture_kind')}`",
        f"- closure candidates: `{demo.get('depth_closure_candidate_count')}`",
        f"- validated contracts: `{','.join(demo.get('validated_contracts') or [])}`",
        "",
        "## Residual Blocker",
        "",
        payload.get("residual_blocker", ""),
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--canonical-live", type=Path)
    parser.add_argument("--runner-live", type=Path)
    parser.add_argument("--executor-before", type=Path)
    parser.add_argument("--executor-after", type=Path)
    parser.add_argument("--spec", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-execution-closure] workspace not found: {workspace}", file=sys.stderr)
        return 2
    audit_dir = workspace / ".auditooor"
    requirements_path = args.requirements or audit_dir / "live_topology_proof_requirements.json"
    canonical_live_path = args.canonical_live or workspace / "live_topology_checks.json"
    runner_live_path = args.runner_live or audit_dir / "live_topology_runner_eo.json"
    executor_before_path = args.executor_before or audit_dir / "live_topology_proof_executor.json"
    executor_after_path = args.executor_after or audit_dir / "live_topology_proof_executor_eo_runner.json"
    spec_path = args.spec or workspace / "monitoring" / "live_topology_proof_requirements.generated.json"

    payload = build_closure(
        workspace=workspace,
        requirements=_load_json(requirements_path, "requirements"),
        canonical_live=_load_json(canonical_live_path, "canonical live topology"),
        runner_live=_load_json(runner_live_path, "runner live topology"),
        executor_before=_load_json(executor_before_path, "executor before"),
        executor_after=_load_json(executor_after_path, "executor after"),
        spec=_load_json(spec_path, "generated live check spec"),
    )

    out_json = args.out_json or audit_dir / "live_topology_execution_closure_eo.json"
    out_md = args.out_md or audit_dir / "live_topology_execution_closure_eo.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-execution-closure] OK "
        f"reduced={payload['closure']['reduced_requirement_count']} "
        f"closed={payload['closure']['closed_requirement_count']} json={out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
