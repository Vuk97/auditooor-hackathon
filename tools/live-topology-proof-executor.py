#!/usr/bin/env python3
"""Validate live-topology proof requirements against executed proof pairs.

This is the executable layer after ``live-topology-proof-requirements.py``.
It consumes the offline requirement checklist and, when a
``live_topology_checks.json`` dossier is available, validates whether each
required same-block topology proof pair is exact enough to become a
semantic/live-depth closure candidate.

It deliberately does not call RPC, prove exploit impact, assign severity, or
make any row submit-ready. Missing live topology data is a terminal local
blocker for this lane, not a prompt for operator approval.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_proof_executor.v1"
DEFAULT_LIMIT = 400
EXECUTED_STATUSES = {"pass", "fail"}
PASS_STATUSES = {"pass"}
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
    "proof_artifacts",
    "execution_evidence",
    "capture_artifact",
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
)
SOURCE_REF_RE = re.compile(
    r"(?P<path>(?:~|/|\.{1,2}/|[A-Za-z0-9_.-])"
    r"[A-Za-z0-9_./@%+,\-]*\."
    r"(?:sol|vy|go|rs|move|cairo|tsx|ts|jsx|json|js|py|md|yaml|yml|toml|txt|log))"
    r"(?:(?::|#L)(?P<line>\d+))?"
)
MISSING_TEXT = {"", "n/a", "na", "none", "null", "unknown", "todo", "tbd", "advisory", "advisory_only"}
ADVISORY_POSTURE = {
    "coverage_claim": "same_block_live_topology_requirement_validation_only",
    "advisory_only": True,
    "promotion_allowed": False,
    "severity": "none",
    "selected_impact": "",
    "submission_posture": "NOT_SUBMIT_READY",
    "impact_contract_required": True,
}


def _row_posture(*, execution_ready: bool) -> dict[str, Any]:
    posture = dict(ADVISORY_POSTURE)
    if execution_ready:
        posture["advisory_only"] = False
        posture["submission_posture"] = "EXECUTION_READY_NOT_SUBMIT_READY"
    return posture


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def _is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text.lower() in MISSING_TEXT or text.startswith("<") or text.endswith(">")


def _text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_text_values(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_text_values(item))
        return out
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _collect_values(payloads: list[dict[str, Any]], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for payload in payloads:
        for key in keys:
            values.extend(_text_values(payload.get(key)))
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


def _resolve_source_ref(workspace: Path, raw_ref: str) -> dict[str, Any]:
    text = _clean_ref(raw_ref)
    match = SOURCE_REF_RE.search(text)
    if not match:
        return {"ref": raw_ref, "current": False, "reason": "missing_current_workspace_source_ref"}
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
            "reason": "source_ref_outside_current_workspace",
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
            "reason": "stale_workspace_source_ref",
            "path": display,
            "line": line,
        }
    if line is not None and not _line_exists(resolved, line):
        return {
            "ref": raw_ref,
            "current": False,
            "reason": "stale_workspace_source_ref",
            "path": display,
            "line": line,
        }
    return {
        "ref": raw_ref,
        "current": True,
        "reason": "current_workspace_source_ref",
        "path": display,
        "line": line,
    }


def _source_ref_status(workspace: Path, refs: list[str]) -> dict[str, Any]:
    resolved = [_resolve_source_ref(workspace, ref) for ref in refs]
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
    if text.startswith("#"):
        return False
    return True


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


def _required_live_rows(requirement: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in requirement.get("required_live_rows") or [] if isinstance(row, dict)]


def _strict_execution_evidence(
    *,
    workspace: Path,
    payloads: list[dict[str, Any]],
    pair_blockers: list[str],
) -> dict[str, Any]:
    reasons: list[str] = []
    source_refs = _collect_values(payloads, SOURCE_REF_KEYS)
    source_status = _source_ref_status(workspace, source_refs)
    if not source_refs:
        reasons.append("missing_current_workspace_source_refs")
    elif source_status["stale_refs"]:
        reasons.append("stale_workspace_source_refs")

    topology_refs = _collect_values(payloads, TOPOLOGY_PATH_KEYS)
    topology_status = _source_ref_status(workspace, topology_refs)
    topology_evidence = [
        value for value in _collect_values(payloads, TOPOLOGY_EVIDENCE_KEYS) if not _is_placeholder(value)
    ]
    if topology_status["stale_refs"]:
        reasons.append("stale_configured_topology_evidence")
    if not topology_evidence and not topology_status["current_refs"]:
        reasons.append("missing_configured_topology_evidence")

    proof_commands = [
        command for command in _collect_values(payloads, PROOF_COMMAND_KEYS) if _has_concrete_proof_command(command)
    ]
    proof_artifact_checks = [
        _proof_artifact_status(workspace, path_value)
        for path_value in _collect_values(payloads, PROOF_PATH_KEYS)
        if not _is_placeholder(path_value)
    ]
    current_proof_artifacts = [item for item in proof_artifact_checks if item["current"]]
    stale_proof_artifacts = [item for item in proof_artifact_checks if not item["current"]]
    if not proof_commands and not current_proof_artifacts:
        reasons.append("missing_concrete_proof_command_or_artifact")

    blocking_markers = _blocker_values(payloads)
    if blocking_markers:
        reasons.append("proof_blockers_present")
    if _has_advisory_payload(payloads):
        reasons.append("advisory_only_evidence")
    if pair_blockers:
        reasons.append("pair_validation_blockers_present")

    return {
        "execution_ready": not reasons,
        "execution_readiness_reasons": sorted(set(reasons)),
        "source_refs": source_status["current_refs"],
        "source_ref_blockers": source_status["stale_refs"],
        "configured_topology_refs": topology_status["current_refs"],
        "configured_topology_ref_blockers": topology_status["stale_refs"],
        "configured_topology_evidence": topology_evidence,
        "proof_commands": proof_commands,
        "proof_artifacts": current_proof_artifacts,
        "proof_artifact_blockers": stale_proof_artifacts,
        "blocking_markers": blocking_markers,
        "pair_validation_blockers": sorted(set(pair_blockers)),
    }


def _load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[live-topology-proof-executor] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-proof-executor] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-proof-executor] expected object JSON for {label}: {path}")
    return payload


def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _row_ids(pair: dict[str, Any]) -> list[str]:
    return [str(row_id).strip() for row_id in pair.get("row_ids") or [] if str(row_id).strip()]


def _pair_blocks(pair: dict[str, Any], row_ids: list[str], rows_by_id: dict[str, dict[str, Any]]) -> list[str]:
    blocks = {
        str((rows_by_id.get(row_id) or {}).get("block") or "").strip()
        for row_id in row_ids
        if str((rows_by_id.get(row_id) or {}).get("block") or "").strip()
    }
    for block in pair.get("pair_blocks") or []:
        if str(block).strip():
            blocks.add(str(block).strip())
    shared = str(pair.get("shared_block") or "").strip()
    if shared:
        blocks.add(shared)
    return sorted(blocks)


def _row_blocks(row_ids: list[str], rows_by_id: dict[str, dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str((rows_by_id.get(row_id) or {}).get("block") or "").strip()
            for row_id in row_ids
            if str((rows_by_id.get(row_id) or {}).get("block") or "").strip()
        }
    )


def _contracts(row_ids: list[str], rows_by_id: dict[str, dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    contracts: list[str] = []
    for row_id in row_ids:
        contract = str((rows_by_id.get(row_id) or {}).get("contract") or "").strip()
        key = contract.lower()
        if contract and key not in seen:
            seen.add(key)
            contracts.append(contract)
    return contracts


def _is_not_collected_pair(
    *,
    pair: dict[str, Any] | None,
    row_ids: list[str],
    row_statuses: dict[str, str],
) -> bool:
    if not pair or not row_ids:
        return False
    pair_status = str(pair.get("status") or "").strip()
    return pair_status == "required_not_collected" and all(
        row_statuses.get(row_id) == "required_not_collected" for row_id in row_ids
    )


def _next_commands(
    *,
    workspace: Path,
    requirement_id: str,
    pair_id: str,
    row_ids: list[str],
) -> list[str]:
    row_args = " ".join(f"--manual-proof-id {row_id}" for row_id in row_ids)
    return [
        f"python3 tools/live-check-runner.py {workspace} --spec {workspace / 'monitoring' / 'live_topology_proof_requirements.generated.json'} --out-json {workspace / 'live_topology_checks.json'}",
        (
            f"python3 tools/live-check-runner.py {workspace} --import-manual-proofs {row_args} "
            f"--out-json {workspace / 'live_topology_checks.json'}"
        ),
        (
            "python3 tools/live-topology-proof-executor.py "
            f"--workspace {workspace} --requirements {workspace / '.auditooor' / 'live_topology_proof_requirements.json'} "
            f"--live-topology {workspace / 'live_topology_checks.json'}"
        ),
        (
            f"# Requirement {requirement_id}: collect two executed topology-relation rows for "
            f"{pair_id} at one shared block before expecting closure."
        ),
    ]


def _verify_requirement(
    requirement: dict[str, Any],
    *,
    workspace: Path,
    rows_by_id: dict[str, dict[str, Any]],
    pairs_by_id: dict[str, dict[str, Any]],
    live_available: bool,
) -> dict[str, Any]:
    requirement_id = str(requirement.get("requirement_id") or "")
    pair_id = str(requirement.get("required_proof_pair_id") or "").strip()
    required_contracts = [
        str(contract).strip()
        for contract in requirement.get("required_contracts") or []
        if str(contract).strip()
    ]
    required_row_ids = [
        str(row.get("id") or "").strip()
        for row in requirement.get("required_live_rows") or []
        if isinstance(row, dict) and str(row.get("id") or "").strip()
    ]
    blockers: list[str] = []

    if not live_available:
        blockers.append("live_topology_checks.json absent; requirement remains terminal NOT_SUBMIT_READY")
        strict_execution = _strict_execution_evidence(
            workspace=workspace,
            payloads=[requirement, *_required_live_rows(requirement)],
            pair_blockers=["missing_live_topology_artifact"],
        )
        return {
            "requirement_id": requirement_id,
            "status": "terminal_missing_live_topology_checks",
            "task_type": "collect_live_topology_proof_pair",
            "required_proof_pair_id": pair_id,
            "required_contracts": required_contracts,
            "required_live_row_ids": required_row_ids,
            "validated_row_ids": [],
            "validated_contracts": [],
            "validated_blocks": [],
            "depth_closure_candidate": False,
            "closure_scope": "semantic_live_topology_depth_only",
            "blockers": blockers,
            "blocker_kind": "missing_live_topology_artifact",
            "execution_readiness_status": "blocked_execution_readiness_inputs",
            **strict_execution,
            "exact_next_commands": _next_commands(
                workspace=workspace,
                requirement_id=requirement_id,
                pair_id=pair_id,
                row_ids=required_row_ids,
            ),
            "next_command": "python3 tools/engage.py --workspace <workspace> --stage live-checks",
            **_row_posture(execution_ready=False),
        }

    pair = pairs_by_id.get(pair_id)
    if not pair:
        blockers.append("required proof pair missing from live_topology_checks.json")
        row_ids: list[str] = []
    else:
        row_ids = _row_ids(pair)

    missing_rows = [row_id for row_id in row_ids if row_id not in rows_by_id]
    row_statuses = {
        row_id: str((rows_by_id.get(row_id) or {}).get("status") or "").strip()
        for row_id in row_ids
    }
    evidence_classes = {
        row_id: str((rows_by_id.get(row_id) or {}).get("evidence_class") or "").strip()
        for row_id in row_ids
    }
    proof_pair_ids = {
        row_id: str((rows_by_id.get(row_id) or {}).get("proof_pair_id") or "").strip()
        for row_id in row_ids
    }
    executed_row_ids = [
        row_id for row_id, status in row_statuses.items() if status in EXECUTED_STATUSES
    ]
    passing_row_ids = [
        row_id for row_id, status in row_statuses.items() if status in PASS_STATUSES
    ]
    failing_row_ids = [
        row_id for row_id, status in row_statuses.items() if status == "fail"
    ]
    unpinned_executed_row_ids = [
        row_id
        for row_id in executed_row_ids
        if not str((rows_by_id.get(row_id) or {}).get("block") or "").strip()
    ]
    contracts = _contracts(row_ids, rows_by_id)
    contract_lc = {contract.lower() for contract in contracts}
    row_blocks = _row_blocks(row_ids, rows_by_id)
    pair_blocks = _pair_blocks(pair or {}, row_ids, rows_by_id)

    if pair and str(pair.get("status") or "").strip() != "proved":
        blockers.append("proof pair status is not proved")
    if missing_rows:
        blockers.append("proof pair references missing row ids: " + ",".join(missing_rows))
    if len(row_ids) < 2:
        blockers.append("proof pair has fewer than two rows")
    if len(executed_row_ids) < 2:
        blockers.append("proof pair has fewer than two executed rows")
    if len(passing_row_ids) < 2:
        blockers.append("proof pair has fewer than two passing rows")
    if failing_row_ids:
        blockers.append("proof pair has failing rows: " + ",".join(sorted(failing_row_ids)))
    if unpinned_executed_row_ids:
        blockers.append("executed proof pair rows are missing block pins: " + ",".join(sorted(unpinned_executed_row_ids)))
    if any(evidence != "topology-relation" for evidence in evidence_classes.values()):
        blockers.append("proof pair rows are not all topology-relation evidence")
    if any(linked_pair_id != pair_id for linked_pair_id in proof_pair_ids.values()):
        blockers.append("proof pair rows do not all preserve required proof_pair_id")
    if len(row_blocks) != 1:
        blockers.append("proof pair is not pinned to one shared block")
    for contract in required_contracts:
        if contract.lower() not in contract_lc:
            blockers.append(f"required contract not covered by pair: {contract}")
    for row_id in required_row_ids:
        if row_id not in row_ids:
            blockers.append(f"required live row missing from pair: {row_id}")

    exact = not blockers
    not_collected = _is_not_collected_pair(pair=pair, row_ids=row_ids, row_statuses=row_statuses)
    status = "closure_candidate_same_block_pair_validated" if exact else "blocked_pair_not_exact"
    task_type = "record_depth_closure_candidate" if exact else "repair_live_topology_proof_pair"
    blocker_kind = "pair_not_exact"
    if not_collected and not exact:
        status = "terminal_required_not_collected_pair"
        task_type = "collect_required_live_topology_pair"
        blocker_kind = "required_not_collected_pair"
    strict_payloads = [
        requirement,
        *_required_live_rows(requirement),
        *[rows_by_id.get(row_id) or {} for row_id in row_ids],
    ]
    if pair:
        strict_payloads.append(pair)
    strict_execution = _strict_execution_evidence(
        workspace=workspace,
        payloads=[payload for payload in strict_payloads if isinstance(payload, dict)],
        pair_blockers=sorted(set(blockers)),
    )
    execution_ready = bool(strict_execution["execution_ready"])
    return {
        "requirement_id": requirement_id,
        "status": status,
        "task_type": task_type,
        "required_proof_pair_id": pair_id,
        "required_contracts": required_contracts,
        "required_live_row_ids": required_row_ids,
        "validated_row_ids": row_ids,
        "validated_contracts": contracts,
        "validated_blocks": row_blocks,
        "pair_declared_blocks": pair_blocks,
        "row_statuses": row_statuses,
        "executed_row_ids": executed_row_ids,
        "passing_row_ids": passing_row_ids,
        "failing_row_ids": failing_row_ids,
        "unpinned_executed_row_ids": unpinned_executed_row_ids,
        "evidence_classes": evidence_classes,
        "row_proof_pair_ids": proof_pair_ids,
        "depth_closure_candidate": exact,
        "closure_scope": "semantic_live_topology_depth_only",
        "blockers": sorted(set(blockers)),
        "blocker_kind": "" if exact else blocker_kind,
        "execution_readiness_status": (
            "execution_ready" if execution_ready else "blocked_execution_readiness_inputs"
        ),
        **strict_execution,
        "exact_next_commands": [] if exact else _next_commands(
            workspace=workspace,
            requirement_id=requirement_id,
            pair_id=pair_id,
            row_ids=required_row_ids or row_ids,
        ),
        "next_command": (
            "cite this executor row as depth-accounting validation only; keep impact gates separate"
            if exact
            else "repair/import two executed topology-relation rows at one shared block with the required proof_pair_id"
        ),
        **_row_posture(execution_ready=execution_ready),
    }


def _demo_payload() -> dict[str, Any]:
    pair_id = "LTPR-DEMO-001-pair"
    return {
        "requirements": [
            {
                "requirement_id": "LTPR-DEMO-001",
                "required_proof_pair_id": pair_id,
                "required_contracts": ["HermeticPortal", "HermeticBridge"],
                "required_live_rows": [
                    {"id": "LTPR-DEMO-001-edge", "contract": "HermeticPortal"},
                    {"id": "LTPR-DEMO-001-authority", "contract": "HermeticBridge"},
                ],
                **ADVISORY_POSTURE,
            }
        ],
        "live": {
            "results": [
                {
                    "id": "LTPR-DEMO-001-edge",
                    "status": "pass",
                    "contract": "HermeticPortal",
                    "evidence_class": "topology-relation",
                    "block": "424242",
                    "proof_pair_id": pair_id,
                },
                {
                    "id": "LTPR-DEMO-001-authority",
                    "status": "pass",
                    "contract": "HermeticBridge",
                    "evidence_class": "topology-relation",
                    "block": "424242",
                    "proof_pair_id": pair_id,
                },
            ],
            "proof_pairs": [
                {
                    "id": pair_id,
                    "status": "proved",
                    "row_ids": ["LTPR-DEMO-001-edge", "LTPR-DEMO-001-authority"],
                    "shared_block": "424242",
                    "pair_blocks": ["424242"],
                }
            ],
        },
    }


def build_execution(
    workspace: Path,
    requirements_payload: dict[str, Any],
    live: dict[str, Any],
    *,
    limit: int,
    live_available: bool,
    demo_fixture: bool,
) -> dict[str, Any]:
    rows = [row for row in live.get("results") or [] if isinstance(row, dict)]
    pairs = [pair for pair in live.get("proof_pairs") or [] if isinstance(pair, dict)]
    rows_by_id = {str(row.get("id") or "").strip(): row for row in rows if str(row.get("id") or "").strip()}
    pairs_by_id = {str(pair.get("id") or "").strip(): pair for pair in pairs if str(pair.get("id") or "").strip()}
    requirements = [
        row
        for row in requirements_payload.get("requirements") or []
        if isinstance(row, dict)
    ][: max(0, limit)]
    executed = [
        _verify_requirement(
            requirement,
            workspace=workspace,
            rows_by_id=rows_by_id,
            pairs_by_id=pairs_by_id,
            live_available=live_available,
        )
        for requirement in requirements
    ]
    closure_rows = [row for row in executed if row.get("depth_closure_candidate")]
    execution_ready_rows = [row for row in executed if row.get("execution_ready")]
    blocker_kind_counts = _status_counts([
        {"status": row.get("blocker_kind") or "none"} for row in executed if not row.get("depth_closure_candidate")
    ])
    blocker_reason_counts: dict[str, int] = {}
    execution_readiness_reason_counts: dict[str, int] = {}
    for row in executed:
        for blocker in row.get("blockers") or []:
            blocker_reason_counts[str(blocker)] = blocker_reason_counts.get(str(blocker), 0) + 1
        for reason in row.get("execution_readiness_reasons") or []:
            text = str(reason)
            execution_readiness_reason_counts[text] = execution_readiness_reason_counts.get(text, 0) + 1
    demo_result: dict[str, Any] = {}
    if demo_fixture:
        demo = _demo_payload()
        demo_execution = build_execution(
            workspace,
            {"requirements": demo["requirements"]},
            demo["live"],
            limit=1,
            live_available=True,
            demo_fixture=False,
        )
        demo_result = {
            "fixture_kind": "hermetic_non_base_same_block_pair",
            "source": "generated_inline_fixture",
            "depth_closure_candidate_count": demo_execution["depth_closure_candidate_count"],
            "status_counts": demo_execution["status_counts"],
            "rows": demo_execution["rows"],
            "live_topology_checks": demo["live"],
        }
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "source_requirements_artifact": str(workspace / ".auditooor" / "live_topology_proof_requirements.json"),
        "source_live_topology_artifact": str(workspace / "live_topology_checks.json"),
        "limit": limit,
        "live_topology_available": live_available,
        "requirement_count": len(requirements),
        "processed_count": len(executed),
        "proof_pair_count": len(pairs),
        "depth_closure_candidate_count": len(closure_rows),
        "execution_ready_count": len(execution_ready_rows),
        "blocking_count": len(executed) - len(closure_rows),
        "execution_non_ready_count": len(executed) - len(execution_ready_rows),
        "exact_same_block_pair_ids": sorted(
            {
                str(row.get("required_proof_pair_id") or "")
                for row in closure_rows
                if str(row.get("required_proof_pair_id") or "").strip()
            }
        ),
        "status_counts": _status_counts(executed),
        "blocker_kind_counts": blocker_kind_counts,
        "blocker_reason_counts": dict(sorted(blocker_reason_counts.items())),
        "execution_readiness_reason_counts": dict(sorted(execution_readiness_reason_counts.items())),
        "rows": executed,
        "demo_fixture": demo_result,
        "next_actions": [
            "Import or execute live topology rows preserving the required proof_pair_id and one shared block.",
            "Use closure candidates only for semantic/live topology depth accounting.",
            "Keep every row NOT_SUBMIT_READY until exact impact, production path, and execution proof gates pass separately.",
        ],
        **ADVISORY_POSTURE,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Live Topology Proof Executor",
        "",
        "Requirement-level validation for same-block topology proof pairs.",
        "Closure candidates here are depth-accounting only and are not exploit proof.",
        "",
        f"- schema: `{payload['schema']}`",
        f"- live topology available: `{payload['live_topology_available']}`",
        f"- processed requirements: {payload['processed_count']}",
        f"- depth closure candidates: {payload['depth_closure_candidate_count']}",
        f"- execution ready rows: {payload['execution_ready_count']}",
        f"- blocking rows: {payload['blocking_count']}",
        f"- execution non-ready rows: {payload['execution_non_ready_count']}",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Status Counts",
        "",
    ]
    for status, count in sorted((payload.get("status_counts") or {}).items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend([
        "",
        "## Blocker Kinds",
        "",
    ])
    for status, count in sorted((payload.get("blocker_kind_counts") or {}).items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend([
        "",
        "## Blocker Reasons",
        "",
    ])
    for reason, count in sorted((payload.get("blocker_reason_counts") or {}).items()):
        lines.append(f"- `{reason}`: {count}")
    lines.extend([
        "",
        "## Execution Readiness Reasons",
        "",
    ])
    for reason, count in sorted((payload.get("execution_readiness_reason_counts") or {}).items()):
        lines.append(f"- `{reason}`: {count}")
    demo = payload.get("demo_fixture") if isinstance(payload.get("demo_fixture"), dict) else {}
    if demo:
        lines.extend([
            "",
            "## Hermetic Demo",
            "",
            f"- fixture kind: `{demo.get('fixture_kind', '')}`",
            f"- depth closure candidates: {demo.get('depth_closure_candidate_count', 0)}",
        ])
    lines.extend([
        "",
        "## Rows",
        "",
        "| Requirement | Status | Execution Ready | Execution Reasons | Blocker Kind | Pair | Contracts | Blocks | Blockers |",
        "|---|---|---|---|---|---|---|---|---|",
    ])
    for row in payload.get("rows", []):
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
            row.get("requirement_id", ""),
            row.get("status", ""),
            row.get("execution_ready", False),
            ",".join(row.get("execution_readiness_reasons") or []),
            row.get("blocker_kind", ""),
            row.get("required_proof_pair_id", ""),
            ",".join(row.get("validated_contracts") or row.get("required_contracts") or []),
            ",".join(row.get("validated_blocks") or []),
            "; ".join(row.get("blockers") or []),
        ))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--live-topology", type=Path)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--demo-fixture", action="store_true")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-proof-executor] workspace not found: {workspace}", file=sys.stderr)
        return 2
    audit_dir = workspace / ".auditooor"
    requirements = _load_json(
        (args.requirements or audit_dir / "live_topology_proof_requirements.json").expanduser().resolve(),
        "live topology proof requirements",
    )
    live_path = (args.live_topology or workspace / "live_topology_checks.json").expanduser().resolve()
    live_available = live_path.is_file()
    live = _load_json(live_path, "live topology", required=False)
    payload = build_execution(
        workspace,
        requirements,
        live,
        limit=max(0, args.limit),
        live_available=live_available,
        demo_fixture=args.demo_fixture,
    )
    out_json = args.out_json or audit_dir / "live_topology_proof_executor.json"
    out_md = args.out_md or audit_dir / "live_topology_proof_executor.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-proof-executor] OK "
        f"processed={payload['processed_count']} closure_candidates={payload['depth_closure_candidate_count']} "
        f"json={out_json}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
