#!/usr/bin/env python3
"""Adjudicate FJ addressable live-topology pairs without fabricating proof.

FJ's ``addressable_candidate`` bucket is intentionally conservative: a pair can
land there when at least one row has a candidate address, but that does not mean
the same-block proof can be executed. This tool turns that bucket into exact
follow-up states by checking for concrete addresses, RPC availability, block
pins, expected values, and imported manual proofs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_addressable_followup.v1"
DEFAULT_FJ_GROUP = ".auditooor/live_topology_manual_proof_command_groups_fj/addressable_candidate.json"
DEFAULT_EW_RESOLUTION = ".auditooor/live_topology_address_resolution_ew.json"
DEFAULT_DEPLOYMENT_TOPOLOGY = ".auditooor/deployment_topology_ew_unresolved.json"
DEFAULT_TEMPLATE_DIR = ".auditooor/live_topology_manual_proof_templates_fd"
DEFAULT_OUT_JSON = ".auditooor/live_topology_addressable_followup.json"
DEFAULT_OUT_MD = ".auditooor/live_topology_addressable_followup.md"
DEFAULT_REQUIREMENT_DIR = ".auditooor/live_topology_addressable_pair_requirements"
SOURCE_REF_KEYS = (
    "source_refs",
    "source_ref",
    "file_line",
    "file_lines",
    "target_file",
    "source_file",
    "source_path",
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
    "configuration_precondition",
    "configuration_evidence",
)
PROOF_EVIDENCE_KEYS = (
    "proof_evidence",
    "harness_evidence",
    "execution_contract",
    "execution_manifest",
    "pass_evidence_lines",
    "test_transcript",
    "proof_transcript",
)
PROOF_PATH_KEYS = (
    "proof_file",
    "proof_artifact_path",
    "poc_path",
    "test_path",
    "generated_test_path",
    "harness_path",
    "execution_manifest_path",
)
PROOF_READY_BOOL_KEYS = (
    "proof_ready",
    "execution_proof_ready",
    "same_block_executor_ready",
    "same_block_executor_ready_now",
    "closure_candidate",
)
PROOF_READY_STATUS_KEYS = (
    "proof_status",
    "proof_verdict",
    "readiness_status",
    "finalization_verdict",
)
PROOF_READY_STATUS_VALUES = {
    "confirmed",
    "execution_proof_ready",
    "finalized",
    "pass",
    "passed",
    "proof-ready",
    "proof_ready",
    "proof-backed",
    "proof_backed",
    "proved",
    "same_block_executor_ready",
}
BLOCKER_KEYS = (
    "blocker",
    "blocker_class",
    "blockers",
    "blocking_reasons",
    "blocking_state",
    "promotion_blockers",
    "workability_blockers",
)
MISSING_TEXT = {"", "n/a", "na", "none", "null", "unknown", "todo", "tbd", "advisory", "advisory_only"}
PASS_EVIDENCE_PATTERNS = (
    "suite result: ok",
    "--- pass:",
    "poc pass",
    "poc_pass",
    "proof-backed",
    "proof_backed",
    "run-backed",
    "run_backed",
    "runnable_harness",
    "forge test",
)
SOURCE_REF_RE = re.compile(
    r"(?P<path>(?:~|/|\.{1,2}/|[A-Za-z0-9_.-])"
    r"[A-Za-z0-9_./@%+,\-]*\."
    r"(?:json|yaml|toml|sol|move|cairo|tsx|jsx|yml|vy|go|rs|ts|js|py|md))"
    r"(?:(?::|#L)(?P<line>\d+))?"
)


ADVISORY_POSTURE = {
    "advisory_only": True,
    "promotion_allowed": False,
    "submission_posture": "NOT_SUBMIT_READY",
    "severity": "none",
    "selected_impact": "",
    "impact_contract_required": True,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def workspace_path(workspace: Path, path: Path | None, default: str) -> Path:
    candidate = path or Path(default)
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[live-topology-addressable-followup] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-addressable-followup] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-addressable-followup] expected object JSON for {label}: {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rpc_env_var(network: str) -> str:
    return {
        "mainnet": "MAINNET_RPC_URL",
        "polygon": "POLYGON_RPC_URL",
        "arbitrum": "ARBITRUM_RPC_URL",
        "optimism": "OPTIMISM_RPC_URL",
        "base": "BASE_RPC_URL",
    }.get(network.lower(), f"{network.upper()}_RPC_URL")


def parse_env_file(path: Path) -> dict[str, str]:
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


def workspace_env(workspace: Path) -> dict[str, str]:
    values: dict[str, str] = {}
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
            values.update(parse_env_file(candidate))
    return values


def row_id(row: dict[str, Any]) -> str:
    return str(row.get("row_id") or row.get("id") or "").strip()


def manual_proof_row_ids(workspace: Path) -> set[str]:
    proof_dir = workspace / "manual_proofs"
    if not proof_dir.is_dir():
        return set()
    discovered: set[str] = set()
    for path in sorted(proof_dir.glob("*.json")):
        discovered.add(path.stem)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            continue
        for raw in rows:
            if isinstance(raw, dict):
                rid = str(raw.get("id") or "").strip()
                if rid:
                    discovered.add(rid)
    return discovered


def template_index(template_dir: Path) -> dict[str, dict[str, Any]]:
    templates: dict[str, dict[str, Any]] = {}
    if not template_dir.is_dir():
        return templates
    for path in sorted(template_dir.glob("*.json")):
        payload = load_json(path, f"template {path.name}", required=False)
        if payload:
            templates[path.stem] = payload
    return templates


def deployment_candidate_index(payload: dict[str, Any]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for entry in payload.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        contract = str(entry.get("contract") or "").strip()
        if not contract:
            continue
        candidates = entry.get("candidate_addresses") or []
        if not isinstance(candidates, list):
            candidates = []
        resolved = str(entry.get("resolved_address") or "").strip()
        values = []
        if resolved:
            values.append(resolved)
        values.extend(str(item).strip() for item in candidates if str(item).strip())
        if values:
            index[contract] = sorted(set(values))
    return index


def is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text.startswith("<") or text.endswith(">")


def truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(text_values(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(text_values(item))
        return out
    if value is None:
        return []
    return [str(value).strip()] if str(value).strip() else []


def collect_values(payloads: list[dict[str, Any]], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for payload in payloads:
        for key in keys:
            values.extend(text_values(payload.get(key)))
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = value.strip()
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out


def clean_ref(value: str) -> str:
    text = value.strip().strip("`'\"()[]{}<>,.;")
    if text.startswith("workspace:"):
        text = text[len("workspace:") :]
    return text.strip()


def line_exists(path: Path, line_no: int) -> bool:
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


def resolve_workspace_ref(workspace: Path, raw_ref: str) -> dict[str, Any]:
    text = clean_ref(raw_ref)
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
    if line is not None and not line_exists(resolved, line):
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


def source_ref_status(workspace: Path, refs: list[str]) -> dict[str, Any]:
    resolved = [resolve_workspace_ref(workspace, ref) for ref in refs]
    return {
        "raw_refs": refs,
        "current_refs": [item for item in resolved if item["current"]],
        "stale_refs": [item for item in resolved if not item["current"]],
        "resolved_refs": resolved,
    }


def proof_path_exists(workspace: Path, value: str) -> bool:
    text = clean_ref(value)
    match = SOURCE_REF_RE.search(text)
    path_text = match.group("path") if match else text
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = workspace / path
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(workspace)
    except (OSError, ValueError):
        return False
    return resolved.is_file()


def value_has_concrete_proof(value: Any, workspace: Path) -> bool:
    if isinstance(value, dict):
        if truthy(value.get("advisory_only")) or truthy(value.get("advisory")):
            return False
        if truthy(value.get("runnable")) and str(value.get("claim") or "").strip() != "blocked_harness":
            return True
        if truthy(value.get("ran")) and any(
            truthy(value.get(key)) for key in ("pass", "passed", "ok", "exploit_pass", "control_pass")
        ):
            return True
        status = str(value.get("status") or value.get("verdict") or "").strip().lower()
        if status in {"pass", "passed", "ok", "proved", "proof-backed", "proof_backed"}:
            return True
        return any(value_has_concrete_proof(item, workspace) for item in value.values())
    if isinstance(value, list):
        return any(value_has_concrete_proof(item, workspace) for item in value)
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or text.lower() in MISSING_TEXT:
        return False
    if any(pattern in text.lower() for pattern in PASS_EVIDENCE_PATTERNS):
        return True
    return proof_path_exists(workspace, text)


def concrete_proof_evidence(payloads: list[dict[str, Any]], workspace: Path) -> dict[str, Any]:
    evidence_values: list[str] = []
    proof_paths: list[str] = []
    for payload in payloads:
        for key in PROOF_EVIDENCE_KEYS:
            if value_has_concrete_proof(payload.get(key), workspace):
                evidence_values.extend(text_values(payload.get(key)))
        for path_value in collect_values([payload], PROOF_PATH_KEYS):
            if proof_path_exists(workspace, path_value):
                proof_paths.append(path_value)
    return {
        "present": bool(evidence_values or proof_paths),
        "evidence_values": sorted(set(evidence_values)),
        "proof_paths": sorted(set(proof_paths)),
    }


def advisory_markers(payloads: list[dict[str, Any]]) -> list[str]:
    markers: list[str] = []
    for payload in payloads:
        if truthy(payload.get("advisory_only")):
            markers.append("advisory_only")
        if truthy(payload.get("advisory")):
            markers.append("advisory")
        for key in (*PROOF_EVIDENCE_KEYS, *TOPOLOGY_EVIDENCE_KEYS):
            value = payload.get(key)
            if isinstance(value, dict) and (truthy(value.get("advisory_only")) or truthy(value.get("advisory"))):
                markers.append(key)
    return sorted(set(markers))


def blocker_markers(payloads: list[dict[str, Any]]) -> list[str]:
    markers: list[str] = []
    for payload in payloads:
        for key in BLOCKER_KEYS:
            for value in text_values(payload.get(key)):
                value = value.strip()
                if value and value.lower() not in MISSING_TEXT and value.lower() != "none":
                    markers.append(f"{key}:{value}")
    return sorted(set(markers))


def proof_ready_claimed(payloads: list[dict[str, Any]]) -> bool:
    for payload in payloads:
        if any(truthy(payload.get(key)) for key in PROOF_READY_BOOL_KEYS):
            return True
        for key in PROOF_READY_STATUS_KEYS:
            if str(payload.get(key) or "").strip().lower() in PROOF_READY_STATUS_VALUES:
                return True
    return False


def topology_dependency_present(payloads: list[dict[str, Any]]) -> bool:
    if collect_values(payloads, TOPOLOGY_PATH_KEYS) or collect_values(payloads, TOPOLOGY_EVIDENCE_KEYS):
        return True
    for payload in payloads:
        if truthy(payload.get("topology_required")) or truthy(payload.get("configured_topology_required")):
            return True
        for key in ("relation_kind", "evidence_class", "expect", "expected_value", "mechanism", "description"):
            for value in text_values(payload.get(key)):
                lowered = value.lower()
                if "topology" in lowered or "configured" in lowered or "deployment" in lowered:
                    return True
    return False


def row_followup_readiness(workspace: Path, payloads: list[dict[str, Any]]) -> dict[str, Any]:
    source_refs = collect_values(payloads, SOURCE_REF_KEYS)
    source_status = source_ref_status(workspace, source_refs)
    topology_paths = collect_values(payloads, TOPOLOGY_PATH_KEYS)
    topology_status = source_ref_status(workspace, topology_paths)
    topology_evidence = [
        value
        for value in collect_values(payloads, TOPOLOGY_EVIDENCE_KEYS)
        if value.strip().lower() not in MISSING_TEXT and not is_placeholder(value)
    ]
    proof_claim = proof_ready_claimed(payloads)
    proof_evidence = concrete_proof_evidence(payloads, workspace)
    blockers = blocker_markers(payloads)
    advisory = advisory_markers(payloads)
    topology_required = topology_dependency_present(payloads)
    reasons: list[str] = []
    if not source_refs:
        reasons.append("missing_source_refs")
    elif source_status["stale_refs"]:
        reasons.append("stale_source")
    if topology_required and not topology_evidence and not topology_status["current_refs"]:
        reasons.append("missing_topology_evidence")
    if topology_status["stale_refs"]:
        reasons.append("stale_source")
    if proof_claim and not proof_evidence["present"]:
        reasons.append("missing_proof_evidence")
    if blockers:
        reasons.append("blocker_present")
    if advisory:
        reasons.append("advisory_only")
    reasons = sorted(set(reasons))
    return {
        "state": "followup_ready" if not reasons else "not_followup_ready",
        "typed_reasons": reasons,
        "source_refs": source_status["current_refs"],
        "source_ref_blockers": source_status["stale_refs"],
        "topology_required": topology_required,
        "topology_paths": topology_status["current_refs"],
        "topology_path_blockers": topology_status["stale_refs"],
        "configured_topology_evidence": topology_evidence,
        "proof_ready_claimed": proof_claim,
        "concrete_proof_or_harness_evidence": proof_evidence["present"],
        "proof_evidence_values": proof_evidence["evidence_values"],
        "proof_paths": proof_evidence["proof_paths"],
        "blocker_markers": blockers,
        "advisory_markers": advisory,
    }


def command_with_candidate(template: dict[str, Any], candidate_address: str | None) -> str | None:
    command = str(template.get("capture_command") or "").strip()
    contract = str(template.get("contract") or "").strip()
    if not command or not candidate_address or not contract:
        return command or None
    return command.replace(f"<resolved-{contract}-address>", candidate_address)


def row_missing_requirements(row: dict[str, Any]) -> list[dict[str, str]]:
    requirements: list[dict[str, str]] = []
    row_id_value = str(row.get("row_id") or "").strip()
    contract = str(row.get("contract") or "UNKNOWN").strip() or "UNKNOWN"
    for missing in row.get("missing") or []:
        if missing == "missing_address":
            requirements.append(
                {
                    "kind": "address",
                    "row_id": row_id_value,
                    "field": "resolved_address",
                    "required_input": f"verified deployed address for {contract}",
                    "safe_next_action": "resolve from deployment docs, canonical registry, or verified live deployment source before capture",
                }
            )
        elif missing == "candidate_address_requires_manual_verification":
            requirements.append(
                {
                    "kind": "candidate_address_verification",
                    "row_id": row_id_value,
                    "field": "resolved_address",
                    "required_input": f"operator-verified deployed address for {contract}",
                    "safe_next_action": "verify the candidate address against deployment evidence before using the candidate-bound command",
                }
            )
        elif missing == "missing_rpc":
            requirements.append(
                {
                    "kind": "rpc",
                    "row_id": row_id_value,
                    "field": str(row.get("rpc_env_var") or "RPC_URL"),
                    "required_input": "private RPC endpoint for the row network",
                    "safe_next_action": f"set {row.get('rpc_env_var') or 'RPC_URL'} in the shell or workspace .env before capture",
                }
            )
        elif missing == "missing_same_block":
            requirements.append(
                {
                    "kind": "same_block",
                    "row_id": row_id_value,
                    "field": "required_same_block",
                    "required_input": "one explicit block shared by both rows in the proof pair",
                    "safe_next_action": "select a block where both contracts and expected topology values are valid",
                }
            )
        elif missing == "missing_expected_value":
            requirements.append(
                {
                    "kind": "expected_value",
                    "row_id": row_id_value,
                    "field": "expect",
                    "required_input": "expected live call result for the topology relation",
                    "safe_next_action": "derive from deployment topology or contract configuration before capture",
                }
            )
        elif missing == "missing_manual_proof":
            requirements.append(
                {
                    "kind": "manual_proof",
                    "row_id": row_id_value,
                    "field": f"manual_proofs/{row_id_value}.json",
                    "required_input": "executed live-state-checker proof saved with the row id",
                    "safe_next_action": "run the candidate-bound capture command only after address/RPC/block/expect are concrete",
                }
            )
    return requirements


def pair_blocker_class(pair: dict[str, Any]) -> str:
    missing = set(pair.get("missing") or [])
    rows = pair.get("rows") or []
    candidate_rows = sum(1 for row in rows if row.get("candidate_address_selected_for_draft_command"))
    rows_with_missing_address = sum(1 for row in rows if "missing_address" in (row.get("missing") or []))
    if pair.get("same_block_executor_ready_now"):
        return "same_block_executor_ready"
    if pair.get("capture_pair_executable_now") and not pair.get("import_pair_ready_now"):
        return "capture_ready_waiting_for_manual_import"
    if candidate_rows and rows_with_missing_address:
        return "one_side_candidate_bound_missing_counterpart_address"
    if "missing_address" in missing:
        return "address_resolution_required"
    if {"missing_rpc", "missing_same_block", "missing_expected_value"} & missing:
        return "runtime_inputs_required"
    if "missing_manual_proof" in missing:
        return "manual_proof_capture_required"
    return "terminal_unknown_live_topology_inputs"


def pair_requirement_bundle(pair: dict[str, Any]) -> dict[str, Any]:
    missing_requirements = [
        requirement
        for row in pair.get("rows") or []
        for requirement in row_missing_requirements(row)
    ]
    return {
        "schema": "auditooor.live_topology_addressable_pair_requirements.v1",
        "proof_pair_id": pair["proof_pair_id"],
        "status": pair["status"],
        "blocker_class": pair["blocker_class"],
        "row_ids": pair["row_ids"],
        "contracts": pair["contracts"],
        "networks": pair["networks"],
        "missing": pair["missing"],
        "missing_requirements": missing_requirements,
        "followup_pair_ready_now": pair.get("followup_pair_ready_now"),
        "followup_ready_row_ids": pair.get("followup_ready_row_ids") or [],
        "followup_non_ready_rows": pair.get("followup_non_ready_rows") or [],
        "candidate_bound_capture_commands": [
            row["capture_command_candidate_bound"]
            for row in pair.get("rows") or []
            if row.get("capture_command_candidate_bound")
        ],
        "manual_import_command_after_capture": pair.get("import_command_after_capture"),
        "same_block_executor_command_after_import": pair.get("executor_command_after_import"),
        "safe_execution_order": [
            "fill every address/RPC/same-block/expected-value requirement",
            "run candidate-bound live-state-checker capture commands for both rows",
            "import the saved manual proofs into live_topology_checks.json",
            "run the same-block proof executor",
            "only treat the pair as closed if both imported rows pass at one shared block",
        ],
        **ADVISORY_POSTURE,
    }


def classify_row(
    *,
    workspace: Path,
    row_id_value: str,
    pair_item: dict[str, Any],
    ew_row: dict[str, Any],
    template: dict[str, Any],
    deployment_candidates: dict[str, list[str]],
    env_values: dict[str, str],
    manual_ids: set[str],
) -> dict[str, Any]:
    network = str(ew_row.get("network") or template.get("network") or "mainnet").strip() or "mainnet"
    env_key = rpc_env_var(network)
    rpc_available = bool(os.environ.get(env_key) or env_values.get(env_key))
    contract = str(ew_row.get("contract") or template.get("contract") or "UNKNOWN")
    candidate_addresses = ew_row.get("candidate_addresses") or []
    if not isinstance(candidate_addresses, list):
        candidate_addresses = []
    if not candidate_addresses:
        candidate_addresses = deployment_candidates.get(contract, [])
    address = str(ew_row.get("resolved_address") or ew_row.get("address") or "").strip()
    single_candidate = candidate_addresses[0] if len(candidate_addresses) == 1 else None
    usable_address = address or single_candidate
    required_block = template.get("required_same_block")
    expected_value = template.get("expect")
    missing: list[str] = []
    if not usable_address:
        missing.append("missing_address")
    elif not address:
        missing.append("candidate_address_requires_manual_verification")
    if not rpc_available:
        missing.append("missing_rpc")
    if is_placeholder(required_block):
        missing.append("missing_same_block")
    if is_placeholder(expected_value):
        missing.append("missing_expected_value")
    if row_id_value not in manual_ids:
        missing.append("missing_manual_proof")
    capture_executable_now = bool(
        usable_address
        and rpc_available
        and not is_placeholder(required_block)
        and not is_placeholder(expected_value)
    )
    import_ready_now = row_id_value in manual_ids
    strict_payloads = [payload for payload in (pair_item, ew_row, template) if isinstance(payload, dict)]
    followup = row_followup_readiness(workspace, strict_payloads)
    return {
        "row_id": row_id_value,
        "contract": contract,
        "requirement_id": str(ew_row.get("requirement_id") or template.get("requirement_id") or ""),
        "network": network,
        "rpc_env_var": env_key,
        "rpc_available": rpc_available,
        "address_resolution_status": ew_row.get("address_resolution_status"),
        "resolved_address": address or None,
        "candidate_addresses": candidate_addresses,
        "candidate_address_selected_for_draft_command": single_candidate,
        "required_same_block": required_block,
        "expected_value": expected_value,
        "manual_proof_present": row_id_value in manual_ids,
        "capture_executable_now": capture_executable_now,
        "import_ready_now": import_ready_now,
        "missing": missing,
        "followup_ready": followup["state"] == "followup_ready",
        "followup_readiness": followup,
        "followup_non_ready_reasons": followup["typed_reasons"],
        "source_refs": followup["source_refs"],
        "source_ref_blockers": followup["source_ref_blockers"],
        "topology_required": followup["topology_required"],
        "topology_paths": followup["topology_paths"],
        "topology_path_blockers": followup["topology_path_blockers"],
        "configured_topology_evidence": followup["configured_topology_evidence"],
        "proof_ready_claimed": followup["proof_ready_claimed"],
        "concrete_proof_or_harness_evidence": followup["concrete_proof_or_harness_evidence"],
        "proof_evidence_values": followup["proof_evidence_values"],
        "proof_paths": followup["proof_paths"],
        "blocker_markers": followup["blocker_markers"],
        "advisory_markers": followup["advisory_markers"],
        "capture_command_candidate_bound": command_with_candidate(template, single_candidate),
        "template_path": str(workspace / DEFAULT_TEMPLATE_DIR / f"{row_id_value}.json"),
    }


def build_payload(
    *,
    workspace: Path,
    fj_group: dict[str, Any],
    ew_resolution: dict[str, Any],
    deployment_topology: dict[str, Any],
    templates: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    env_values = workspace_env(workspace)
    manual_ids = manual_proof_row_ids(workspace)
    ew_by_id = {row_id(row): row for row in ew_resolution.get("rows") or [] if isinstance(row, dict) and row_id(row)}
    deployment_candidates = deployment_candidate_index(deployment_topology)
    pair_items = [item for item in fj_group.get("items") or [] if isinstance(item, dict)]
    pair_results: list[dict[str, Any]] = []
    pair_status_counts: Counter[str] = Counter()
    row_missing_counts: Counter[str] = Counter()
    followup_non_ready_reason_counts: Counter[str] = Counter()

    for item in pair_items:
        pid = str(item.get("proof_pair_id") or "").strip()
        row_ids = [str(rid).strip() for rid in item.get("row_ids") or [] if str(rid).strip()]
        rows = [
            classify_row(
                workspace=workspace,
                row_id_value=rid,
                pair_item=item,
                ew_row=ew_by_id.get(rid, {}),
                template=templates.get(rid, {}),
                deployment_candidates=deployment_candidates,
                env_values=env_values,
                manual_ids=manual_ids,
            )
            for rid in row_ids
        ]
        for row in rows:
            row_missing_counts.update(row["missing"])
            followup_non_ready_reason_counts.update(row["followup_non_ready_reasons"])
        capture_ready = len(rows) >= 2 and all(row["capture_executable_now"] for row in rows)
        import_ready = len(rows) >= 2 and all(row["import_ready_now"] for row in rows)
        followup_ready = len(rows) >= 2 and all(row["followup_ready"] for row in rows)
        if capture_ready and import_ready:
            status = "ready_for_import_and_executor"
        elif capture_ready:
            status = "capture_executable_missing_manual_import"
        else:
            status = "terminal_not_locally_executable"
        pair_status_counts[status] += 1
        pair_missing = sorted({missing for row in rows for missing in row["missing"]})
        pair_result = {
            "proof_pair_id": pid,
            "requirement_ids": item.get("requirement_ids") or [],
            "row_ids": row_ids,
            "contracts": item.get("contracts") or sorted({row["contract"] for row in rows}),
            "networks": item.get("networks") or sorted({row["network"] for row in rows}),
            "status": status,
            "capture_pair_executable_now": capture_ready,
            "import_pair_ready_now": import_ready,
            "same_block_executor_ready_now": capture_ready and import_ready,
            "followup_pair_ready_now": followup_ready,
            "followup_ready_row_ids": [row["row_id"] for row in rows if row["followup_ready"]],
            "followup_non_ready_rows": [
                {
                    "row_id": row["row_id"],
                    "typed_reasons": row["followup_non_ready_reasons"],
                    "source_ref_blockers": row["source_ref_blockers"],
                    "topology_path_blockers": row["topology_path_blockers"],
                    "blocker_markers": row["blocker_markers"],
                    "advisory_markers": row["advisory_markers"],
                }
                for row in rows
                if not row["followup_ready"]
            ],
            "missing": pair_missing,
            "rows": rows,
            "import_command_after_capture": item.get("import_command_after_capture"),
            "executor_command_after_import": item.get("executor_command_after_import"),
        }
        pair_result["blocker_class"] = pair_blocker_class(pair_result)
        pair_result["missing_requirements"] = [
            requirement for row in rows for requirement in row_missing_requirements(row)
        ]
        pair_result["requirement_bundle_path"] = str(
            workspace / DEFAULT_REQUIREMENT_DIR / f"{pid or 'unknown_pair'}.json"
        )
        pair_results.append(pair_result)

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "inputs": {
            "fj_addressable_group": str(workspace / DEFAULT_FJ_GROUP),
            "ew_address_resolution": str(workspace / DEFAULT_EW_RESOLUTION),
            "deployment_topology": str(workspace / DEFAULT_DEPLOYMENT_TOPOLOGY),
            "template_dir": str(workspace / DEFAULT_TEMPLATE_DIR),
        },
        "before_counts": {
            "fj_addressable_pairs": int(fj_group.get("pair_count") or len(pair_items)),
            "fj_addressable_rows": int(fj_group.get("row_count") or sum(len(item.get("row_ids") or []) for item in pair_items)),
            "template_files_loaded": len(templates),
            "manual_proof_row_ids": len(manual_ids),
            "rpc_env_keys_found": sorted(
                key for key in {rpc_env_var(network) for item in pair_items for network in item.get("networks") or ["mainnet"]}
                if os.environ.get(key) or env_values.get(key)
            ),
            "contracts_with_candidate_addresses": len(deployment_candidates),
        },
        "after_counts": {
            "pairs_total": len(pair_results),
            "rows_total": sum(len(item["rows"]) for item in pair_results),
            "pair_status_counts": dict(sorted(pair_status_counts.items())),
            "row_missing_counts": dict(sorted(row_missing_counts.items())),
            "capture_executable_pairs": sum(1 for item in pair_results if item["capture_pair_executable_now"]),
            "import_ready_pairs": sum(1 for item in pair_results if item["import_pair_ready_now"]),
            "same_block_executor_ready_pairs": sum(1 for item in pair_results if item["same_block_executor_ready_now"]),
            "followup_ready_pairs": sum(1 for item in pair_results if item["followup_pair_ready_now"]),
            "followup_ready_rows": sum(1 for item in pair_results for row in item["rows"] if row["followup_ready"]),
            "followup_non_ready_rows": sum(
                1 for item in pair_results for row in item["rows"] if not row["followup_ready"]
            ),
            "followup_non_ready_reason_counts": dict(sorted(followup_non_ready_reason_counts.items())),
            "proof_ready_claimed_rows": sum(
                1 for item in pair_results for row in item["rows"] if row["proof_ready_claimed"]
            ),
            "proof_ready_claimed_missing_evidence_rows": sum(
                1
                for item in pair_results
                for row in item["rows"]
                if row["proof_ready_claimed"] and "missing_proof_evidence" in row["followup_non_ready_reasons"]
            ),
            "candidate_bound_rows": sum(1 for item in pair_results for row in item["rows"] if row["candidate_address_selected_for_draft_command"]),
            "pair_blocker_class_counts": dict(
                sorted(Counter(item["blocker_class"] for item in pair_results).items())
            ),
            "missing_requirement_kind_counts": dict(
                sorted(
                    Counter(
                        requirement["kind"]
                        for item in pair_results
                        for requirement in item["missing_requirements"]
                    ).items()
                )
            ),
            "missing_rpc_pairs": sum(1 for item in pair_results if "missing_rpc" in item["missing"]),
            "missing_address_pairs": sum(1 for item in pair_results if "missing_address" in item["missing"]),
            "missing_block_pairs": sum(1 for item in pair_results if "missing_same_block" in item["missing"]),
            "missing_expected_value_pairs": sum(1 for item in pair_results if "missing_expected_value" in item["missing"]),
            "missing_manual_proof_pairs": sum(1 for item in pair_results if "missing_manual_proof" in item["missing"]),
        },
        "pairs": pair_results,
        "why_no_more_local_closure_safe": (
            "An addressable FJ pair still needs concrete addresses for both rows, an RPC URL for the network, "
            "one explicit shared block, expected values for each call, imported manual proof rows, and executor "
            "validation before it can close. This artifact found no pair with all prerequisites, so no live "
            "topology proof was promoted."
        ),
        **ADVISORY_POSTURE,
    }


def write_requirement_bundles(directory: Path, payload: dict[str, Any]) -> list[str]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for pair in payload.get("pairs") or []:
        if not isinstance(pair, dict):
            continue
        pair_id = str(pair.get("proof_pair_id") or "unknown_pair").strip() or "unknown_pair"
        path = directory / f"{pair_id}.json"
        write_json(path, pair_requirement_bundle(pair))
        written.append(str(path))
    return written


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# Live Topology Addressable Follow-Up",
        "",
        "Adjudicates FJ addressable candidates for real same-block proof readiness.",
        "",
        "## Summary",
    ]
    for key, value in payload["after_counts"].items():
        lines.append(f"- `{key}`: `{json.dumps(value, sort_keys=True) if isinstance(value, dict) else value}`")
    lines.extend(["", "## Pair Results"])
    for pair in payload["pairs"]:
        lines.append(
            f"- `{pair['proof_pair_id']}`: `{pair['status']}` / `{pair['blocker_class']}`; "
            f"followup_ready_rows={len(pair['followup_ready_row_ids'])}; "
            f"missing={', '.join(pair['missing']) or 'none'}; "
            f"contracts={', '.join(pair['contracts'])}"
        )
    lines.extend(["", "## Safety", "", payload["why_no_more_local_closure_safe"], ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--fj-group", type=Path)
    parser.add_argument("--ew-resolution", type=Path)
    parser.add_argument("--deployment-topology", type=Path)
    parser.add_argument("--template-dir", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--requirement-dir", type=Path)
    parser.add_argument(
        "--no-write-requirements",
        action="store_true",
        help="Do not write per-proof-pair requirement bundle JSON files",
    )
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[live-topology-addressable-followup] workspace not found: {workspace}")
    fj_group = load_json(workspace_path(workspace, args.fj_group, DEFAULT_FJ_GROUP), "FJ addressable group")
    ew_resolution = load_json(workspace_path(workspace, args.ew_resolution, DEFAULT_EW_RESOLUTION), "EW address resolution")
    deployment_topology = load_json(
        workspace_path(workspace, args.deployment_topology, DEFAULT_DEPLOYMENT_TOPOLOGY),
        "deployment topology",
        required=False,
    )
    template_dir = workspace_path(workspace, args.template_dir, DEFAULT_TEMPLATE_DIR)
    payload = build_payload(
        workspace=workspace,
        fj_group=fj_group,
        ew_resolution=ew_resolution,
        deployment_topology=deployment_topology,
        templates=template_index(template_dir),
    )
    out_json = workspace_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = workspace_path(workspace, args.out_md, DEFAULT_OUT_MD)
    write_json(out_json, payload)
    write_markdown(out_md, payload)
    requirement_dir = workspace_path(workspace, args.requirement_dir, DEFAULT_REQUIREMENT_DIR)
    requirement_files: list[str] = []
    if not args.no_write_requirements:
        requirement_files = write_requirement_bundles(requirement_dir, payload)
        payload["requirement_bundle_dir"] = str(requirement_dir)
        payload["requirement_bundle_files"] = requirement_files
        write_json(out_json, payload)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            "[live-topology-addressable-followup] OK "
            f"pairs={payload['after_counts']['pairs_total']} "
            f"capture_executable={payload['after_counts']['capture_executable_pairs']} "
            f"same_block_executor_ready={payload['after_counts']['same_block_executor_ready_pairs']} "
            f"requirement_bundles={len(requirement_files)} "
            f"out={out_json}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
