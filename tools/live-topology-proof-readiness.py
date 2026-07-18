#!/usr/bin/env python3
"""Classify full-corpus live-topology proof-pair readiness.

This is the bridge between the 350 offline proof-pair skeletons and the
executor that can only close rows after real same-block proof is imported.
It validates every required row against its manual-proof template, optional
manual_proofs/ cache, and live_topology_checks.json import state, then writes
machine-readable per-pair requirement bundles.

The tool never calls RPC and never marks a proof as executed. If all local
inputs are not already present, it emits exact terminal blockers and safe next
commands instead of inventing evidence.
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


SCHEMA = "auditooor.live_topology_proof_readiness.v1"
DEFAULT_REQUIREMENTS = ".auditooor/live_topology_proof_requirements.json"
DEFAULT_TEMPLATE_DIR = ".auditooor/live_topology_manual_proof_templates_fd"
DEFAULT_LIVE_TOPOLOGY = "live_topology_checks.json"
DEFAULT_MANUAL_PROOFS = "manual_proofs"
DEFAULT_ADDRESSABLE = ".auditooor/live_topology_addressable_followup.json"
DEFAULT_OUT_JSON = ".auditooor/live_topology_proof_readiness.json"
DEFAULT_OUT_MD = ".auditooor/live_topology_proof_readiness.md"
DEFAULT_BUNDLE_DIR = ".auditooor/live_topology_full_pair_requirements"
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
SOURCE_REF_RE = re.compile(
    r"(?P<path>(?:~|/|\.{1,2}/|[A-Za-z0-9_.-])"
    r"[A-Za-z0-9_./@%+,\-]*\."
    r"(?:sol|vy|go|rs|move|cairo|ts|tsx|js|jsx|py|md|json|yaml|yml|toml))"
    r"(?:(?::|#L)(?P<line>\d+))?"
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


def resolve_path(workspace: Path, path: Path | None, default: str) -> Path:
    candidate = path or Path(default)
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def load_json(path: Path, label: str, *, required: bool = True) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise SystemExit(f"[live-topology-proof-readiness] missing {label}: {path}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-proof-readiness] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-proof-readiness] expected object JSON for {label}: {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text.lower() in MISSING_TEXT or text.startswith("<") or text.endswith(">")


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


def resolve_source_ref(workspace: Path, raw_ref: str) -> dict[str, Any]:
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
    resolved = [resolve_source_ref(workspace, ref) for ref in refs]
    return {
        "raw_refs": refs,
        "current_refs": [item for item in resolved if item["current"]],
        "stale_refs": [item for item in resolved if not item["current"]],
        "resolved_refs": resolved,
    }


def has_advisory_payload(payloads: list[dict[str, Any]]) -> bool:
    for payload in payloads:
        if truthy(payload.get("advisory_only")) or truthy(payload.get("advisory")):
            return True
        for key in (*PROOF_EVIDENCE_KEYS, *TOPOLOGY_EVIDENCE_KEYS):
            value = payload.get(key)
            if isinstance(value, dict) and (truthy(value.get("advisory_only")) or truthy(value.get("advisory"))):
                return True
    return False


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


def has_concrete_proof_or_harness(payloads: list[dict[str, Any]], workspace: Path) -> bool:
    for payload in payloads:
        for key in PROOF_EVIDENCE_KEYS:
            if value_has_concrete_proof(payload.get(key), workspace):
                return True
        for path_value in collect_values([payload], PROOF_PATH_KEYS):
            if proof_path_exists(workspace, path_value):
                return True
    return False


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
        if key.strip():
            values[key.strip()] = value.strip().strip("'").strip('"')
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


def load_templates(template_dir: Path) -> dict[str, dict[str, Any]]:
    templates: dict[str, dict[str, Any]] = {}
    if not template_dir.is_dir():
        return templates
    for path in sorted(template_dir.glob("*.json")):
        payload = load_json(path, f"template {path.name}", required=False)
        row_id = str(payload.get("row_id") or path.stem).strip()
        if row_id:
            templates[row_id] = payload
    return templates


def first_result(payload: dict[str, Any]) -> dict[str, Any]:
    results = payload.get("results")
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                return item
    return payload


def load_manual_proofs(manual_dir: Path) -> dict[str, dict[str, Any]]:
    proofs: dict[str, dict[str, Any]] = {}
    if not manual_dir.is_dir():
        return proofs
    for path in sorted(manual_dir.glob("*.json")):
        payload = load_json(path, f"manual proof {path.name}", required=False)
        if not payload:
            continue
        row = first_result(payload)
        row_id = str(row.get("id") or row.get("row_id") or path.stem).strip()
        if row_id:
            proofs[row_id] = {"path": str(path), "row": row, "payload": payload}
    return proofs


def index_live_topology(live: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = {
        str(row.get("id") or row.get("row_id") or "").strip(): row
        for row in live.get("results") or []
        if isinstance(row, dict) and str(row.get("id") or row.get("row_id") or "").strip()
    }
    pairs = {
        str(pair.get("id") or pair.get("proof_pair_id") or "").strip(): pair
        for pair in live.get("proof_pairs") or []
        if isinstance(pair, dict) and str(pair.get("id") or pair.get("proof_pair_id") or "").strip()
    }
    return rows, pairs


def addressable_row_index(addressable: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for pair in addressable.get("pairs") or []:
        if not isinstance(pair, dict):
            continue
        for row in pair.get("rows") or []:
            if not isinstance(row, dict):
                continue
            row_id = str(row.get("row_id") or "").strip()
            if row_id:
                index[row_id] = row
    return index


def row_strict_evidence(
    workspace: Path,
    payloads: list[dict[str, Any]],
) -> dict[str, Any]:
    missing: list[str] = []
    source_refs = collect_values(payloads, SOURCE_REF_KEYS)
    source_status = source_ref_status(workspace, source_refs)
    if not source_refs:
        missing.append("missing_current_workspace_source_refs")
    elif source_status["stale_refs"]:
        missing.append("stale_workspace_source_refs")

    topology_paths = collect_values(payloads, TOPOLOGY_PATH_KEYS)
    topology_status = source_ref_status(workspace, topology_paths)
    topology_evidence = [
        value
        for value in collect_values(payloads, TOPOLOGY_EVIDENCE_KEYS)
        if not is_placeholder(value)
    ]
    if not topology_paths:
        missing.append("missing_topology_path")
    elif topology_status["stale_refs"]:
        missing.append("stale_topology_path")
    if not topology_evidence and not topology_status["current_refs"]:
        missing.append("missing_configured_topology_evidence")
    if has_advisory_payload(payloads):
        missing.append("advisory_only_evidence")

    return {
        "missing": sorted(set(missing)),
        "source_refs": source_status["current_refs"],
        "source_ref_blockers": source_status["stale_refs"],
        "topology_paths": topology_status["current_refs"],
        "topology_path_blockers": topology_status["stale_refs"],
        "configured_topology_evidence": topology_evidence,
    }


def import_command(workspace: Path, row_ids: list[str]) -> str:
    row_args = " ".join(f"--manual-proof-id {row_id}" for row_id in row_ids)
    return (
        f"python3 tools/live-check-runner.py {workspace} --import-manual-proofs {row_args} "
        f"--out-json {workspace / 'live_topology_checks.json'} --out-md {workspace / 'LIVE_TOPOLOGY.md'}"
    )


def executor_command(workspace: Path) -> str:
    return (
        "python3 tools/live-topology-proof-executor.py "
        f"--workspace {workspace} --requirements {workspace / '.auditooor' / 'live_topology_proof_requirements.json'} "
        f"--live-topology {workspace / 'live_topology_checks.json'}"
    )


def row_requirement(
    *,
    workspace: Path,
    required_row: dict[str, Any],
    template: dict[str, Any],
    live_row: dict[str, Any] | None,
    manual_proof: dict[str, Any] | None,
    addressable_row: dict[str, Any] | None,
    env_values: dict[str, str],
    pair_id: str,
) -> dict[str, Any]:
    row_id = str(required_row.get("id") or template.get("row_id") or "").strip()
    contract = str(required_row.get("contract") or template.get("contract") or "UNKNOWN").strip() or "UNKNOWN"
    network = str(template.get("network") or "mainnet").strip() or "mainnet"
    rpc_env_var = str(template.get("rpc_env_var") or f"{network.upper()}_RPC_URL").strip()
    if rpc_env_var == "MAINNET_RPC_URL" or network.lower() == "mainnet":
        rpc_env_var = "MAINNET_RPC_URL"
    rpc_available = bool(os.environ.get(rpc_env_var) or env_values.get(rpc_env_var))
    required_address = template.get("required_address")
    candidate_address = None
    if addressable_row:
        candidate_address = addressable_row.get("candidate_address_selected_for_draft_command")
    manual_row = (manual_proof or {}).get("row") if manual_proof else None
    manual_payload = (manual_proof or {}).get("payload") if manual_proof else None
    live_status = str((live_row or {}).get("status") or "").strip()
    manual_status = str((manual_row or {}).get("status") or "").strip() if isinstance(manual_row, dict) else ""
    live_block = str((live_row or {}).get("block") or "").strip()
    manual_block = str((manual_row or {}).get("block") or "").strip() if isinstance(manual_row, dict) else ""
    live_pair = str((live_row or {}).get("proof_pair_id") or "").strip()
    manual_pair = str((manual_row or {}).get("proof_pair_id") or "").strip() if isinstance(manual_row, dict) else ""
    live_evidence = str((live_row or {}).get("evidence_class") or "").strip()
    manual_evidence = str((manual_row or {}).get("evidence_class") or "").strip() if isinstance(manual_row, dict) else ""
    strict_payloads = [payload for payload in [required_row, template, live_row, manual_row, manual_payload] if isinstance(payload, dict)]
    strict_evidence = row_strict_evidence(workspace, strict_payloads)
    missing: list[str] = []
    if not template:
        missing.append("missing_template")
    if is_placeholder(required_address) and not candidate_address:
        missing.append("missing_verified_address")
    elif candidate_address:
        missing.append("candidate_address_requires_manual_verification")
    if not rpc_available:
        missing.append("missing_rpc")
    if is_placeholder(template.get("required_same_block")):
        missing.append("missing_same_block")
    if is_placeholder(template.get("expect")):
        missing.append("missing_expected_value")
    if not manual_proof:
        missing.append("missing_manual_proof")
    else:
        if manual_status not in {"pass", "fail"}:
            missing.append("manual_proof_not_executed")
        if not manual_block:
            missing.append("manual_proof_missing_block")
        if manual_pair and manual_pair != pair_id:
            missing.append("manual_proof_pair_mismatch")
        if manual_evidence and manual_evidence != "topology-relation":
            missing.append("manual_proof_wrong_evidence_class")
    if not live_row:
        missing.append("missing_imported_live_row")
    else:
        if live_status not in {"pass", "fail"}:
            missing.append("imported_live_row_not_executed")
        if not live_block:
            missing.append("imported_live_row_missing_block")
        if live_pair and live_pair != pair_id:
            missing.append("imported_live_row_pair_mismatch")
        if live_evidence and live_evidence != "topology-relation":
            missing.append("imported_live_row_wrong_evidence_class")
    missing.extend(strict_evidence["missing"])
    capture_ready = not any(
        item in missing
        for item in [
            "missing_template",
            "missing_verified_address",
            "missing_rpc",
            "missing_same_block",
            "missing_expected_value",
        ]
    )
    import_ready = bool(manual_proof) and not any(item.startswith("manual_proof_") for item in missing)
    base_executor_ready = bool(live_row) and live_status == "pass" and not any(
        item.startswith("imported_live_row_") or item == "missing_imported_live_row" for item in missing
    )
    executor_ready = base_executor_ready and not strict_evidence["missing"]
    return {
        "row_id": row_id,
        "contract": contract,
        "network": network,
        "rpc_env_var": rpc_env_var,
        "rpc_available": rpc_available,
        "required_address": required_address,
        "candidate_address": candidate_address,
        "required_same_block": template.get("required_same_block"),
        "expected_value": template.get("expect"),
        "manual_proof_path": (manual_proof or {}).get("path"),
        "manual_status": manual_status or None,
        "manual_block": manual_block or None,
        "live_status": live_status or None,
        "live_block": live_block or None,
        "missing": sorted(set(missing)),
        "strict_missing": strict_evidence["missing"],
        "source_refs": strict_evidence["source_refs"],
        "source_ref_blockers": strict_evidence["source_ref_blockers"],
        "topology_paths": strict_evidence["topology_paths"],
        "topology_path_blockers": strict_evidence["topology_path_blockers"],
        "configured_topology_evidence": strict_evidence["configured_topology_evidence"],
        "concrete_proof_or_harness_evidence": has_concrete_proof_or_harness(strict_payloads, workspace),
        "capture_ready": capture_ready,
        "import_ready": import_ready,
        "base_executor_ready": base_executor_ready,
        "executor_ready": executor_ready,
        "capture_command": template.get("capture_command"),
        "manual_import_command": import_command(workspace, [row_id]),
    }


def pair_status(rows: list[dict[str, Any]], live_pair: dict[str, Any] | None, pair_strict_missing: set[str]) -> str:
    if len(rows) < 2:
        return "blocked_pair_incomplete"
    if all(row["base_executor_ready"] for row in rows):
        blocks = {row.get("live_block") for row in rows if row.get("live_block")}
        live_status = str((live_pair or {}).get("status") or "").strip()
        if len(blocks) == 1 and live_status == "proved":
            if pair_strict_missing or any(row["strict_missing"] for row in rows):
                return "blocked_strict_readiness_inputs"
            return "same_block_executor_ready"
        return "blocked_imported_pair_not_exact"
    if all(row["import_ready"] for row in rows):
        return "manual_proofs_ready_for_import"
    if all(row["capture_ready"] for row in rows):
        return "capture_ready_missing_manual_proofs"
    return "terminal_missing_local_inputs"


def pair_blocker_class(status: str, missing: set[str]) -> str:
    if status == "same_block_executor_ready":
        return "none"
    if status == "blocked_strict_readiness_inputs":
        if "stale_workspace_source_refs" in missing:
            return "stale_source_refs"
        if "missing_current_workspace_source_refs" in missing:
            return "source_refs_required"
        if "advisory_only_evidence" in missing:
            return "advisory_only_evidence"
        if {"missing_topology_path", "missing_configured_topology_evidence", "stale_topology_path"} & missing:
            return "configured_topology_required"
        if "missing_concrete_proof_or_harness_evidence" in missing:
            return "concrete_proof_required"
        return "strict_readiness_inputs_required"
    if status == "blocked_imported_pair_not_exact":
        return "imported_pair_not_exact"
    if status == "manual_proofs_ready_for_import":
        return "ready_to_import_manual_proofs"
    if status == "capture_ready_missing_manual_proofs":
        return "ready_to_capture_manual_proofs"
    if "missing_verified_address" in missing:
        return "address_resolution_required"
    if {"missing_rpc", "missing_same_block", "missing_expected_value"} & missing:
        return "runtime_inputs_required"
    if "missing_manual_proof" in missing:
        return "manual_proof_required"
    return "terminal_unknown_live_topology_inputs"


def pair_strict_missing(
    *,
    workspace: Path,
    requirement: dict[str, Any],
    live_pair: dict[str, Any] | None,
    rows: list[dict[str, Any]],
) -> list[str]:
    missing: list[str] = []
    payloads = [payload for payload in [requirement, live_pair] if isinstance(payload, dict)]
    if has_advisory_payload(payloads):
        missing.append("advisory_only_evidence")
    if not has_concrete_proof_or_harness(payloads, workspace):
        if not any(row.get("concrete_proof_or_harness_evidence") for row in rows):
            missing.append("missing_concrete_proof_or_harness_evidence")
    return sorted(set(missing))


def build_payload(
    *,
    workspace: Path,
    requirements: dict[str, Any],
    templates: dict[str, dict[str, Any]],
    live: dict[str, Any],
    manual_proofs: dict[str, dict[str, Any]],
    addressable: dict[str, Any],
) -> dict[str, Any]:
    env_values = workspace_env(workspace)
    live_rows, live_pairs = index_live_topology(live)
    addressable_rows = addressable_row_index(addressable)
    proof_pairs: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    row_missing_counts: Counter[str] = Counter()
    strict_missing_counts: Counter[str] = Counter()
    row_readiness_counts: Counter[str] = Counter()

    for requirement in requirements.get("requirements") or []:
        if not isinstance(requirement, dict):
            continue
        pair_id = str(requirement.get("required_proof_pair_id") or "").strip()
        required_rows = [row for row in requirement.get("required_live_rows") or [] if isinstance(row, dict)]
        rows = [
            row_requirement(
                workspace=workspace,
                required_row=row,
                template=templates.get(str(row.get("id") or "").strip(), {}),
                live_row=live_rows.get(str(row.get("id") or "").strip()),
                manual_proof=manual_proofs.get(str(row.get("id") or "").strip()),
                addressable_row=addressable_rows.get(str(row.get("id") or "").strip()),
                env_values=env_values,
                pair_id=pair_id,
            )
            for row in required_rows
        ]
        pair_strict = pair_strict_missing(
            workspace=workspace,
            requirement=requirement,
            live_pair=live_pairs.get(pair_id),
            rows=rows,
        )
        missing = {item for row in rows for item in row["missing"]}
        missing.update(pair_strict)
        status = pair_status(rows, live_pairs.get(pair_id), set(pair_strict))
        blocker_class = pair_blocker_class(status, missing)
        status_counts[status] += 1
        blocker_counts[blocker_class] += 1
        strict_missing_counts.update(pair_strict)
        for row in rows:
            row_missing_counts.update(row["missing"])
            strict_missing_counts.update(row["strict_missing"])
            if row["executor_ready"]:
                row_readiness_counts["executor_ready"] += 1
            elif row["import_ready"]:
                row_readiness_counts["import_ready"] += 1
            elif row["capture_ready"]:
                row_readiness_counts["capture_ready"] += 1
            else:
                row_readiness_counts["blocked_missing_inputs"] += 1
        row_ids = [row["row_id"] for row in rows if row.get("row_id")]
        proof_pairs.append(
            {
                "requirement_id": requirement.get("requirement_id"),
                "proof_pair_id": pair_id,
                "source_item_id": requirement.get("source_item_id"),
                "relation_kind": requirement.get("relation_kind"),
                "required_contracts": requirement.get("required_contracts") or [],
                "row_ids": row_ids,
                "status": status,
                "blocker_class": blocker_class,
                "missing": sorted(missing),
                "strict_missing": sorted(set(pair_strict) | {item for row in rows for item in row["strict_missing"]}),
                "rows": rows,
                "import_command_after_manual_proofs": import_command(workspace, row_ids),
                "executor_command_after_import": executor_command(workspace),
                "closure_candidate": status == "same_block_executor_ready",
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
            }
        )

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "inputs": {
            "requirements": str(workspace / DEFAULT_REQUIREMENTS),
            "template_dir": str(workspace / DEFAULT_TEMPLATE_DIR),
            "live_topology": str(workspace / DEFAULT_LIVE_TOPOLOGY),
            "manual_proofs": str(workspace / DEFAULT_MANUAL_PROOFS),
            "addressable_followup": str(workspace / DEFAULT_ADDRESSABLE),
        },
        "before_counts": {
            "requirements": len(requirements.get("requirements") or []),
            "templates_loaded": len(templates),
            "manual_proofs_loaded": len(manual_proofs),
            "live_topology_rows": len(live_rows),
            "live_topology_pairs": len(live_pairs),
            "addressable_rows_loaded": len(addressable_rows),
        },
        "after_counts": {
            "proof_pairs_total": len(proof_pairs),
            "rows_total": sum(len(pair["rows"]) for pair in proof_pairs),
            "pair_status_counts": dict(sorted(status_counts.items())),
            "pair_blocker_class_counts": dict(sorted(blocker_counts.items())),
            "row_missing_counts": dict(sorted(row_missing_counts.items())),
            "strict_missing_counts": dict(sorted(strict_missing_counts.items())),
            "row_readiness_counts": dict(sorted(row_readiness_counts.items())),
            "capture_ready_pairs": sum(1 for pair in proof_pairs if pair["status"] == "capture_ready_missing_manual_proofs"),
            "manual_proof_import_ready_pairs": sum(1 for pair in proof_pairs if pair["status"] == "manual_proofs_ready_for_import"),
            "same_block_executor_ready_pairs": sum(1 for pair in proof_pairs if pair["status"] == "same_block_executor_ready"),
            "closure_candidates": sum(1 for pair in proof_pairs if pair["closure_candidate"]),
        },
        "proof_pairs": proof_pairs,
        "next_actions": [
            "Attach current workspace source_refs, configured topology paths, and concrete proof/harness evidence before treating a pair as ready.",
            "Fill verified addresses, RPC env vars, same-block pins, and expected values for each pair bundle.",
            "Run both row capture commands for a pair so manual_proofs/<row_id>.json exists.",
            "Import both manual proof ids with the emitted import_command_after_manual_proofs.",
            "Run live-topology-proof-executor and only count closure when it returns same-block validated pairs.",
        ],
        "why_no_more_local_closure_safe": (
            "Readiness classification found no full proof pair with concrete address/RPC/block/expected-value, "
            "executed manual proof rows, and exact same-block import. Promoting any pair without those inputs "
            "would be fake live proof."
        ),
        **ADVISORY_POSTURE,
    }


def write_pair_bundles(directory: Path, payload: dict[str, Any]) -> list[str]:
    directory.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for pair in payload.get("proof_pairs") or []:
        pair_id = str(pair.get("proof_pair_id") or "unknown_pair").strip() or "unknown_pair"
        bundle = {
            "schema": "auditooor.live_topology_full_pair_requirements.v1",
            "proof_pair_id": pair_id,
            "requirement_id": pair.get("requirement_id"),
            "status": pair.get("status"),
            "blocker_class": pair.get("blocker_class"),
            "row_ids": pair.get("row_ids") or [],
            "required_contracts": pair.get("required_contracts") or [],
            "missing": pair.get("missing") or [],
            "strict_missing": pair.get("strict_missing") or [],
            "rows": pair.get("rows") or [],
            "safe_execution_order": [
                "resolve verified deployed addresses for both rows",
                "set required RPC env var(s)",
                "pin both rows to one shared block",
                "fill expected values for both topology calls",
                "run capture_command for both rows",
                "run import_command_after_manual_proofs",
                "run executor_command_after_import",
            ],
            "import_command_after_manual_proofs": pair.get("import_command_after_manual_proofs"),
            "executor_command_after_import": pair.get("executor_command_after_import"),
            **ADVISORY_POSTURE,
        }
        path = directory / f"{pair_id}.json"
        write_json(path, bundle)
        written.append(str(path))
    return written


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Live Topology Proof Readiness",
        "",
        "Full-corpus readiness gate for same-block topology proof pairs.",
        "This is not proof; it is the exact map from skeleton pairs to executable/importable blockers.",
        "",
        f"- proof pairs: `{payload['after_counts']['proof_pairs_total']}`",
        f"- rows: `{payload['after_counts']['rows_total']}`",
        f"- closure candidates: `{payload['after_counts']['closure_candidates']}`",
        f"- capture-ready pairs: `{payload['after_counts']['capture_ready_pairs']}`",
        f"- manual-proof import-ready pairs: `{payload['after_counts']['manual_proof_import_ready_pairs']}`",
        f"- same-block executor-ready pairs: `{payload['after_counts']['same_block_executor_ready_pairs']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Pair Status Counts",
        "",
    ]
    for status, count in sorted(payload["after_counts"]["pair_status_counts"].items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Blocker Classes", ""])
    for status, count in sorted(payload["after_counts"]["pair_blocker_class_counts"].items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Row Missing Counts", ""])
    for status, count in sorted(payload["after_counts"]["row_missing_counts"].items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## First 25 Pairs", "", "| Pair | Status | Blocker | Missing |", "|---|---|---|---|"])
    for pair in payload.get("proof_pairs", [])[:25]:
        lines.append(
            f"| `{pair.get('proof_pair_id')}` | `{pair.get('status')}` | "
            f"`{pair.get('blocker_class')}` | `{', '.join(pair.get('missing') or [])}` |"
        )
    lines.extend(["", "## Why No Further Local Closure", "", payload["why_no_more_local_closure_safe"], ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--requirements", type=Path)
    parser.add_argument("--template-dir", type=Path)
    parser.add_argument("--live-topology", type=Path)
    parser.add_argument("--manual-proofs", type=Path)
    parser.add_argument("--addressable-followup", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--no-write-bundles", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-proof-readiness] workspace not found: {workspace}")
        return 2
    requirements_path = resolve_path(workspace, args.requirements, DEFAULT_REQUIREMENTS)
    template_dir = resolve_path(workspace, args.template_dir, DEFAULT_TEMPLATE_DIR)
    live_path = resolve_path(workspace, args.live_topology, DEFAULT_LIVE_TOPOLOGY)
    manual_dir = resolve_path(workspace, args.manual_proofs, DEFAULT_MANUAL_PROOFS)
    addressable_path = resolve_path(workspace, args.addressable_followup, DEFAULT_ADDRESSABLE)
    out_json = resolve_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = resolve_path(workspace, args.out_md, DEFAULT_OUT_MD)
    bundle_dir = resolve_path(workspace, args.bundle_dir, DEFAULT_BUNDLE_DIR)

    payload = build_payload(
        workspace=workspace,
        requirements=load_json(requirements_path, "proof requirements"),
        templates=load_templates(template_dir),
        live=load_json(live_path, "live topology", required=False),
        manual_proofs=load_manual_proofs(manual_dir),
        addressable=load_json(addressable_path, "addressable followup", required=False),
    )
    if not args.no_write_bundles:
        payload["requirement_bundle_dir"] = str(bundle_dir)
        payload["requirement_bundle_files"] = write_pair_bundles(bundle_dir, payload)
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-proof-readiness] OK "
        f"pairs={payload['after_counts']['proof_pairs_total']} "
        f"closure_candidates={payload['after_counts']['closure_candidates']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
