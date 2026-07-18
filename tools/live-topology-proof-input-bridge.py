#!/usr/bin/env python3
"""Prepare exact input-acquisition bundles for live-topology proof pairs.

This runs after ``live-topology-proof-readiness.py``. It does not call RPC,
does not import manual proofs, and never marks a proof pair closed. Its job is
to turn terminal ``missing local input`` pairs into operator/tool-fillable
bundles: per-network RPC/input manifests, per-pair capture forms, and a
manual-proof import preflight summary.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.live_topology_proof_input_bridge.v1"
DEFAULT_READINESS = ".auditooor/live_topology_proof_readiness.json"
DEFAULT_OUT_JSON = ".auditooor/live_topology_proof_input_bridge.json"
DEFAULT_OUT_MD = ".auditooor/live_topology_proof_input_bridge.md"
DEFAULT_BUNDLE_DIR = ".auditooor/live_topology_proof_input_bundles"
ADVISORY_POSTURE = {
    "advisory_only": True,
    "promotion_allowed": False,
    "submission_posture": "NOT_SUBMIT_READY",
    "severity": "none",
    "selected_impact": "",
    "impact_contract_required": True,
}
SOURCE_REF_RE = re.compile(
    r"(?P<path>(?:~|/|\.{1,2}/|[A-Za-z0-9_.-])"
    r"[A-Za-z0-9_./@%+,\-]*\."
    r"(?:sol|vy|go|rs|move|cairo|ts|tsx|js|jsx|py|md|json|yaml|yml|toml))"
    r"(?:(?::|#L)(?P<line>\d+))?"
)
MISSING_TEXT = {"", "n/a", "na", "none", "null", "unknown", "todo", "tbd", "advisory", "advisory_only"}
SOURCE_REF_KEYS = ("source_refs", "source_ref", "file_line", "file_lines", "target_file", "source_file", "source_path")
SOURCE_BLOCKER_KEYS = ("source_ref_blockers", "source_refs_blockers")
TOPOLOGY_REF_KEYS = ("topology_paths", "topology_path", "configured_topology_path", "deployment_topology_path")
TOPOLOGY_BLOCKER_KEYS = ("topology_path_blockers", "topology_paths_blockers")
TOPOLOGY_EVIDENCE_KEYS = (
    "configured_topology_evidence",
    "topology_evidence",
    "deployment_topology",
    "configuration_precondition",
    "configuration_evidence",
)
PROOF_EVIDENCE_KEYS = (
    "concrete_proof_or_harness_evidence",
    "proof_evidence",
    "harness_evidence",
    "execution_contract",
    "execution_manifest",
    "pass_evidence_lines",
    "test_transcript",
    "proof_transcript",
)
PROOF_PATH_KEYS = ("proof_file", "proof_artifact_path", "poc_path", "test_path", "generated_test_path", "harness_path")
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
BRIDGEABLE_PAIR_STATUSES = {"same_block_executor_ready"}
NON_BLOCKING_BLOCKER_CLASSES = {"", "none", "null"}
ADVISORY_REASON = "advisory_only_evidence"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def resolve_path(workspace: Path, path: Path | None, default: str) -> Path:
    candidate = path or Path(default)
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"[live-topology-proof-input-bridge] missing {label}: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"[live-topology-proof-input-bridge] unreadable {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"[live-topology-proof-input-bridge] expected object JSON for {label}: {path}")
    return payload


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value).strip("_") or "unknown"


def truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def is_placeholder(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or text.lower() in MISSING_TEXT or text.startswith("<") or text.endswith(">")


def dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            out.append(text)
            seen.add(text)
    return out


def text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, bool):
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(text_values(item))
        return out
    if isinstance(value, dict):
        out: list[str] = []
        for key in ("path", "ref", "source_ref", "file_line", "value"):
            if key in value:
                out.extend(text_values(value.get(key)))
        if not out:
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
    return dedupe(values)


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
        return {"ref": raw_ref, "current": False, "reason": "missing_current_workspace_source_refs"}
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
    if not resolved.is_file() or (line is not None and not line_exists(resolved, line)):
        return {
            "ref": raw_ref,
            "current": False,
            "reason": "stale_workspace_source_refs",
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


def classify_refs(workspace: Path, refs: list[str]) -> dict[str, list[dict[str, Any]]]:
    resolved = [resolve_workspace_ref(workspace, ref) for ref in refs]
    return {
        "current": [item for item in resolved if item["current"]],
        "stale": [item for item in resolved if not item["current"]],
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
    if value is True:
        return True
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
    if "missing_concrete_proof_or_harness_evidence" in {item for row in payloads for item in row.get("strict_missing") or []}:
        return False
    for payload in payloads:
        for key in PROOF_EVIDENCE_KEYS:
            if value_has_concrete_proof(payload.get(key), workspace):
                return True
        for path_value in collect_values([payload], PROOF_PATH_KEYS):
            if proof_path_exists(workspace, path_value):
                return True
    return False


def has_advisory_marker(payloads: list[dict[str, Any]]) -> bool:
    for payload in payloads:
        if truthy(payload.get("advisory_only")) or truthy(payload.get("advisory")):
            return True
        for key in ("missing", "strict_missing", "operator_inputs_required"):
            if ADVISORY_REASON in {str(item) for item in payload.get(key) or []}:
                return True
        for key in (*PROOF_EVIDENCE_KEYS, *TOPOLOGY_EVIDENCE_KEYS):
            value = payload.get(key)
            if isinstance(value, dict) and (truthy(value.get("advisory_only")) or truthy(value.get("advisory"))):
                return True
    return False


def command_with_candidate(row: dict[str, Any]) -> str | None:
    candidate = str(row.get("candidate_address") or "").strip()
    command = str(row.get("capture_command") or "").strip()
    required = str(row.get("required_address") or "").strip()
    if not candidate or not command:
        return None
    if required and required in command:
        return command.replace(required, candidate)
    return command


def row_input(row: dict[str, Any]) -> dict[str, Any]:
    missing = set(row.get("missing") or [])
    requirements: list[str] = []
    if "missing_verified_address" in missing:
        requirements.append("verified_address")
    if "candidate_address_requires_manual_verification" in missing:
        requirements.append("candidate_address_verification")
    if "missing_rpc" in missing:
        requirements.append("rpc_env_value")
    if "missing_same_block" in missing:
        requirements.append("shared_block")
    if "missing_expected_value" in missing:
        requirements.append("expected_value")
    if "missing_manual_proof" in missing:
        requirements.append("manual_proof_capture")
    if "missing_imported_live_row" in missing or any(item.startswith("imported_live_row_") for item in missing):
        requirements.append("manual_proof_import")

    return {
        "row_id": row.get("row_id"),
        "contract": row.get("contract"),
        "network": row.get("network") or "mainnet",
        "rpc_env_var": row.get("rpc_env_var") or "MAINNET_RPC_URL",
        "candidate_address": row.get("candidate_address"),
        "required_address": row.get("required_address"),
        "required_same_block": row.get("required_same_block"),
        "expected_value": row.get("expected_value"),
        "operator_inputs_required": requirements,
        "missing": sorted(missing),
        "capture_command_template": row.get("capture_command"),
        "capture_command_after_candidate_verification": command_with_candidate(row),
        "manual_import_command": row.get("manual_import_command"),
        "manual_proof_path": row.get("manual_proof_path"),
        "manual_status": row.get("manual_status"),
        "manual_block": row.get("manual_block"),
        "live_status": row.get("live_status"),
        "live_block": row.get("live_block"),
        "strict_missing": sorted(set(row.get("strict_missing") or [])),
        "source_refs": row.get("source_refs") or [],
        "source_ref_blockers": row.get("source_ref_blockers") or [],
        "topology_paths": row.get("topology_paths") or [],
        "topology_path_blockers": row.get("topology_path_blockers") or [],
        "configured_topology_evidence": row.get("configured_topology_evidence") or [],
        "concrete_proof_or_harness_evidence": bool(row.get("concrete_proof_or_harness_evidence")),
        "base_executor_ready": bool(row.get("base_executor_ready")),
        "capture_ready": bool(row.get("capture_ready")),
        "import_ready": bool(row.get("import_ready")),
        "executor_ready": bool(row.get("executor_ready")),
    }


def manual_preflight(pair_rows: list[dict[str, Any]]) -> dict[str, Any]:
    row_ids = [str(row.get("row_id") or "") for row in pair_rows if row.get("row_id")]
    import_ready = [row["row_id"] for row in pair_rows if row.get("import_ready")]
    invalid: dict[str, list[str]] = {}
    for row in pair_rows:
        problems = [
            item
            for item in row.get("missing") or []
            if item.startswith("manual_proof_") or item == "missing_manual_proof"
        ]
        if problems:
            invalid[str(row.get("row_id") or "unknown")] = sorted(set(problems))
    blocks = {str(row.get("manual_block") or "").strip() for row in pair_rows if row.get("manual_block")}
    return {
        "row_ids": row_ids,
        "import_ready_row_ids": import_ready,
        "invalid_or_missing_manual_proof_rows": invalid,
        "same_block_manual_proofs": len(blocks) == 1 and len(import_ready) == len(row_ids) and bool(row_ids),
        "manual_blocks_seen": sorted(blocks),
    }


def row_bridge_reasons(workspace: Path, row: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    source_blockers = collect_values([row], SOURCE_BLOCKER_KEYS)
    source_refs = collect_values([row], SOURCE_REF_KEYS)
    source_status = classify_refs(workspace, source_refs)
    if source_blockers or source_status["stale"]:
        reasons.append("stale_workspace_source_refs")
    if not source_refs or not source_status["current"]:
        reasons.append("missing_current_workspace_source_refs")

    topology_blockers = collect_values([row], TOPOLOGY_BLOCKER_KEYS)
    topology_refs = collect_values([row], TOPOLOGY_REF_KEYS)
    topology_status = classify_refs(workspace, topology_refs)
    topology_evidence = [
        value
        for value in collect_values([row], TOPOLOGY_EVIDENCE_KEYS)
        if not is_placeholder(value)
    ]
    if topology_blockers or topology_status["stale"]:
        reasons.append("stale_topology_path")
    if not topology_evidence and not topology_status["current"]:
        reasons.append("missing_configured_topology_evidence")

    if has_advisory_marker([row]):
        reasons.append(ADVISORY_REASON)
    for key in ("missing", "strict_missing"):
        for item in row.get(key) or []:
            reasons.append(str(item))
    return dedupe(reasons)


def pair_bridge_reasons(workspace: Path, pair: dict[str, Any], rows: list[dict[str, Any]]) -> list[str]:
    payloads = [pair, *rows]
    reasons: list[str] = []
    status = str(pair.get("status") or pair.get("status_before_bridge") or "").strip()
    if status not in BRIDGEABLE_PAIR_STATUSES:
        reasons.append(f"status_not_bridgeable:{status or 'unknown'}")
    blocker_class = str(pair.get("blocker_class") or pair.get("blocker_class_before_bridge") or "").strip()
    if blocker_class.lower() not in NON_BLOCKING_BLOCKER_CLASSES:
        reasons.append(blocker_class)
    for key in ("missing", "strict_missing"):
        for item in pair.get(key) or []:
            reasons.append(str(item))
    if has_advisory_marker(payloads):
        reasons.append(ADVISORY_REASON)
    if not has_concrete_proof_or_harness(payloads, workspace):
        reasons.append("missing_concrete_proof_or_harness_evidence")
    return dedupe(reasons)


def bridge_decision(reasons: list[str]) -> dict[str, Any]:
    clean = dedupe(reasons)
    bridged = not clean
    return {
        "bridged": bridged,
        "status": "bridged" if bridged else "not_bridged",
        "reasons": clean,
    }


def attach_bridge_decisions(
    *,
    workspace: Path,
    pair: dict[str, Any],
    rows: list[dict[str, Any]],
) -> tuple[dict[str, Any], Counter[str], Counter[str]]:
    row_reason_counts: Counter[str] = Counter()
    row_status_counts: Counter[str] = Counter()
    row_reasons_by_id: dict[str, list[str]] = {}
    pair_reasons = pair_bridge_reasons(workspace, pair, rows)
    for row in rows:
        row_reasons = row_bridge_reasons(workspace, row)
        if pair_reasons:
            row_reasons.extend(pair_reasons)
        row_reasons_by_id[str(row.get("row_id") or "")] = dedupe(row_reasons)

    if any(row_reasons_by_id.values()):
        pair_reasons.append("proof_pair_has_non_bridgeable_rows")
    pair_reasons.extend(reason for reasons in row_reasons_by_id.values() for reason in reasons)
    pair_decision = bridge_decision(pair_reasons)

    for row in rows:
        row_id = str(row.get("row_id") or "")
        row_decision = bridge_decision(row_reasons_by_id.get(row_id, []))
        if pair_decision["bridged"]:
            row_decision = bridge_decision([])
        elif row_decision["bridged"]:
            row_decision = bridge_decision(["proof_pair_not_bridgeable"])
        row["proof_input_bridge"] = row_decision
        row["bridge_status"] = row_decision["status"]
        row["bridge_reasons"] = row_decision["reasons"]
        row_status_counts[row_decision["status"]] += 1
        row_reason_counts.update(row_decision["reasons"])

    return pair_decision, row_status_counts, row_reason_counts


def acquisition_class(pair: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    missing = set(pair.get("missing") or [])
    if pair.get("status") == "same_block_executor_ready":
        return "executor_ready_no_input_acquisition_needed"
    if pair.get("status") == "manual_proofs_ready_for_import":
        return "ready_to_import_manual_proofs"
    if pair.get("status") == "capture_ready_missing_manual_proofs":
        return "ready_to_capture_manual_proofs"
    if any(item.startswith("manual_proof_") for item in missing):
        return "manual_proof_validation_required"
    candidate_rows = sum(1 for row in rows if row.get("candidate_address"))
    missing_verified_rows = sum(1 for row in rows if "missing_verified_address" in set(row.get("missing") or []))
    if candidate_rows and missing_verified_rows:
        return "partial_candidate_address_needs_counterpart"
    if candidate_rows:
        return "candidate_addresses_need_runtime_inputs"
    if "missing_verified_address" in missing:
        return "address_discovery_required"
    if {"missing_rpc", "missing_same_block", "missing_expected_value"} & missing:
        return "runtime_input_binding_required"
    return "unknown_input_acquisition_required"


def build_payload(workspace: Path, readiness: dict[str, Any]) -> dict[str, Any]:
    pair_items: list[dict[str, Any]] = []
    class_counts: Counter[str] = Counter()
    network_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rpc_env_vars: Counter[str] = Counter()
    operator_input_counts: Counter[str] = Counter()
    pair_status_counts: Counter[str] = Counter()
    manual_preflight_counts: Counter[str] = Counter()
    pair_bridge_status_counts: Counter[str] = Counter()
    row_bridge_status_counts: Counter[str] = Counter()
    non_bridged_reason_counts: Counter[str] = Counter()

    for pair in readiness.get("proof_pairs") or []:
        if not isinstance(pair, dict):
            continue
        row_inputs = [row_input(row) for row in pair.get("rows") or [] if isinstance(row, dict)]
        klass = acquisition_class(pair, row_inputs)
        pair_bridge, row_statuses, row_reasons = attach_bridge_decisions(
            workspace=workspace,
            pair=pair,
            rows=row_inputs,
        )
        class_counts[klass] += 1
        pair_status_counts[str(pair.get("status") or "unknown")] += 1
        pair_bridge_status_counts[pair_bridge["status"]] += 1
        row_bridge_status_counts.update(row_statuses)
        non_bridged_reason_counts.update(pair_bridge["reasons"])
        non_bridged_reason_counts.update(row_reasons)
        for row in row_inputs:
            network_rows[str(row.get("network") or "mainnet")].append(
                {
                    "proof_pair_id": pair.get("proof_pair_id"),
                    "row_id": row.get("row_id"),
                    "contract": row.get("contract"),
                    "rpc_env_var": row.get("rpc_env_var"),
                    "candidate_address": row.get("candidate_address"),
                    "operator_inputs_required": row.get("operator_inputs_required") or [],
                    "bridge_status": row.get("bridge_status"),
                    "bridge_reasons": row.get("bridge_reasons") or [],
                }
            )
            rpc_env_vars[str(row.get("rpc_env_var") or "MAINNET_RPC_URL")] += 1
            operator_input_counts.update(row.get("operator_inputs_required") or [])

        preflight = manual_preflight(row_inputs)
        if preflight["same_block_manual_proofs"]:
            manual_preflight_counts["same_block_manual_proofs_ready"] += 1
        elif preflight["import_ready_row_ids"]:
            manual_preflight_counts["partial_manual_proofs_ready"] += 1
        else:
            manual_preflight_counts["manual_proofs_missing_or_invalid"] += 1

        pair_items.append(
            {
                "proof_pair_id": pair.get("proof_pair_id"),
                "requirement_id": pair.get("requirement_id"),
                "status_before_bridge": pair.get("status"),
                "blocker_class_before_bridge": pair.get("blocker_class"),
                "input_acquisition_class": klass,
                "row_ids": pair.get("row_ids") or [],
                "required_contracts": pair.get("required_contracts") or [],
                "rows": row_inputs,
                "manual_import_preflight": preflight,
                "proof_input_bridge": pair_bridge,
                "bridge_status": pair_bridge["status"],
                "bridge_reasons": pair_bridge["reasons"],
                "pair_import_command_after_inputs": pair.get("import_command_after_manual_proofs"),
                "executor_command_after_import": pair.get("executor_command_after_import"),
                "safe_execution_order": [
                    "fill per-row verified_address values or verify candidate_address values",
                    "set the required RPC env var for every row network",
                    "pin all rows in the pair to one explicit shared block",
                    "fill each expected value from deployment/topology source evidence",
                    "run capture_command_template or capture_command_after_candidate_verification for both rows",
                    "preflight manual_proofs/<row_id>.json against this bundle",
                    "import exactly both row ids, then run the live-topology proof executor",
                ],
                **ADVISORY_POSTURE,
            }
        )

    per_network = []
    for network, rows in sorted(network_rows.items()):
        env_vars = sorted({str(row.get("rpc_env_var") or "MAINNET_RPC_URL") for row in rows})
        per_network.append(
            {
                "network": network,
                "row_count": len(rows),
                "pair_count": len({str(row.get("proof_pair_id") or "") for row in rows}),
                "rpc_env_vars": env_vars,
                "env_template": [f"{env_var}=<rpc-url-for-{network}>" for env_var in env_vars],
                "candidate_address_rows": sum(1 for row in rows if row.get("candidate_address")),
                "rows": rows,
            }
        )

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "generated_at": now_iso(),
        "source_readiness": readiness.get("inputs", {}).get("live_topology") or str(workspace / DEFAULT_READINESS),
        "source_readiness_schema": readiness.get("schema"),
        "summary": {
            "proof_pairs_total": len(pair_items),
            "rows_total": sum(len(pair["rows"]) for pair in pair_items),
            "proof_pairs_closed": 0,
            "proof_pairs_promoted": 0,
            "input_acquisition_class_counts": dict(sorted(class_counts.items())),
            "pair_status_counts": dict(sorted(pair_status_counts.items())),
            "manual_import_preflight_counts": dict(sorted(manual_preflight_counts.items())),
            "operator_input_counts": dict(sorted(operator_input_counts.items())),
            "rpc_env_var_counts": dict(sorted(rpc_env_vars.items())),
            "per_network_counts": {item["network"]: item["row_count"] for item in per_network},
            "proof_pairs_bridged": pair_bridge_status_counts.get("bridged", 0),
            "proof_pairs_not_bridged": pair_bridge_status_counts.get("not_bridged", 0),
            "rows_bridged": row_bridge_status_counts.get("bridged", 0),
            "rows_not_bridged": row_bridge_status_counts.get("not_bridged", 0),
            "proof_input_bridge_status_counts": dict(sorted(pair_bridge_status_counts.items())),
            "row_bridge_status_counts": dict(sorted(row_bridge_status_counts.items())),
            "non_bridged_reason_counts": dict(sorted(non_bridged_reason_counts.items())),
        },
        "per_network_input_bundles": per_network,
        "proof_pairs": pair_items,
        "why_no_more_local_closure_safe": (
            "The bridge prepared exact capture/import inputs but found no pair with executed, imported, "
            "same-block topology-relation evidence. Claiming proof still requires real RPC-backed/manual "
            "captures and live-topology-proof-executor validation."
        ),
        **ADVISORY_POSTURE,
    }


def write_bundles(bundle_dir: Path, payload: dict[str, Any]) -> dict[str, list[str]]:
    pair_dir = bundle_dir / "pairs"
    network_dir = bundle_dir / "networks"
    pair_dir.mkdir(parents=True, exist_ok=True)
    network_dir.mkdir(parents=True, exist_ok=True)
    pair_files: list[str] = []
    network_files: list[str] = []
    for pair in payload.get("proof_pairs") or []:
        pair_id = str(pair.get("proof_pair_id") or "unknown_pair")
        path = pair_dir / f"{safe_name(pair_id)}.json"
        write_json(path, pair)
        pair_files.append(str(path))
    for bundle in payload.get("per_network_input_bundles") or []:
        network = str(bundle.get("network") or "unknown")
        path = network_dir / f"{safe_name(network)}.json"
        write_json(path, bundle)
        network_files.append(str(path))
    return {"pair_bundle_files": pair_files, "network_bundle_files": network_files}


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Live Topology Proof Input Bridge",
        "",
        "Exact input-acquisition bridge after proof-readiness classification.",
        "This is not proof and does not promote any pair.",
        "",
        f"- proof pairs processed: `{summary['proof_pairs_total']}`",
        f"- rows processed: `{summary['rows_total']}`",
        f"- proof pairs closed: `{summary['proof_pairs_closed']}`",
        f"- proof pairs bridged: `{summary['proof_pairs_bridged']}`",
        f"- proof pairs not bridged: `{summary['proof_pairs_not_bridged']}`",
        f"- rows bridged: `{summary['rows_bridged']}`",
        f"- rows not bridged: `{summary['rows_not_bridged']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Input Acquisition Classes",
        "",
    ]
    for name, count in summary["input_acquisition_class_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Operator Inputs Required", ""])
    for name, count in summary["operator_input_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Manual Import Preflight", ""])
    for name, count in summary["manual_import_preflight_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Non-Bridged Reasons", ""])
    for name, count in summary["non_bridged_reason_counts"].items():
        lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Per-Network Bundles", ""])
    for network, count in summary["per_network_counts"].items():
        lines.append(f"- `{network}`: {count} rows")
    lines.extend(
        [
            "",
            "## First 25 Pairs",
            "",
            "| Pair | Class | Bridge | Reasons | Rows |",
            "|---|---|---|---|---|",
        ]
    )
    for pair in payload.get("proof_pairs", [])[:25]:
        lines.append(
            f"| `{pair.get('proof_pair_id')}` | `{pair.get('input_acquisition_class')}` | "
            f"`{pair.get('bridge_status')}` | `{', '.join(pair.get('bridge_reasons') or [])}` | "
            f"`{', '.join(pair.get('row_ids') or [])}` |"
        )
    lines.extend(["", "## Why No Further Local Closure", "", payload["why_no_more_local_closure_safe"], ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--readiness", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--bundle-dir", type=Path)
    parser.add_argument("--no-write-bundles", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[live-topology-proof-input-bridge] workspace not found: {workspace}")
        return 2
    readiness_path = resolve_path(workspace, args.readiness, DEFAULT_READINESS)
    out_json = resolve_path(workspace, args.out_json, DEFAULT_OUT_JSON)
    out_md = resolve_path(workspace, args.out_md, DEFAULT_OUT_MD)
    bundle_dir = resolve_path(workspace, args.bundle_dir, DEFAULT_BUNDLE_DIR)

    payload = build_payload(workspace, load_json(readiness_path, "proof readiness"))
    if not args.no_write_bundles:
        payload["bundle_dir"] = str(bundle_dir)
        payload["bundle_files"] = write_bundles(bundle_dir, payload)
    write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        "[live-topology-proof-input-bridge] OK "
        f"pairs={payload['summary']['proof_pairs_total']} "
        f"closed={payload['summary']['proof_pairs_closed']} json={out_json}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
