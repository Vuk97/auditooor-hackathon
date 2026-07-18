#!/usr/bin/env python3
"""Fail-closed executor state for Pipeline V2 manifests.

The executor does not execute targets.  It only issues per-attempt authority,
validates terminal receipts, and persists the canonical ordered state.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import secrets
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


def _load_module(name: str, filename: str) -> Any:
    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


_manifest_validator = _load_module("_pipeline_manifest_validate", "pipeline-manifest-validate.py")
_receipt = _load_module("_pipeline_receipt", "pipeline-receipt.py")
_applicability = _load_module("_pipeline_state_applicability", "pipeline-applicability.py")

stable_hash = _receipt.stable_hash
PROVENANCE_FIELDS = _receipt.PROVENANCE_FIELDS
TERMINAL_SUCCESS_STATES = frozenset({"succeeded", "not_applicable"})
TERMINAL_RECEIPT_STATES = frozenset({"succeeded", "not_applicable", "failed"})
STEP_STATES = frozenset({"pending", "running", "succeeded", "not_applicable", "failed", "invalidated"})
SCHEMA = "auditooor.pipeline_state.v2"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class StateMachineError(ValueError):
    """Raised for a fail-closed transition with stable diagnostic codes."""

    def __init__(self, *diagnostics: str):
        self.diagnostics = tuple(sorted(set(diagnostics)))
        super().__init__(", ".join(self.diagnostics))


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _state_hash(state: Mapping[str, Any]) -> str:
    body = dict(state)
    body.pop("state_self_hash", None)
    return stable_hash(_canonical(body))


def _seal(state: dict[str, Any]) -> dict[str, Any]:
    state["state_self_hash"] = _state_hash(state)
    return state


def _manifest_hash(manifest: Mapping[str, Any]) -> str:
    return stable_hash(_canonical(manifest))


def _manifest_context(manifest: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    result = _manifest_validator.validate_manifest(manifest)
    if not result["valid"]:
        raise StateMachineError("invalid_manifest")
    assert isinstance(manifest, dict)
    steps = manifest["steps"]
    return manifest, {step["step_id"]: step for step in steps}


def _require_hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise StateMachineError(code)
    return value


def _contains_raw_token(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if key in {"token", "active_token", "raw_token", "step_token", "active_step_token", "raw_step_token"}:
                return True
            if _contains_raw_token(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_raw_token(item) for item in value)
    return False


def _output_artifact_errors(value: Any, name: str) -> list[str]:
    errors: list[str] = []
    _receipt._validate_artifact_list(value, name, errors, outputs=True)
    return errors


def _valid_optional_hash(value: Any) -> bool:
    return value is None or (isinstance(value, str) and bool(HEX64_RE.fullmatch(value)))


def _step_entry_diagnostics(step_id: str, entry: Any) -> list[str]:
    prefix = f"state_step_{step_id}"
    if not isinstance(entry, dict):
        return [f"{prefix}_not_object"]
    errors: list[str] = []
    if entry.get("state") not in STEP_STATES:
        errors.append(f"{prefix}_invalid_state")
    for field in ("order_index", "run_sequence"):
        if isinstance(entry.get(field), bool) or not isinstance(entry.get(field), int) or entry[field] < 0:
            errors.append(f"{prefix}_invalid_{field}")
    attempt = entry.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
        errors.append(f"{prefix}_invalid_attempt")
    active_token = entry.get("active_token_sha256")
    if not _valid_optional_hash(active_token):
        errors.append(f"{prefix}_invalid_active_token_sha256")
    current_receipt_id = entry.get("current_receipt_id")
    if not _valid_optional_hash(current_receipt_id):
        errors.append(f"{prefix}_invalid_current_receipt_id")
    output_fingerprint = entry.get("output_fingerprint")
    if not _valid_optional_hash(output_fingerprint):
        errors.append(f"{prefix}_invalid_output_fingerprint")
    current_outputs = entry.get("current_output_artifacts")
    errors.extend(_output_artifact_errors(current_outputs, f"{prefix}_current_output_artifacts"))
    history = entry.get("receipt_history")
    if not isinstance(history, list):
        return errors + [f"{prefix}_invalid_receipt_history"]
    history_ids: set[str] = set()
    expected_history = []
    for index, record in enumerate(history):
        record_prefix = f"{prefix}_history_{index}"
        if not isinstance(record, dict):
            errors.append(f"{record_prefix}_not_object")
            continue
        receipt_id = record.get("receipt_id")
        if not isinstance(receipt_id, str) or not HEX64_RE.fullmatch(receipt_id):
            errors.append(f"{record_prefix}_invalid_receipt_id")
        elif receipt_id in history_ids:
            errors.append(f"{prefix}_duplicate_history_receipt_id")
        else:
            history_ids.add(receipt_id)
        if record.get("status") not in TERMINAL_RECEIPT_STATES:
            errors.append(f"{record_prefix}_invalid_status")
        record_attempt = record.get("attempt")
        if isinstance(record_attempt, bool) or not isinstance(record_attempt, int) or record_attempt < 1:
            errors.append(f"{record_prefix}_invalid_attempt")
        if not isinstance(record.get("output_fingerprint"), str) or not HEX64_RE.fullmatch(record["output_fingerprint"]):
            errors.append(f"{record_prefix}_invalid_output_fingerprint")
        record_outputs = record.get("output_artifacts")
        errors.extend(_output_artifact_errors(record_outputs, f"{record_prefix}_output_artifacts"))
        if isinstance(record_outputs, list) and record.get("output_fingerprint") != stable_hash(record_outputs):
            errors.append(f"{record_prefix}_output_fingerprint_mismatch")
        expected_history.append(record)
    if history and isinstance(attempt, int) and not isinstance(attempt, bool):
        history_attempts = [record.get("attempt") for record in history if isinstance(record, dict)]
        if any(isinstance(value, int) and not isinstance(value, bool) and value > attempt for value in history_attempts):
            errors.append(f"{prefix}_attempt_precedes_history")
    if all(
        isinstance(item.get("attempt"), int)
        and not isinstance(item.get("attempt"), bool)
        and isinstance(item.get("receipt_id"), str)
        for item in expected_history
    ):
        if history != sorted(expected_history, key=lambda item: (item["attempt"], item["receipt_id"])):
            errors.append(f"{prefix}_nondeterministic_receipt_history")
    current_record = _history_record(entry, current_receipt_id) if isinstance(current_receipt_id, str) else None
    current_state = entry.get("state")
    if current_state == "running":
        valid_attempt = isinstance(attempt, int) and not isinstance(attempt, bool) and attempt >= 1
        if not valid_attempt or not isinstance(active_token, str) or current_receipt_id is not None or current_outputs != [] or output_fingerprint is not None:
            errors.append(f"{prefix}_running_state_inconsistent")
    elif current_state in TERMINAL_SUCCESS_STATES:
        if active_token is not None or current_record is None or current_record.get("status") != current_state:
            errors.append(f"{prefix}_current_receipt_inconsistent")
        if current_record is not None and current_outputs != current_record.get("output_artifacts"):
            errors.append(f"{prefix}_current_outputs_history_mismatch")
        if isinstance(current_outputs, list) and output_fingerprint != stable_hash(current_outputs):
            errors.append(f"{prefix}_current_output_fingerprint_mismatch")
    else:
        if active_token is not None or current_receipt_id is not None or current_outputs != [] or output_fingerprint is not None:
            errors.append(f"{prefix}_noncanonical_state_inconsistent")
    return errors


def _state_diagnostics(state: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(state, dict):
        return ["state_not_json_object"]
    if state.get("schema") != SCHEMA:
        errors.append("invalid_state_schema")
    if not isinstance(state.get("run_id"), str) or not state["run_id"].strip():
        errors.append("invalid_run_id")
    for field in PROVENANCE_FIELDS:
        if not isinstance(state.get(field), str) or not HEX64_RE.fullmatch(state[field]):
            errors.append(f"invalid_{field}")
    if isinstance(state.get("expected_step_count"), bool) or not isinstance(state.get("expected_step_count"), int) or state.get("expected_step_count", 0) <= 0:
        errors.append("invalid_expected_step_count")
    steps = state.get("steps")
    if not isinstance(steps, dict):
        errors.append("invalid_state_steps")
    elif isinstance(state.get("expected_step_count"), int) and len(steps) != state["expected_step_count"]:
        errors.append("state_step_count_mismatch")
    elif isinstance(state.get("expected_step_count"), int):
        order_indexes: list[int] = []
        run_sequences: list[int] = []
        for step_id, entry in steps.items():
            if not isinstance(step_id, str) or not step_id.strip():
                errors.append("invalid_state_step_id")
                continue
            errors.extend(_step_entry_diagnostics(step_id, entry))
            if isinstance(entry, dict) and isinstance(entry.get("order_index"), int) and not isinstance(entry.get("order_index"), bool):
                order_indexes.append(entry["order_index"])
            if isinstance(entry, dict) and isinstance(entry.get("run_sequence"), int) and not isinstance(entry.get("run_sequence"), bool):
                run_sequences.append(entry["run_sequence"])
        expected_indexes = list(range(state["expected_step_count"]))
        if sorted(order_indexes) != expected_indexes:
            errors.append("state_order_indexes_not_contiguous")
        if sorted(run_sequences) != expected_indexes:
            errors.append("state_run_sequences_not_contiguous")
    invalidation_history = state.get("invalidation_history")
    if not isinstance(invalidation_history, list):
        errors.append("invalid_invalidation_history")
    else:
        for index, record in enumerate(invalidation_history):
            prefix = f"invalidation_history_{index}"
            if not isinstance(record, dict):
                errors.append(f"{prefix}_not_object")
                continue
            if not isinstance(record.get("source_step_id"), str) or not record["source_step_id"].strip():
                errors.append(f"{prefix}_invalid_source_step_id")
            elif isinstance(steps, dict) and record["source_step_id"] not in steps:
                errors.append(f"{prefix}_unknown_source_step_id")
            if not isinstance(record.get("step_id"), str) or not record["step_id"].strip():
                errors.append(f"{prefix}_invalid_step_id")
            elif isinstance(steps, dict) and record["step_id"] not in steps:
                errors.append(f"{prefix}_unknown_step_id")
            if record.get("prior_state") not in STEP_STATES:
                errors.append(f"{prefix}_invalid_prior_state")
            if not _valid_optional_hash(record.get("prior_current_receipt_id")):
                errors.append(f"{prefix}_invalid_prior_current_receipt_id")
            if not isinstance(record.get("reason"), str) or not record["reason"].strip():
                errors.append(f"{prefix}_invalid_reason")
    if _contains_raw_token(state):
        errors.append("raw_step_token_persisted")
    if not isinstance(state.get("state_self_hash"), str) or not HEX64_RE.fullmatch(state["state_self_hash"]):
        errors.append("invalid_state_self_hash")
    elif _state_hash(state) != state["state_self_hash"]:
        errors.append("state_self_hash_mismatch")
    return sorted(set(errors))


def validate_state(state: Any) -> tuple[bool, list[str]]:
    """Validate only the durable state envelope and its self-hash."""

    errors = _state_diagnostics(state)
    return not errors, errors


def _require_state(state: dict[str, Any]) -> None:
    ok, errors = validate_state(state)
    if not ok:
        raise StateMachineError(*errors)


def _baseline_values(
    manifest: Mapping[str, Any],
    *,
    workspace_identity_sha256: str,
    source_snapshot_sha256: str,
    scope_sha256: str,
    severity_sha256: str,
    targets_sha256: str,
    program_rules_sha256: str,
    pipeline_tooling_sha256: str,
) -> dict[str, str]:
    values = {
        "manifest_sha256": _manifest_hash(manifest),
        "workspace_identity_sha256": workspace_identity_sha256,
        "source_snapshot_sha256": source_snapshot_sha256,
        "scope_sha256": scope_sha256,
        "severity_sha256": severity_sha256,
        "targets_sha256": targets_sha256,
        "program_rules_sha256": program_rules_sha256,
        "pipeline_tooling_sha256": pipeline_tooling_sha256,
    }
    return {field: _require_hash(values[field], f"invalid_{field}") for field in PROVENANCE_FIELDS}


def initialize_state(
    manifest: Any,
    *,
    run_id: str,
    workspace_identity_sha256: str,
    source_snapshot_sha256: str,
    scope_sha256: str,
    severity_sha256: str,
    targets_sha256: str,
    program_rules_sha256: str,
    pipeline_tooling_sha256: str,
) -> dict[str, Any]:
    """Create a new canonical state from a statically valid V2 manifest."""

    checked_manifest, by_id = _manifest_context(manifest)
    if not isinstance(run_id, str) or not run_id.strip():
        raise StateMachineError("invalid_run_id")
    baselines = _baseline_values(
        checked_manifest,
        workspace_identity_sha256=workspace_identity_sha256,
        source_snapshot_sha256=source_snapshot_sha256,
        scope_sha256=scope_sha256,
        severity_sha256=severity_sha256,
        targets_sha256=targets_sha256,
        program_rules_sha256=program_rules_sha256,
        pipeline_tooling_sha256=pipeline_tooling_sha256,
    )
    entries: dict[str, dict[str, Any]] = {}
    for step_id, step in sorted(by_id.items(), key=lambda item: item[1]["run_sequence"]):
        entries[step_id] = {
            "order_index": step["order_index"],
            "run_sequence": step["run_sequence"],
            "state": "pending",
            "attempt": 0,
            "active_token_sha256": None,
            "current_receipt_id": None,
            "receipt_history": [],
            "output_fingerprint": None,
            "current_output_artifacts": [],
        }
    return _seal(
        {
            "schema": SCHEMA,
            "run_id": run_id.strip(),
            **baselines,
            "expected_step_count": checked_manifest["expected_step_count"],
            "steps": entries,
            "invalidation_history": [],
        }
    )


def _require_manifest_match(state: dict[str, Any], manifest: Any) -> dict[str, dict[str, Any]]:
    checked_manifest, by_id = _manifest_context(manifest)
    if state["manifest_sha256"] != _manifest_hash(checked_manifest):
        raise StateMachineError("manifest_sha256_mismatch")
    if state["expected_step_count"] != checked_manifest["expected_step_count"]:
        raise StateMachineError("expected_step_count_mismatch")
    if set(state["steps"]) != set(by_id):
        raise StateMachineError("state_manifest_step_set_mismatch")
    for step_id, step in by_id.items():
        entry = state["steps"][step_id]
        if entry.get("order_index") != step["order_index"] or entry.get("run_sequence") != step["run_sequence"]:
            raise StateMachineError("state_manifest_step_contract_mismatch")
    return by_id


def resume_state(
    state: dict[str, Any],
    manifest: Any,
    *,
    run_id: str,
    workspace_identity_sha256: str,
    source_snapshot_sha256: str,
    scope_sha256: str,
    severity_sha256: str,
    targets_sha256: str,
    program_rules_sha256: str,
    pipeline_tooling_sha256: str,
) -> dict[str, Any]:
    """Verify state self-integrity and every immutable resume baseline."""

    _require_state(state)
    by_id = _require_manifest_match(state, manifest)
    if state["run_id"] != run_id:
        raise StateMachineError("run_id_mismatch")
    baselines = _baseline_values(
        manifest,
        workspace_identity_sha256=workspace_identity_sha256,
        source_snapshot_sha256=source_snapshot_sha256,
        scope_sha256=scope_sha256,
        severity_sha256=severity_sha256,
        targets_sha256=targets_sha256,
        program_rules_sha256=program_rules_sha256,
        pipeline_tooling_sha256=pipeline_tooling_sha256,
    )
    for field, value in baselines.items():
        if state[field] != value:
            raise StateMachineError(f"{field}_mismatch")
    return state


def _history_record(entry: Mapping[str, Any], receipt_id: str) -> dict[str, Any] | None:
    for record in entry.get("receipt_history", []):
        if isinstance(record, dict) and record.get("receipt_id") == receipt_id:
            return record
    return None


def _has_current_terminal_receipt(entry: Mapping[str, Any]) -> bool:
    current_id = entry.get("current_receipt_id")
    record = _history_record(entry, current_id) if isinstance(current_id, str) else None
    return (
        entry.get("state") in TERMINAL_SUCCESS_STATES
        and record is not None
        and record.get("status") == entry.get("state")
        and isinstance(current_id, str)
        and bool(HEX64_RE.fullmatch(current_id))
    )


def _startable(state: dict[str, Any], by_id: dict[str, dict[str, Any]], step_id: str) -> None:
    if step_id not in by_id:
        raise StateMachineError("unknown_step")
    entry = state["steps"][step_id]
    if entry.get("state") not in {"pending", "failed", "invalidated"}:
        raise StateMachineError("step_not_startable")
    sequence = by_id[step_id]["run_sequence"]
    for earlier_id, earlier_step in by_id.items():
        if earlier_step["run_sequence"] < sequence:
            earlier = state["steps"][earlier_id]
            if earlier.get("state") not in TERMINAL_SUCCESS_STATES:
                raise StateMachineError("earlier_run_sequence_blocks")
            if not _has_current_terminal_receipt(earlier):
                raise StateMachineError("earlier_step_missing_current_receipt")
    for predecessor in by_id[step_id]["depends_on"]:
        if not _has_current_terminal_receipt(state["steps"][predecessor]):
            raise StateMachineError("predecessor_missing_current_terminal_receipt")


def start_step(state: dict[str, Any], manifest: Any, step_id: str) -> str:
    """Move one ordered step to running and return its raw one-time token."""

    _require_state(state)
    by_id = _require_manifest_match(state, manifest)
    _startable(state, by_id, step_id)
    entry = state["steps"][step_id]
    token = secrets.token_hex(32)
    entry["attempt"] += 1
    entry["state"] = "running"
    entry["active_token_sha256"] = stable_hash(token)
    entry["current_receipt_id"] = None
    entry["output_fingerprint"] = None
    entry["current_output_artifacts"] = []
    _seal(state)
    return token


def _current_dependency_receipt_ids(state: Mapping[str, Any], step: Mapping[str, Any]) -> list[str]:
    return sorted(state["steps"][step_id]["current_receipt_id"] for step_id in step["depends_on"])


def _artifact_key(row: Mapping[str, Any]) -> tuple[str, str, str, int]:
    return (row["artifact_contract"], row["path"], row["sha256"], row["size"])


def _validate_typed_artifact_joins(
    state: Mapping[str, Any],
    by_id: Mapping[str, Mapping[str, Any]],
    step: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> None:
    status = receipt["status"]
    inputs = receipt["input_artifacts"]
    outputs = receipt["output_artifacts"]
    if status == "not_applicable":
        if inputs or outputs:
            raise StateMachineError("not_applicable_has_artifacts")
        return
    input_contracts = {row["artifact_contract"] for row in inputs}
    expected_inputs = set(step["consumes"])
    if input_contracts != expected_inputs:
        raise StateMachineError("receipt_input_contract_set_mismatch")
    output_contracts = {row["artifact_contract"] for row in outputs}
    expected_outputs = set(step["produces"])
    if status == "succeeded" and output_contracts != expected_outputs:
        raise StateMachineError("receipt_output_contract_set_mismatch")
    if status == "failed" and not output_contracts.issubset(expected_outputs):
        raise StateMachineError("receipt_failed_output_contract_unknown")
    producer_ids_by_contract: dict[str, list[str]] = {}
    for producer_id, producer_step in by_id.items():
        for artifact_contract in producer_step["produces"]:
            producer_ids_by_contract.setdefault(artifact_contract, []).append(producer_id)
    for input_row in inputs:
        contract = input_row["artifact_contract"]
        candidate_rows: list[Mapping[str, Any]] = []
        for producer_id in producer_ids_by_contract.get(contract, []):
            producer_entry = state["steps"][producer_id]
            if not _has_current_terminal_receipt(producer_entry):
                continue
            candidate_rows.extend(producer_entry["current_output_artifacts"])
        if _artifact_key(input_row) not in {_artifact_key(row) for row in candidate_rows}:
            raise StateMachineError("receipt_input_artifact_not_current_producer_output")


def accept_receipt(state: dict[str, Any], manifest: Any, receipt: Any, *, workspace: str | Path) -> None:
    """Accept exactly one executor-authorized terminal receipt for a running step."""

    _require_state(state)
    by_id = _require_manifest_match(state, manifest)
    ok, receipt_errors = _receipt.validate_terminal_receipt(receipt)
    if not ok:
        raise StateMachineError("invalid_terminal_receipt", *receipt_errors)
    assert isinstance(receipt, dict)
    step_id = receipt["step_id"]
    if step_id not in by_id:
        raise StateMachineError("unknown_receipt_step")
    step = by_id[step_id]
    entry = state["steps"][step_id]
    if entry.get("state") != "running":
        raise StateMachineError("receipt_step_not_running")
    expected: dict[str, Any] = {
        "run_id": state["run_id"],
        **{field: state[field] for field in PROVENANCE_FIELDS},
        "step_id": step_id,
        "order_index": step["order_index"],
        "attempt": entry["attempt"],
        "argv": step["execution_target"],
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise StateMachineError(f"receipt_{field}_mismatch")
    if stable_hash(receipt["step_token"]) != entry.get("active_token_sha256"):
        raise StateMachineError("receipt_step_token_mismatch")
    required_dependencies = _current_dependency_receipt_ids(state, step)
    if receipt.get("upstream_receipt_ids") != required_dependencies:
        raise StateMachineError("receipt_dependency_receipts_mismatch")
    if receipt["status"] not in TERMINAL_RECEIPT_STATES:
        raise StateMachineError("receipt_not_terminal")
    received_applicability = receipt.get("applicability")
    if not isinstance(received_applicability, dict) or received_applicability.get("probe_id") != step["applicability_probe"]:
        raise StateMachineError("receipt_applicability_probe_mismatch")
    try:
        expected_applicability = _applicability.evaluate_probe(manifest, step["applicability_probe"], workspace)
    except _applicability.ApplicabilityError as exc:
        if receipt["status"] != "failed":
            raise StateMachineError("applicability_probe_error_requires_failed_receipt", *exc.diagnostics) from exc
        expected_error = _receipt.applicability_evaluation_error(step["applicability_probe"], exc.diagnostics)
        if received_applicability != expected_error:
            raise StateMachineError("receipt_applicability_evaluation_error_mismatch", *exc.diagnostics)
    else:
        if received_applicability != expected_applicability:
            raise StateMachineError("receipt_applicability_mismatch")
    _validate_typed_artifact_joins(state, by_id, step, receipt)
    fingerprint = stable_hash(receipt["output_artifacts"])
    history = entry["receipt_history"]
    if _history_record(entry, receipt["receipt_id"]) is not None:
        raise StateMachineError("duplicate_receipt_id")
    history.append(
        {
            "receipt_id": receipt["receipt_id"],
            "status": receipt["status"],
            "attempt": receipt["attempt"],
            "output_fingerprint": fingerprint,
            "output_artifacts": _canonical(receipt["output_artifacts"]),
        }
    )
    history.sort(key=lambda item: (item["attempt"], item["receipt_id"]))
    entry["state"] = receipt["status"]
    entry["active_token_sha256"] = None
    entry["current_receipt_id"] = receipt["receipt_id"] if receipt["status"] in TERMINAL_SUCCESS_STATES else None
    entry["output_fingerprint"] = fingerprint if receipt["status"] in TERMINAL_SUCCESS_STATES else None
    entry["current_output_artifacts"] = _canonical(receipt["output_artifacts"]) if receipt["status"] in TERMINAL_SUCCESS_STATES else []
    _seal(state)


def _downstream_steps(manifest_steps: Mapping[str, Mapping[str, Any]], start_id: str) -> set[str]:
    reverse_dependencies: dict[str, set[str]] = {step_id: set() for step_id in manifest_steps}
    artifact_consumers: dict[str, set[str]] = {}
    for step_id, step in manifest_steps.items():
        for dep in step["depends_on"]:
            reverse_dependencies[dep].add(step_id)
        for artifact in step["consumes"]:
            artifact_consumers.setdefault(artifact, set()).add(step_id)
    start_sequence = manifest_steps[start_id]["run_sequence"]
    seen = {
        step_id
        for step_id, step in manifest_steps.items()
        if step["run_sequence"] >= start_sequence
    }
    queue = [start_id]
    while queue:
        current = queue.pop(0)
        step = manifest_steps[current]
        next_ids = set(reverse_dependencies[current]) | set(step["invalidates"])
        for artifact in step["produces"]:
            next_ids.update(artifact_consumers.get(artifact, set()))
        for next_id in sorted(next_ids):
            if next_id not in seen:
                seen.add(next_id)
                queue.append(next_id)
    return seen


def invalidate_step(state: dict[str, Any], manifest: Any, step_id: str, *, reason: str = "") -> list[str]:
    """Invalidate a producer or input and every declared downstream consumer."""

    _require_state(state)
    by_id = _require_manifest_match(state, manifest)
    if step_id not in by_id:
        raise StateMachineError("unknown_step")
    if not isinstance(reason, str) or not reason.strip():
        raise StateMachineError("invalid_invalidation_reason")
    invalidated = _downstream_steps(by_id, step_id)
    for target_id in sorted(invalidated, key=lambda item: by_id[item]["run_sequence"]):
        entry = state["steps"][target_id]
        state["invalidation_history"].append(
            {
                "source_step_id": step_id,
                "step_id": target_id,
                "prior_state": entry["state"],
                "prior_current_receipt_id": entry["current_receipt_id"],
                "reason": reason.strip(),
            }
        )
        entry["state"] = "invalidated"
        entry["active_token_sha256"] = None
        entry["current_receipt_id"] = None
        entry["output_fingerprint"] = None
        entry["current_output_artifacts"] = []
    _seal(state)
    return sorted(invalidated, key=lambda item: by_id[item]["run_sequence"])


def reopen_step(state: dict[str, Any], manifest: Any, step_id: str, *, reason: str = "") -> list[str]:
    """Explicitly remove canonical credit before a producer or input is rerun."""

    return invalidate_step(state, manifest, step_id, reason=reason)


def closeout(state: dict[str, Any], manifest: Any) -> dict[str, Any]:
    """Return a deterministic closeout result without mutating the state."""

    try:
        _require_state(state)
        by_id = _require_manifest_match(state, manifest)
    except StateMachineError as exc:
        return {"valid": False, "diagnostics": list(exc.diagnostics), "current_receipt_count": 0}
    errors: list[str] = []
    current_ids: list[str] = []
    for step_id in sorted(by_id, key=lambda item: by_id[item]["run_sequence"]):
        entry = state["steps"][step_id]
        if entry.get("state") not in TERMINAL_SUCCESS_STATES:
            errors.append("closeout_non_success_terminal_state")
            continue
        if not _has_current_terminal_receipt(entry):
            errors.append("closeout_missing_current_receipt")
            continue
        current_ids.append(entry["current_receipt_id"])
    if len(current_ids) != state["expected_step_count"]:
        errors.append("closeout_receipt_count_mismatch")
    if len(current_ids) != len(set(current_ids)):
        errors.append("closeout_duplicate_current_receipt")
    return {
        "valid": not errors,
        "diagnostics": sorted(set(errors)),
        "current_receipt_count": len(current_ids),
    }


def write_state(path: str | Path, state: Mapping[str, Any]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(_canonical(dict(state)), indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def read_state(path: str | Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        state = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ["state_file_missing"]
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"state_file_unreadable:{exc}"]
    ok, errors = validate_state(state)
    return (state if ok else None), errors


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _baseline_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--run-id", required=True)
    for field in PROVENANCE_FIELDS[1:]:
        parser.add_argument("--" + field.replace("_", "-"), required=True)


def _baseline_from_args(args: argparse.Namespace) -> dict[str, str]:
    return {field: getattr(args, field) for field in PROVENANCE_FIELDS[1:]}


def _cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="operation", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("--manifest", type=Path, required=True)
    init.add_argument("--state", type=Path, required=True)
    _baseline_arguments(init)
    for name in ("start", "accept", "invalidate", "status", "closeout"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--manifest", type=Path, required=True)
        sub.add_argument("--state", type=Path, required=True)
        if name == "start":
            sub.add_argument("--step-id", required=True)
        elif name == "accept":
            sub.add_argument("--receipt", type=Path, required=True)
            sub.add_argument("--workspace", type=Path, required=True)
        elif name == "invalidate":
            sub.add_argument("--step-id", required=True)
            sub.add_argument("--reason", default="")
    args = parser.parse_args(argv)
    try:
        manifest = _load_json(args.manifest)
        if args.operation == "init":
            state = initialize_state(manifest, run_id=args.run_id, **_baseline_from_args(args))
            write_state(args.state, state)
            print(json.dumps({"valid": True, "run_id": state["run_id"]}, sort_keys=True))
            return 0
        state, errors = read_state(args.state)
        if errors or state is None:
            raise StateMachineError(*errors)
        if args.operation == "start":
            token = start_step(state, manifest, args.step_id)
            write_state(args.state, state)
            print(token)
            return 0
        if args.operation == "accept":
            accept_receipt(state, manifest, _load_json(args.receipt), workspace=args.workspace)
            write_state(args.state, state)
            print(json.dumps({"valid": True}, sort_keys=True))
            return 0
        if args.operation == "invalidate":
            invalidated = invalidate_step(state, manifest, args.step_id, reason=args.reason)
            write_state(args.state, state)
            print(json.dumps({"invalidated": invalidated, "valid": True}, sort_keys=True))
            return 0
        if args.operation == "status":
            _require_manifest_match(state, manifest)
            print(json.dumps({"valid": True, "state": state}, indent=2, sort_keys=True))
            return 0
        result = closeout(state, manifest)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["valid"] else 1
    except (OSError, json.JSONDecodeError, StateMachineError) as exc:
        diagnostics = list(exc.diagnostics) if isinstance(exc, StateMachineError) else [str(exc)]
        print(json.dumps({"valid": False, "diagnostics": diagnostics}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
