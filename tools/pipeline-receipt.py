"""Pipeline V2 execution receipt schema, builder, and validator.

This module is intentionally independent from both MCP evidence receipts and
control run manifests.  It records one ordered pipeline step and its evidence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


def _load_hash_helpers() -> tuple[Any, Any]:
    """Load the shared hashing helpers in package and script contexts."""

    try:
        from tools.lib.mcp_evidence_receipt import file_sha256, stable_hash

        return stable_hash, file_sha256
    except ModuleNotFoundError:
        try:
            from lib.mcp_evidence_receipt import file_sha256, stable_hash

            return stable_hash, file_sha256
        except ModuleNotFoundError:
            helper_path = Path(__file__).resolve().parent / "lib" / "mcp_evidence_receipt.py"
            spec = importlib.util.spec_from_file_location("_pipeline_mcp_evidence_receipt", helper_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"cannot load shared receipt helpers from {helper_path}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module.stable_hash, module.file_sha256


stable_hash, file_sha256 = _load_hash_helpers()

SCHEMA = "auditooor.pipeline_receipt.v2"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_FAILED = "failed"
TERMINAL_STATUSES = frozenset({STATUS_SUCCEEDED, STATUS_NOT_APPLICABLE, STATUS_FAILED})
VALID_STATUSES = TERMINAL_STATUSES | {STATUS_RUNNING}
VALIDATOR_STATUSES = TERMINAL_STATUSES
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
APPLICABILITY_EVALUATION_ERROR_KIND = "applicability_probe_evaluation_error"

PROVENANCE_FIELDS = (
    "manifest_sha256",
    "workspace_identity_sha256",
    "source_snapshot_sha256",
    "scope_sha256",
    "severity_sha256",
    "targets_sha256",
    "program_rules_sha256",
    "pipeline_tooling_sha256",
)
RECEIPT_FIELDS = (
    "schema",
    "run_id",
    *PROVENANCE_FIELDS,
    "step_id",
    "order_index",
    "attempt",
    "step_token",
    "status",
    "applicability",
    "argv",
    "selected_environment",
    "started_at",
    "finished_at",
    "exit_code",
    "upstream_receipt_ids",
    "input_artifacts",
    "output_artifacts",
    "stdout_sha256",
    "stderr_sha256",
    "tool_versions",
    "toolchain_versions",
    "receipt_id",
    "self_hash",
)


def _canonical(value: Any) -> Any:
    """Return JSON data with recursively canonicalized object keys."""

    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _hash(value: Any) -> str:
    return _text(value).lower()


def _sorted_unique(values: Sequence[Any] | None) -> list[str]:
    return sorted({str(value).strip() for value in (values or []) if str(value).strip()})


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    text = _text(value)
    return text or None


def _artifact_sort_key(row: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        _text(row.get("artifact_contract")),
        _text(row.get("path")),
        _hash(row.get("sha256")),
    )


def artifact_metadata(
    path: str | Path,
    *,
    artifact_contract: str,
    semantic_validator_results: Sequence[Mapping[str, Any]] | None = None,
    validators: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return deterministic metadata for one artifact on disk."""

    artifact_path = Path(path)
    result = {
        "artifact_contract": _text(artifact_contract),
        "path": str(path),
        "sha256": file_sha256(artifact_path),
        "size": artifact_path.stat().st_size,
    }
    validator_rows = semantic_validator_results if semantic_validator_results is not None else validators
    if validator_rows is not None:
        result["semantic_validator_results"] = _canonical(list(validator_rows))
    return result


def _normalize_validator_rows(raw: Sequence[Mapping[str, Any]] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in raw or []:
        item = dict(row)
        if "validator_id" not in item and "id" in item:
            item["validator_id"] = item.pop("id")
        if "validator_id" not in item and "validator" in item:
            item["validator_id"] = item.pop("validator")
        if "status" not in item and "result" in item:
            item["status"] = item.pop("result")
        status = _text(item.get("status")).lower()
        if status in {"passed", "pass", "ok"}:
            item["status"] = STATUS_SUCCEEDED
        rows.append(_canonical(item))
    return sorted(rows, key=lambda item: (_text(item.get("validator_id")), stable_hash(item)))


def _normalize_artifacts(raw: Sequence[Mapping[str, Any]] | None, *, validators: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in raw or []:
        item = _canonical(dict(row))
        if validators and "semantic_validator_results" not in item and "validators" in item:
            item["semantic_validator_results"] = item.pop("validators")
        if validators and "semantic_validator_results" in item:
            item["semantic_validator_results"] = _normalize_validator_rows(item["semantic_validator_results"])
        rows.append(item)
    return sorted(rows, key=_artifact_sort_key)


def _sorted_diagnostics(values: Sequence[Any] | None) -> list[str]:
    return sorted({str(value).strip() for value in (values or []) if str(value).strip()})


def build_applicability_result(probe_id: str, canonical_inputs: Any, result: bool) -> dict[str, Any]:
    inputs = _canonical(canonical_inputs)
    body = {"probe_id": _text(probe_id), "canonical_inputs": inputs, "result": bool(result)}
    return {**body, "hash": stable_hash(body)}


def applicability_evaluation_error(probe_id: str, diagnostics: Sequence[Any]) -> dict[str, Any]:
    evidence = {
        "kind": APPLICABILITY_EVALUATION_ERROR_KIND,
        "diagnostics": _sorted_diagnostics(diagnostics),
    }
    body = {"probe_id": _text(probe_id), "evaluation_error": evidence}
    return {**body, "hash": stable_hash(body)}


def receipt_id(receipt: Mapping[str, Any]) -> str:
    """Compute the self-hash for a receipt, excluding both self-hash fields."""

    body = dict(receipt)
    body.pop("receipt_id", None)
    body.pop("self_hash", None)
    return stable_hash(_canonical(body))


def build_receipt(
    *,
    run_id: str,
    manifest_sha256: str,
    workspace_identity_sha256: str,
    source_snapshot_sha256: str,
    scope_sha256: str,
    severity_sha256: str,
    targets_sha256: str,
    program_rules_sha256: str,
    pipeline_tooling_sha256: str,
    step_id: str,
    order_index: int,
    attempt: int,
    step_token: str,
    status: str,
    applicability_probe_id: str,
    applicability_inputs: Any,
    applicability_result: bool,
    argv: Sequence[str],
    selected_environment: Mapping[str, str],
    started_at: str,
    finished_at: str | None = None,
    exit_code: int | None = None,
    upstream_receipt_ids: Sequence[str] | None = None,
    input_artifacts: Sequence[Mapping[str, Any]] | None = None,
    output_artifacts: Sequence[Mapping[str, Any]] | None = None,
    stdout_sha256: str,
    stderr_sha256: str,
    tool_versions: Mapping[str, str],
    toolchain_versions: Mapping[str, str],
    applicability_error_diagnostics: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Build a canonical receipt; validation is available separately."""

    normalized_status = _text(status).lower()
    provenance = {field: _hash(locals()[field]) for field in PROVENANCE_FIELDS}
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "run_id": _text(run_id),
        **provenance,
        "step_id": _text(step_id),
        "order_index": order_index,
        "attempt": attempt,
        "step_token": _hash(step_token),
        "status": normalized_status,
        "applicability": (
            applicability_evaluation_error(applicability_probe_id, applicability_error_diagnostics)
            if applicability_error_diagnostics is not None
            else build_applicability_result(
                probe_id=applicability_probe_id,
                canonical_inputs=applicability_inputs,
                result=applicability_result,
            )
        ),
        "argv": [str(item) for item in argv],
        "selected_environment": {str(key): str(value) for key, value in sorted(selected_environment.items())},
        "started_at": _timestamp(started_at),
        "finished_at": _timestamp(finished_at),
        "exit_code": exit_code,
        "upstream_receipt_ids": _sorted_unique(upstream_receipt_ids),
        "input_artifacts": _normalize_artifacts(input_artifacts, validators=False),
        "output_artifacts": _normalize_artifacts(output_artifacts, validators=True),
        "stdout_sha256": _hash(stdout_sha256),
        "stderr_sha256": _hash(stderr_sha256),
        "tool_versions": _canonical(dict(tool_versions)),
        "toolchain_versions": _canonical(dict(toolchain_versions)),
    }
    digest = receipt_id(receipt)
    receipt["receipt_id"] = digest
    receipt["self_hash"] = digest
    return receipt


def _parse_timestamp(value: Any) -> dt.datetime | None:
    text = _text(value)
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _validate_hash(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        errors.append(f"invalid_{name}")


def _validate_artifact_list(value: Any, name: str, errors: list[str], *, outputs: bool) -> None:
    if not isinstance(value, list):
        errors.append(f"invalid_{name}")
        return
    paths: list[str] = []
    artifact_keys: list[tuple[str, str, str]] = []
    for index, row in enumerate(value):
        prefix = f"{name}_{index}"
        if not isinstance(row, dict):
            errors.append(f"invalid_{prefix}")
            continue
        artifact_contract = _text(row.get("artifact_contract"))
        if not artifact_contract:
            errors.append(f"missing_{prefix}_artifact_contract")
        path = _text(row.get("path"))
        if not path:
            errors.append(f"missing_{prefix}_path")
        paths.append(path)
        artifact_keys.append(_artifact_sort_key(row))
        _validate_hash(row.get("sha256"), f"{prefix}_sha256", errors)
        size = row.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            errors.append(f"invalid_{prefix}_size")
        if outputs:
            validators = row.get("semantic_validator_results")
            if not isinstance(validators, list) or not validators:
                errors.append(f"invalid_{prefix}_semantic_validator_results")
                continue
            validator_ids: list[str] = []
            for validator_index, validator in enumerate(validators):
                vp = f"{prefix}_validator_{validator_index}"
                if not isinstance(validator, dict):
                    errors.append(f"invalid_{vp}")
                    continue
                validator_id = _text(validator.get("validator_id"))
                if not validator_id:
                    errors.append(f"missing_{vp}_id")
                validator_ids.append(validator_id)
                if validator.get("status") not in VALIDATOR_STATUSES:
                    errors.append(f"invalid_{vp}_status")
            if len(validator_ids) != len(set(validator_ids)):
                errors.append(f"duplicate_{prefix}_validator_id")
            if validators != sorted(validators, key=lambda item: (_text(item.get("validator_id")), stable_hash(item))):
                errors.append(f"nondeterministic_{prefix}_validators")
    if artifact_keys != sorted(artifact_keys):
        errors.append(f"nondeterministic_{name}")
    if len(paths) != len(set(paths)):
        errors.append(f"duplicate_{name}_path")


def _validate_version_map(value: Any, name: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or not value:
        errors.append(f"invalid_{name}")
        return
    if any(
        not isinstance(key, str)
        or not key.strip()
        or not isinstance(version, str)
        or not version.strip()
        for key, version in value.items()
    ):
        errors.append(f"invalid_{name}")


def validate_receipt(receipt: Any, *, require_terminal: bool = False) -> tuple[bool, list[str]]:
    """Validate a receipt and return ``(ok, diagnostic_codes)``."""

    errors: list[str] = []
    if not isinstance(receipt, dict):
        return False, ["receipt_not_json_object"]
    for field in RECEIPT_FIELDS:
        if field not in receipt:
            errors.append(f"missing_{field}")
    if errors:
        return False, errors
    if receipt.get("schema") != SCHEMA:
        errors.append("invalid_schema")
    for field in PROVENANCE_FIELDS + ("stdout_sha256", "stderr_sha256"):
        _validate_hash(receipt.get(field), field, errors)
    for field in ("run_id", "step_id"):
        if not _text(receipt.get(field)):
            errors.append(f"missing_{field}")
    order_index = receipt.get("order_index")
    if isinstance(order_index, bool) or not isinstance(order_index, int) or order_index < 0:
        errors.append("invalid_order_index")
    attempt = receipt.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        errors.append("invalid_attempt")
    _validate_hash(receipt.get("step_token"), "step_token", errors)
    status = receipt.get("status")
    if status not in VALID_STATUSES:
        errors.append("invalid_status")
    elif require_terminal and status not in TERMINAL_STATUSES:
        errors.append("non_terminal_status")

    applicability = receipt.get("applicability")
    applicability_mode: str | None = None
    applicability_result_value: bool | None = None
    if not isinstance(applicability, dict):
        errors.append("invalid_applicability")
    else:
        probe_id = _text(applicability.get("probe_id"))
        if not probe_id:
            errors.append("missing_applicability_probe_id")
        _validate_hash(applicability.get("hash"), "applicability_hash", errors)
        has_evaluation_error = "evaluation_error" in applicability
        has_result = "result" in applicability
        has_inputs = "canonical_inputs" in applicability
        if has_evaluation_error:
            applicability_mode = "evaluation_error"
            if has_result:
                errors.append("applicability_evaluation_error_has_result")
            if has_inputs:
                errors.append("applicability_evaluation_error_has_canonical_inputs")
            evaluation_error = applicability.get("evaluation_error")
            canonical_error: dict[str, Any] | None = None
            if not isinstance(evaluation_error, dict):
                errors.append("invalid_applicability_evaluation_error")
            else:
                kind = _text(evaluation_error.get("kind"))
                if kind != APPLICABILITY_EVALUATION_ERROR_KIND:
                    errors.append("invalid_applicability_evaluation_error_kind")
                diagnostics = evaluation_error.get("diagnostics")
                if not isinstance(diagnostics, list) or not diagnostics:
                    errors.append("invalid_applicability_evaluation_error_diagnostics")
                elif any(not isinstance(item, str) or not item.strip() for item in diagnostics):
                    errors.append("invalid_applicability_evaluation_error_diagnostics")
                else:
                    canonical_diagnostics = _sorted_diagnostics(diagnostics)
                    canonical_error = {
                        "kind": kind,
                        "diagnostics": canonical_diagnostics,
                    }
                    if diagnostics != canonical_diagnostics:
                        errors.append("nondeterministic_applicability_evaluation_error_diagnostics")
            if canonical_error is not None and stable_hash({"probe_id": probe_id, "evaluation_error": canonical_error}) != applicability.get("hash"):
                errors.append("applicability_hash_mismatch")
        else:
            applicability_mode = "result"
            if "canonical_inputs" not in applicability:
                errors.append("missing_applicability_canonical_inputs")
            result = applicability.get("result")
            if not isinstance(result, bool):
                errors.append("invalid_applicability_result")
            else:
                applicability_result_value = result
            expected = {
                "probe_id": probe_id,
                "canonical_inputs": _canonical(applicability.get("canonical_inputs")),
                "result": result,
            }
            if isinstance(result, bool) and stable_hash(expected) != applicability.get("hash"):
                errors.append("applicability_hash_mismatch")

    argv = receipt.get("argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
        errors.append("invalid_argv")
    environment = receipt.get("selected_environment")
    if not isinstance(environment, dict) or any(
        not isinstance(key, str) or not key or not isinstance(value, str) for key, value in environment.items()
    ):
        errors.append("invalid_selected_environment")
    elif list(environment) != sorted(environment):
        errors.append("nondeterministic_selected_environment")

    started = _parse_timestamp(receipt.get("started_at"))
    finished = _parse_timestamp(receipt.get("finished_at"))
    if started is None:
        errors.append("invalid_started_at")
    if status == STATUS_RUNNING:
        if receipt.get("finished_at") is not None:
            errors.append("running_has_finished_at")
        if receipt.get("exit_code") is not None:
            errors.append("running_has_exit_code")
    else:
        if finished is None:
            errors.append("invalid_finished_at")
        if started is not None and finished is not None and finished < started:
            errors.append("timestamp_ordering")
        exit_code = receipt.get("exit_code")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            errors.append("invalid_exit_code")
        elif status in {STATUS_SUCCEEDED, STATUS_NOT_APPLICABLE} and exit_code != 0:
            errors.append("invalid_exit_code_for_status")
        elif status == STATUS_FAILED and exit_code == 0:
            errors.append("invalid_exit_code_for_status")

    for field in ("upstream_receipt_ids",):
        values = receipt.get(field)
        if not isinstance(values, list) or any(not isinstance(value, str) or not value.strip() for value in values):
            errors.append(f"invalid_{field}")
        elif any(not HEX64_RE.fullmatch(value) for value in values):
            errors.append("invalid_upstream_receipt_id")
        elif values != sorted(set(values)):
            errors.append(f"nondeterministic_{field}")
    _validate_artifact_list(receipt.get("input_artifacts"), "input_artifacts", errors, outputs=False)
    _validate_artifact_list(receipt.get("output_artifacts"), "output_artifacts", errors, outputs=True)
    _validate_version_map(receipt.get("tool_versions"), "tool_versions", errors)
    _validate_version_map(receipt.get("toolchain_versions"), "toolchain_versions", errors)

    if status == STATUS_SUCCEEDED:
        if applicability_mode == "evaluation_error":
            errors.append("succeeded_forbids_applicability_evaluation_error")
        elif applicability_result_value is not True:
            errors.append("execution_requires_applicability")
    elif status == STATUS_FAILED:
        if applicability_mode != "evaluation_error" and applicability_result_value is not True:
            errors.append("execution_requires_applicability")
    elif status == STATUS_NOT_APPLICABLE:
        if applicability_mode == "evaluation_error":
            errors.append("not_applicable_forbids_applicability_evaluation_error")
        elif applicability_result_value is not False:
            errors.append("not_applicable_unproven")
    output_artifacts = receipt.get("output_artifacts")
    if status == STATUS_NOT_APPLICABLE and isinstance(output_artifacts, list) and output_artifacts:
        errors.append("not_applicable_has_output_artifacts")
    input_artifacts = receipt.get("input_artifacts")
    if status == STATUS_NOT_APPLICABLE and isinstance(input_artifacts, list) and input_artifacts:
        errors.append("not_applicable_has_input_artifacts")
    if isinstance(output_artifacts, list):
        has_failed_validator = any(
            isinstance(artifact, dict)
            and isinstance(artifact.get("semantic_validator_results"), list)
            and any(
                isinstance(validator, dict) and validator.get("status") == STATUS_FAILED
                for validator in artifact["semantic_validator_results"]
            )
            for artifact in output_artifacts
        )
        if has_failed_validator and status != STATUS_FAILED:
            errors.append("failed_validator_requires_failed_status")
        if has_failed_validator and status == STATUS_SUCCEEDED:
            errors.append("succeeded_contains_failed_validator")
        if status == STATUS_SUCCEEDED:
            has_non_succeeded_validator = any(
                isinstance(artifact, dict)
                and isinstance(artifact.get("semantic_validator_results"), list)
                and any(
                    not isinstance(validator, dict)
                    or validator.get("status") != STATUS_SUCCEEDED
                    for validator in artifact["semantic_validator_results"]
                )
                for artifact in output_artifacts
            )
            if has_non_succeeded_validator:
                errors.append("succeeded_requires_succeeded_validators")

    rid = receipt.get("receipt_id")
    self_hash = receipt.get("self_hash")
    _validate_hash(rid, "receipt_id", errors)
    _validate_hash(self_hash, "self_hash", errors)
    if isinstance(rid, str) and isinstance(self_hash, str) and rid != self_hash:
        errors.append("receipt_id_self_hash_mismatch")
    if isinstance(rid, str) and HEX64_RE.fullmatch(rid) and receipt_id(receipt) != rid:
        errors.append("receipt_id_mismatch")
    return not errors, errors


def validate_terminal_receipt(receipt: Any) -> tuple[bool, list[str]]:
    return validate_receipt(receipt, require_terminal=True)


def write_receipt(path: str | Path, receipt: Mapping[str, Any]) -> None:
    """Write deterministic receipt JSON."""

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(_canonical(dict(receipt)), indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def read_receipt(path: str | Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Read JSON without raising ordinary file or JSON diagnostics."""

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, ["receipt_file_missing"]
    except (OSError, json.JSONDecodeError) as exc:
        return None, [f"receipt_file_unreadable:{exc}"]
    if not isinstance(value, dict):
        return None, ["receipt_not_json_object"]
    return value, []


def validate_receipt_file(path: str | Path, *, require_terminal: bool = True) -> tuple[bool, list[str], dict[str, Any] | None]:
    value, read_errors = read_receipt(path)
    if read_errors:
        return False, read_errors, value
    ok, errors = validate_receipt(value, require_terminal=require_terminal)
    return ok, errors, value


def _cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an auditooor Pipeline V2 receipt")
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args(argv)
    ok, errors, _ = validate_receipt_file(args.receipt, require_terminal=True)
    if ok:
        print("valid")
        return 0
    for error in errors:
        print(error, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
