#!/usr/bin/env python3
"""Static validator for auditooor pipeline manifest V2 contracts.

This validator is intentionally isolated from the legacy README conformance
flow. It validates only the V2 manifest shape, its explicit registries, and
the execution/dataflow graph declared by the manifest.

CLI:
    python3 tools/pipeline-manifest-validate.py --manifest path/to/manifest.json

Exit codes:
    0 = manifest valid
    1 = manifest invalid or unreadable
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pipeline_manifest.validation.v1"
MANIFEST_V2_SCHEMA = "auditooor.pipeline_manifest.v2"

REQUIRED_STEP_FIELDS = (
    "step_id",
    "order_index",
    "run_sequence",
    "phase",
    "execution_target",
    "applicability_probe",
    "depends_on",
    "consumes",
    "produces",
    "validators",
    "invalidates",
    "terminal_output",
    "required",
)

BUILTIN_VALIDATORS = frozenset()
BUILTIN_LEGACY_ARTIFACT_CHECK_TYPES = frozenset()
KNOWN_EXECUTABLES = frozenset({"bash", "make", "python3"})
PLACEHOLDER_RE = re.compile(r"\{([^{}]+)\}")
LEGACY_PLACEHOLDER_RE = re.compile(r"<[^<>]+>")
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SECRET_ENVIRONMENT_TOKENS = frozenset({"API_KEY", "PASSWORD", "PRIVATE_KEY", "SECRET", "TOKEN"})


def _load_applicability() -> Any:
    path = Path(__file__).resolve().parent / "pipeline-applicability.py"
    spec = importlib.util.spec_from_file_location("_pipeline_manifest_applicability", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


_applicability = _load_applicability()


@dataclass(frozen=True)
class Diagnostic:
    severity: str
    code: str
    path: str
    message: str
    step_id: str | None = None
    artifact_contract: str | None = None


def _diag(
    diagnostics: list[Diagnostic],
    code: str,
    path: str,
    message: str,
    *,
    step_id: str | None = None,
    artifact_contract: str | None = None,
) -> None:
    diagnostics.append(
        Diagnostic(
            severity="error",
            code=code,
            path=path,
            message=message,
            step_id=step_id,
            artifact_contract=artifact_contract,
        )
    )


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _collect_registry_ids(
    manifest: dict[str, Any],
    section: str,
    diagnostics: list[Diagnostic],
    *,
    builtin_ids: frozenset[str],
) -> set[str]:
    ids = set(builtin_ids)
    if section not in manifest:
        return ids
    raw = manifest.get(section)
    if not isinstance(raw, list):
        _diag(
            diagnostics,
            "MALFORMED_REGISTRY",
            f"$.{section}",
            f"registry '{section}' must be a list",
        )
        return ids
    seen_local: set[str] = set()
    for idx, item in enumerate(raw):
        path = f"$.{section}[{idx}]"
        if isinstance(item, str):
            item_id = item.strip()
        elif isinstance(item, dict):
            candidate = item.get("id")
            item_id = candidate.strip() if isinstance(candidate, str) else ""
        else:
            item_id = ""
        if not item_id:
            _diag(
                diagnostics,
                "MALFORMED_REGISTRY_ENTRY",
                path,
                f"registry '{section}' entries must be non-empty strings or objects with an 'id' field",
            )
            continue
        if item_id in seen_local:
            _diag(
                diagnostics,
                "DUPLICATE_REGISTRY_ID",
                path,
                f"registry '{section}' contains duplicate id '{item_id}'",
            )
            continue
        seen_local.add(item_id)
        ids.add(item_id)
    return ids


def _normalize_string_list(
    value: Any,
    diagnostics: list[Diagnostic],
    path: str,
    code: str,
    *,
    allow_empty: bool,
    duplicate_code: str | None = None,
    step_id: str | None = None,
) -> list[str] | None:
    if not isinstance(value, list):
        _diag(diagnostics, code, path, "expected a list of non-empty strings", step_id=step_id)
        return None
    normalized: list[str] = []
    seen: set[str] = set()
    for idx, item in enumerate(value):
        if not _is_nonempty_string(item):
            _diag(
                diagnostics,
                code,
                f"{path}[{idx}]",
                "expected a non-empty string",
                step_id=step_id,
            )
            return None
        normalized_item = item.strip()
        if duplicate_code is not None and normalized_item in seen:
            _diag(
                diagnostics,
                duplicate_code,
                f"{path}[{idx}]",
                f"duplicate entry '{normalized_item}' is not allowed",
                step_id=step_id,
            )
        seen.add(normalized_item)
        normalized.append(normalized_item)
    if not allow_empty and not normalized:
        _diag(diagnostics, code, path, "list must not be empty", step_id=step_id)
        return None
    return normalized


def _validate_top_level(manifest: Any, diagnostics: list[Diagnostic]) -> dict[str, Any] | None:
    if not isinstance(manifest, dict):
        _diag(diagnostics, "MALFORMED_TOP_LEVEL", "$", "manifest must be a JSON object")
        return None
    schema = manifest.get("schema")
    if schema != MANIFEST_V2_SCHEMA:
        _diag(
            diagnostics,
            "INVALID_MANIFEST_SCHEMA",
            "$.schema",
            f"manifest schema must be '{MANIFEST_V2_SCHEMA}'",
        )
    expected_step_count = manifest.get("expected_step_count")
    if not isinstance(expected_step_count, int) or isinstance(expected_step_count, bool) or expected_step_count <= 0:
        _diag(
            diagnostics,
            "INVALID_EXPECTED_STEP_COUNT",
            "$.expected_step_count",
            "expected_step_count must be a positive integer",
        )
    steps = manifest.get("steps")
    if not isinstance(steps, list):
        _diag(diagnostics, "MALFORMED_TOP_LEVEL", "$.steps", "manifest.steps must be a list")
        return None
    if isinstance(expected_step_count, int) and not isinstance(expected_step_count, bool):
        if expected_step_count != len(steps):
            _diag(
                diagnostics,
                "MISMATCHED_EXPECTED_STEP_COUNT",
                "$.expected_step_count",
                f"expected_step_count {expected_step_count} does not match len(steps) {len(steps)}",
            )
    return manifest


def _validate_steps(
    steps: list[Any],
    diagnostics: list[Diagnostic],
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, int],
    dict[int, str],
    dict[str, int],
    dict[int, str],
]:
    normalized_steps: list[dict[str, Any]] = []
    steps_by_id: dict[str, dict[str, Any]] = {}
    order_by_step_id: dict[str, int] = {}
    step_id_by_order: dict[int, str] = {}
    run_sequence_by_step_id: dict[str, int] = {}
    step_id_by_run_sequence: dict[int, str] = {}
    for idx, raw_step in enumerate(steps):
        path = f"$.steps[{idx}]"
        if not isinstance(raw_step, dict):
            _diag(diagnostics, "MALFORMED_STEP", path, "step must be a JSON object")
            continue
        missing = [field for field in REQUIRED_STEP_FIELDS if field not in raw_step]
        for field in missing:
            _diag(
                diagnostics,
                "MISSING_STEP_FIELD",
                f"{path}.{field}",
                f"required step field '{field}' is missing",
            )
        step_id = raw_step.get("step_id") if isinstance(raw_step.get("step_id"), str) else None
        normalized_step_id = step_id.strip() if step_id else None
        if not normalized_step_id:
            _diag(diagnostics, "INVALID_STEP_ID", f"{path}.step_id", "step_id must be a non-empty string")
        order_index = raw_step.get("order_index")
        if not isinstance(order_index, int) or isinstance(order_index, bool) or order_index < 0:
            _diag(
                diagnostics,
                "INVALID_ORDER_INDEX",
                f"{path}.order_index",
                "order_index must be a non-negative integer",
                step_id=normalized_step_id,
            )
        run_sequence = raw_step.get("run_sequence")
        if not isinstance(run_sequence, int) or isinstance(run_sequence, bool) or run_sequence < 0:
            _diag(
                diagnostics,
                "INVALID_RUN_SEQUENCE",
                f"{path}.run_sequence",
                "run_sequence must be a non-negative integer",
                step_id=normalized_step_id,
            )
        phase = raw_step.get("phase")
        if not _is_nonempty_string(phase):
            _diag(
                diagnostics,
                "INVALID_PHASE",
                f"{path}.phase",
                "phase must be a non-empty string",
                step_id=normalized_step_id,
            )
        execution_target = _normalize_string_list(
            raw_step.get("execution_target"),
            diagnostics,
            f"{path}.execution_target",
            "INVALID_EXECUTION_TARGET",
            allow_empty=False,
            step_id=normalized_step_id,
        )
        depends_on = _normalize_string_list(
            raw_step.get("depends_on"),
            diagnostics,
            f"{path}.depends_on",
            "INVALID_DEPENDENCY_LIST",
            allow_empty=True,
            duplicate_code="DUPLICATE_DEPENDENCY_ENTRY",
            step_id=normalized_step_id,
        )
        consumes = _normalize_string_list(
            raw_step.get("consumes"),
            diagnostics,
            f"{path}.consumes",
            "INVALID_ARTIFACT_LIST",
            allow_empty=True,
            duplicate_code="DUPLICATE_CONSUMES_ENTRY",
            step_id=normalized_step_id,
        )
        produces = _normalize_string_list(
            raw_step.get("produces"),
            diagnostics,
            f"{path}.produces",
            "INVALID_ARTIFACT_LIST",
            allow_empty=True,
            duplicate_code="DUPLICATE_PRODUCES_ENTRY",
            step_id=normalized_step_id,
        )
        validators = _normalize_string_list(
            raw_step.get("validators"),
            diagnostics,
            f"{path}.validators",
            "INVALID_VALIDATOR_LIST",
            allow_empty=True,
            duplicate_code="DUPLICATE_VALIDATOR_ENTRY",
            step_id=normalized_step_id,
        )
        invalidates = _normalize_string_list(
            raw_step.get("invalidates"),
            diagnostics,
            f"{path}.invalidates",
            "INVALID_INVALIDATES_LIST",
            allow_empty=True,
            duplicate_code="DUPLICATE_INVALIDATES_ENTRY",
            step_id=normalized_step_id,
        )
        how_to_verify_done = raw_step.get("how_to_verify_done")
        if how_to_verify_done is not None and not isinstance(how_to_verify_done, dict):
            _diag(
                diagnostics,
                "INVALID_HOW_TO_VERIFY_DONE",
                f"{path}.how_to_verify_done",
                "how_to_verify_done must be an object when present",
                step_id=normalized_step_id,
            )
        terminal_output = raw_step.get("terminal_output")
        if not isinstance(terminal_output, bool):
            _diag(
                diagnostics,
                "INVALID_TERMINAL_OUTPUT",
                f"{path}.terminal_output",
                "terminal_output must be a boolean",
                step_id=normalized_step_id,
            )

        elif terminal_output and produces == []:
            _diag(
                diagnostics,
                "EMPTY_TERMINAL_OUTPUT",
                f"{path}.terminal_output",
                "terminal_output=true is invalid when the step produces no artifacts",
                step_id=normalized_step_id,
            )
        required = raw_step.get("required")
        if required is not True:
            _diag(
                diagnostics,
                "FALSE_OPTIONALITY",
                f"{path}.required",
                "Pipeline V2 steps are load-bearing and must declare required=true; applicability belongs in the probe",
                step_id=normalized_step_id,
            )

        if normalized_step_id:
            if normalized_step_id in steps_by_id:
                _diag(
                    diagnostics,
                    "DUPLICATE_STEP_ID",
                    f"{path}.step_id",
                    f"duplicate step_id '{normalized_step_id}'",
                    step_id=normalized_step_id,
                )
            elif isinstance(order_index, int) and order_index >= 0:
                steps_by_id[normalized_step_id] = {
                    "step_id": normalized_step_id,
                    "order_index": order_index,
                    "run_sequence": run_sequence,
                    "phase": phase.strip() if isinstance(phase, str) else phase,
                    "execution_target": execution_target,
                    "applicability_probe": raw_step.get("applicability_probe"),
                    "depends_on": depends_on,
                    "consumes": consumes,
                    "produces": produces,
                    "validators": validators,
                    "invalidates": invalidates,
                    "terminal_output": terminal_output,
                    "required": required,
                    "class": raw_step.get("class"),
                    "how_to_verify_done": how_to_verify_done if isinstance(how_to_verify_done, dict) else None,
                    "_path": path,
                }
                normalized_steps.append(steps_by_id[normalized_step_id])

        if isinstance(order_index, int) and order_index >= 0:
            if order_index in step_id_by_order:
                _diag(
                    diagnostics,
                    "DUPLICATE_ORDER_INDEX",
                    f"{path}.order_index",
                    f"duplicate order_index {order_index}",
                    step_id=normalized_step_id,
                )
            elif normalized_step_id:
                step_id_by_order[order_index] = normalized_step_id
                order_by_step_id[normalized_step_id] = order_index
        if isinstance(run_sequence, int) and run_sequence >= 0:
            if run_sequence in step_id_by_run_sequence:
                _diag(
                    diagnostics,
                    "DUPLICATE_RUN_SEQUENCE",
                    f"{path}.run_sequence",
                    f"duplicate run_sequence {run_sequence}",
                    step_id=normalized_step_id,
                )
            elif normalized_step_id:
                step_id_by_run_sequence[run_sequence] = normalized_step_id
                run_sequence_by_step_id[normalized_step_id] = run_sequence
    return (
        normalized_steps,
        steps_by_id,
        order_by_step_id,
        step_id_by_order,
        run_sequence_by_step_id,
        step_id_by_run_sequence,
    )


def _validate_sequence_contiguity(
    sequence_by_value: dict[int, str],
    diagnostics: list[Diagnostic],
    *,
    code: str,
    label: str,
) -> None:
    if not sequence_by_value:
        return
    observed = sorted(sequence_by_value)
    expected = list(range(len(sequence_by_value)))
    if observed != expected:
        _diag(
            diagnostics,
            code,
            "$.steps",
            f"{label} values must be contiguous starting at 0; expected {expected}, got {observed}",
        )


def _validate_execution_placeholders(
    manifest: dict[str, Any], diagnostics: list[Diagnostic]
) -> set[str]:
    raw = manifest.get("execution_placeholders")
    if not isinstance(raw, list) or not raw:
        _diag(
            diagnostics,
            "MALFORMED_EXECUTION_PLACEHOLDER_REGISTRY",
            "$.execution_placeholders",
            "execution_placeholders must be a non-empty list of objects",
        )
        return set()
    tokens: set[str] = set()
    for idx, row in enumerate(raw):
        path = f"$.execution_placeholders[{idx}]"
        if not isinstance(row, dict):
            _diag(diagnostics, "MALFORMED_EXECUTION_PLACEHOLDER", path, "placeholder entry must be an object")
            continue
        placeholder_id = row.get("id")
        token = row.get("token")
        source = row.get("source")
        if not all(_is_nonempty_string(value) for value in (placeholder_id, token, source)):
            _diag(
                diagnostics,
                "MALFORMED_EXECUTION_PLACEHOLDER",
                path,
                "placeholder entries require non-empty id, token, and source fields",
            )
            continue
        normalized_token = token.strip()
        if not re.fullmatch(r"\{[a-z][a-z0-9_]*\}", normalized_token):
            _diag(
                diagnostics,
                "MALFORMED_EXECUTION_PLACEHOLDER",
                f"{path}.token",
                f"invalid placeholder token '{normalized_token}'",
            )
            continue
        if normalized_token in tokens:
            _diag(
                diagnostics,
                "DUPLICATE_EXECUTION_PLACEHOLDER",
                f"{path}.token",
                f"duplicate placeholder token '{normalized_token}'",
            )
            continue
        tokens.add(normalized_token)
    if tokens != {"{workspace}"}:
        _diag(
            diagnostics,
            "INVALID_EXECUTION_PLACEHOLDER_REGISTRY",
            "$.execution_placeholders",
            "Pipeline V2 currently permits exactly the {workspace} placeholder",
        )
    return tokens


def _validate_environment_passthrough(manifest: dict[str, Any], diagnostics: list[Diagnostic]) -> None:
    raw = manifest.get("environment_passthrough")
    if not isinstance(raw, list):
        _diag(
            diagnostics,
            "MALFORMED_ENVIRONMENT_PASSTHROUGH",
            "$.environment_passthrough",
            "environment_passthrough must be a sorted list of unique environment variable names",
        )
        return
    normalized: list[str] = []
    for idx, value in enumerate(raw):
        path = f"$.environment_passthrough[{idx}]"
        if not _is_nonempty_string(value) or not ENVIRONMENT_NAME_RE.fullmatch(value.strip()):
            _diag(diagnostics, "MALFORMED_ENVIRONMENT_PASSTHROUGH", path, "environment variable name must use uppercase ASCII letters, digits, and underscores")
            continue
        name = value.strip()
        if any(token in name for token in SECRET_ENVIRONMENT_TOKENS):
            _diag(diagnostics, "SECRET_ENVIRONMENT_PASSTHROUGH", path, f"secret-bearing environment variable '{name}' must not be inherited")
        normalized.append(name)
    if len(normalized) != len(set(normalized)):
        _diag(diagnostics, "DUPLICATE_ENVIRONMENT_PASSTHROUGH", "$.environment_passthrough", "environment_passthrough entries must be unique")
    if normalized != sorted(normalized):
        _diag(diagnostics, "UNSORTED_ENVIRONMENT_PASSTHROUGH", "$.environment_passthrough", "environment_passthrough entries must be sorted")


def _make_targets() -> set[str]:
    makefile = Path(__file__).resolve().parents[1] / "Makefile"
    try:
        text = makefile.read_text(encoding="utf-8")
    except OSError:
        return set()
    result: set[str] = set()
    for line in text.splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue
        lhs = line.split(":", 1)[0].strip()
        if not lhs or any(token in lhs for token in ("$", "%", "=", "/")):
            continue
        for target in lhs.split():
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", target):
                result.add(target)
    return result


def _validate_execution_target_registry(
    manifest: dict[str, Any], diagnostics: list[Diagnostic]
) -> dict[str, list[str]]:
    raw = manifest.get("execution_target_registry")
    if not isinstance(raw, list) or not raw:
        _diag(diagnostics, "MALFORMED_EXECUTION_TARGET_REGISTRY", "$.execution_target_registry", "execution_target_registry must be a non-empty list")
        return {}
    result: dict[str, list[str]] = {}
    for idx, row in enumerate(raw):
        path = f"$.execution_target_registry[{idx}]"
        if not isinstance(row, dict) or not _is_nonempty_string(row.get("step_id")):
            _diag(diagnostics, "MALFORMED_EXECUTION_TARGET_REGISTRY", path, "target registry entries require a non-empty step_id")
            continue
        step_id = row["step_id"].strip()
        argv = _normalize_string_list(
            row.get("argv"),
            diagnostics,
            f"{path}.argv",
            "MALFORMED_EXECUTION_TARGET_REGISTRY",
            allow_empty=False,
        )
        if argv is None:
            continue
        if step_id in result:
            _diag(diagnostics, "DUPLICATE_EXECUTION_TARGET_REGISTRY_ENTRY", path, f"duplicate target registry entry for step '{step_id}'", step_id=step_id)
            continue
        result[step_id] = argv
    return result


def _validate_execution_target(
    target: list[str] | None,
    registered_placeholders: set[str],
    registered_targets: dict[str, list[str]],
    diagnostics: list[Diagnostic],
    *,
    path: str,
    step_id: str,
) -> None:
    if not target:
        return
    if registered_targets.get(step_id) != target:
        _diag(
            diagnostics,
            "UNKNOWN_EXECUTION_TARGET",
            path,
            f"execution_target for '{step_id}' does not match its canonical registry argv",
            step_id=step_id,
        )
    for idx, argument in enumerate(target):
        argument_path = f"{path}[{idx}]"
        if LEGACY_PLACEHOLDER_RE.search(argument):
            _diag(
                diagnostics,
                "LEGACY_TARGET_PLACEHOLDER",
                argument_path,
                "execution_target must use {workspace}, not angle-bracket placeholders",
                step_id=step_id,
            )
        for name in PLACEHOLDER_RE.findall(argument):
            token = "{" + name + "}"
            if token not in registered_placeholders:
                _diag(
                    diagnostics,
                    "UNKNOWN_TARGET_PLACEHOLDER",
                    argument_path,
                    f"execution_target references unregistered placeholder '{token}'",
                    step_id=step_id,
                )
    executable = target[0]
    if executable not in KNOWN_EXECUTABLES:
        _diag(
            diagnostics,
            "UNKNOWN_EXECUTION_TARGET",
            path,
            f"unsupported execution target executable '{executable}'",
            step_id=step_id,
        )
        return
    if len(target) < 2:
        _diag(
            diagnostics,
            "UNKNOWN_EXECUTION_TARGET",
            path,
            f"execution target '{executable}' does not name a concrete repository target",
            step_id=step_id,
        )
        return
    if executable == "make":
        target_name = target[1]
        if target_name not in _make_targets():
            _diag(
                diagnostics,
                "UNKNOWN_EXECUTION_TARGET",
                f"{path}[1]",
                f"unknown Makefile target '{target_name}'",
                step_id=step_id,
            )
        return
    tool_token = target[1]
    tool_path = Path(tool_token)
    repo_root = Path(__file__).resolve().parents[1]
    if tool_path.is_absolute() or ".." in tool_path.parts or not tool_token.startswith("tools/"):
        _diag(
            diagnostics,
            "UNKNOWN_EXECUTION_TARGET",
            f"{path}[1]",
            f"target '{tool_token}' must be a repository-relative tools/ path",
            step_id=step_id,
        )
        return
    expected_suffix = ".py" if executable == "python3" else ".sh"
    if tool_path.suffix != expected_suffix or not (repo_root / tool_path).is_file():
        _diag(
            diagnostics,
            "UNKNOWN_EXECUTION_TARGET",
            f"{path}[1]",
            f"unknown {executable} target '{tool_token}'",
            step_id=step_id,
        )


def _validate_legacy_check_tree(
    check: Any,
    legacy_check_type_ids: set[str],
    diagnostics: list[Diagnostic],
    *,
    path: str,
    step_id: str,
) -> None:
    if not isinstance(check, dict):
        _diag(diagnostics, "MALFORMED_STEP_ARTIFACT_CHECK", path, "artifact check entries must be objects", step_id=step_id)
        return
    check_type = check.get("type")
    if not _is_nonempty_string(check_type):
        _diag(diagnostics, "MALFORMED_STEP_ARTIFACT_CHECK", f"{path}.type", "artifact check type must be a non-empty string", step_id=step_id)
        return
    normalized_type = check_type.strip()
    if normalized_type not in legacy_check_type_ids:
        _diag(
            diagnostics,
            "UNKNOWN_LEGACY_ARTIFACT_CHECK_TYPE",
            f"{path}.type",
            f"legacy artifact check type '{normalized_type}' is not registered",
            step_id=step_id,
        )
    if normalized_type != "any_of":
        return
    groups = check.get("groups")
    if not isinstance(groups, list) or not groups:
        _diag(diagnostics, "MALFORMED_STEP_ARTIFACT_CHECK", f"{path}.groups", "any_of requires a non-empty groups list", step_id=step_id)
        return
    for group_idx, group in enumerate(groups):
        group_path = f"{path}.groups[{group_idx}]"
        if not isinstance(group, list) or not group:
            _diag(diagnostics, "MALFORMED_STEP_ARTIFACT_CHECK", group_path, "any_of groups must be non-empty lists", step_id=step_id)
            continue
        for check_idx, nested in enumerate(group):
            _validate_legacy_check_tree(
                nested,
                legacy_check_type_ids,
                diagnostics,
                path=f"{group_path}[{check_idx}]",
                step_id=step_id,
            )


def _validate_registries_and_targets(
    manifest: dict[str, Any],
    normalized_steps: list[dict[str, Any]],
    diagnostics: list[Diagnostic],
) -> set[str]:
    registered_placeholders = _validate_execution_placeholders(manifest, diagnostics)
    registered_targets = _validate_execution_target_registry(manifest, diagnostics)
    _validate_environment_passthrough(manifest, diagnostics)
    applicability_probes, applicability_diagnostics = _applicability.parse_probe_registry(manifest)
    for item in applicability_diagnostics:
        _diag(diagnostics, item.code, item.path, item.message)
    applicability_ids = set(applicability_probes)
    validator_ids = _collect_registry_ids(
        manifest,
        "validators",
        diagnostics,
        builtin_ids=BUILTIN_VALIDATORS,
    )
    legacy_check_type_ids = _collect_registry_ids(
        manifest,
        "legacy_artifact_check_types",
        diagnostics,
        builtin_ids=BUILTIN_LEGACY_ARTIFACT_CHECK_TYPES,
    )

    for step in sorted(normalized_steps, key=lambda item: item["order_index"]):
        step_id = step["step_id"]
        path = step["_path"]
        _validate_execution_target(
            step.get("execution_target"),
            registered_placeholders,
            registered_targets,
            diagnostics,
            path=f"{path}.execution_target",
            step_id=step_id,
        )
        probe = step.get("applicability_probe")
        if not _is_nonempty_string(probe):
            _diag(
                diagnostics,
                "INVALID_APPLICABILITY_PROBE",
                f"{path}.applicability_probe",
                "applicability_probe must be a non-empty string",
                step_id=step_id,
            )
        elif probe.strip() not in applicability_ids:
            _diag(
                diagnostics,
                "UNKNOWN_APPLICABILITY_PROBE",
                f"{path}.applicability_probe",
                f"applicability_probe '{probe.strip()}' is not registered",
                step_id=step_id,
            )

        validators = step.get("validators") or []
        for idx, validator_id in enumerate(validators):
            if validator_id not in validator_ids:
                _diag(
                    diagnostics,
                    "UNKNOWN_VALIDATOR",
                    f"{path}.validators[{idx}]",
                    f"validator '{validator_id}' is not registered",
                    step_id=step_id,
                )
        how_to_verify_done = step.get("how_to_verify_done") or {}
        artifact_checks = how_to_verify_done.get("artifact_checks", [])
        if artifact_checks is None:
            artifact_checks = []
        if not isinstance(artifact_checks, list):
            _diag(
                diagnostics,
                "MALFORMED_STEP_ARTIFACT_CHECKS",
                f"{path}.how_to_verify_done.artifact_checks",
                "artifact_checks must be a list when present",
                step_id=step_id,
            )
            artifact_checks = []
        for idx, check in enumerate(artifact_checks):
            check_path = f"{path}.how_to_verify_done.artifact_checks[{idx}]"
            _validate_legacy_check_tree(
                check,
                legacy_check_type_ids,
                diagnostics,
                path=check_path,
                step_id=step_id,
            )

    known_step_ids = {step["step_id"] for step in normalized_steps}
    for registered_step_id in sorted(set(registered_targets) - known_step_ids):
        _diag(
            diagnostics,
            "UNKNOWN_EXECUTION_TARGET_STEP",
            "$.execution_target_registry",
            f"execution target registry references unknown step '{registered_step_id}'",
            step_id=registered_step_id,
        )

    raw_legacy_checks = manifest.get("legacy_artifact_checks", [])
    if raw_legacy_checks is None:
        raw_legacy_checks = []
    if not isinstance(raw_legacy_checks, list):
        _diag(
            diagnostics,
            "MALFORMED_LEGACY_ARTIFACT_CHECKS",
            "$.legacy_artifact_checks",
            "legacy_artifact_checks must be a list",
        )
        return validator_ids
    for idx, row in enumerate(raw_legacy_checks):
        path = f"$.legacy_artifact_checks[{idx}]"
        if not isinstance(row, dict):
            _diag(
                diagnostics,
                "MALFORMED_LEGACY_ARTIFACT_CHECK",
                path,
                "legacy_artifact_checks entries must be objects",
            )
            continue
        step_id = row.get("step_id")
        check_type = row.get("check_type")
        if not _is_nonempty_string(step_id):
            _diag(
                diagnostics,
                "MALFORMED_LEGACY_ARTIFACT_CHECK",
                f"{path}.step_id",
                "legacy artifact check step_id must be a non-empty string",
            )
        if not _is_nonempty_string(check_type):
            _diag(
                diagnostics,
                "MALFORMED_LEGACY_ARTIFACT_CHECK",
                f"{path}.check_type",
                "legacy artifact check type must be a non-empty string",
                step_id=step_id.strip() if isinstance(step_id, str) else None,
            )
        if _is_nonempty_string(step_id) and step_id.strip() not in {step["step_id"] for step in normalized_steps}:
            _diag(
                diagnostics,
                "UNKNOWN_LEGACY_ARTIFACT_CHECK_STEP",
                f"{path}.step_id",
                f"legacy artifact check references unknown step '{step_id.strip()}'",
                step_id=step_id.strip(),
            )
        if _is_nonempty_string(check_type) and check_type.strip() not in legacy_check_type_ids:
            _diag(
                diagnostics,
                "UNKNOWN_LEGACY_ARTIFACT_CHECK_TYPE",
                f"{path}.check_type",
                f"legacy artifact check type '{check_type.strip()}' is not registered",
                step_id=step_id.strip() if isinstance(step_id, str) else None,
            )
    return validator_ids


def _validate_dependencies(
    normalized_steps: list[dict[str, Any]],
    steps_by_id: dict[str, dict[str, Any]],
    run_sequence_by_step_id: dict[str, int],
    diagnostics: list[Diagnostic],
) -> dict[str, set[str]]:
    adjacency: dict[str, set[str]] = {}
    for step in sorted(normalized_steps, key=lambda item: item["order_index"]):
        step_id = step["step_id"]
        path = step["_path"]
        deps = step.get("depends_on")
        adjacency[step_id] = set()
        if deps is None:
            continue
        if step["run_sequence"] > 0 and not deps:
            _diag(
                diagnostics,
                "MISSING_DEPENDENCY",
                f"{path}.depends_on",
                "non-root steps must declare at least one dependency",
                step_id=step_id,
            )
        for idx, dep_id in enumerate(deps):
            dep_path = f"{path}.depends_on[{idx}]"
            if dep_id == step_id:
                _diag(
                    diagnostics,
                    "SELF_DEPENDENCY",
                    dep_path,
                    f"step '{step_id}' cannot depend on itself",
                    step_id=step_id,
                )
                continue
            if dep_id not in steps_by_id:
                _diag(
                    diagnostics,
                    "UNKNOWN_DEPENDENCY",
                    dep_path,
                    f"dependency '{dep_id}' does not exist",
                    step_id=step_id,
                )
                continue
            current_run_sequence = step["run_sequence"]
            dep_run_sequence = run_sequence_by_step_id.get(dep_id)
            if dep_run_sequence is not None and dep_run_sequence > current_run_sequence:
                _diag(
                    diagnostics,
                    "FORWARD_DEPENDENCY",
                    dep_path,
                    f"dependency '{dep_id}' points forward from run_sequence {current_run_sequence} to {dep_run_sequence}",
                    step_id=step_id,
                )
            adjacency[step_id].add(dep_id)
    return adjacency


def _compute_dependency_ancestors(adjacency: dict[str, set[str]]) -> dict[str, set[str]]:
    memo: dict[str, set[str]] = {}
    active: set[str] = set()

    def visit(step_id: str) -> set[str]:
        if step_id in memo:
            return memo[step_id]
        if step_id in active:
            return set(adjacency.get(step_id, set()))
        active.add(step_id)
        ancestors = set(adjacency.get(step_id, set()))
        for dep_id in adjacency.get(step_id, set()):
            ancestors.update(visit(dep_id))
        memo[step_id] = ancestors
        active.remove(step_id)
        return ancestors

    for step_id in adjacency:
        visit(step_id)
    return memo


def _validate_cycles(adjacency: dict[str, set[str]], diagnostics: list[Diagnostic]) -> None:
    if not adjacency:
        return
    indegree: dict[str, int] = {node: 0 for node in adjacency}
    dependents: dict[str, set[str]] = {node: set() for node in adjacency}
    for node, deps in adjacency.items():
        for dep in deps:
            if dep not in indegree:
                continue
            indegree[node] += 1
            dependents[dep].add(node)
    queue = sorted([node for node, degree in indegree.items() if degree == 0])
    visited = 0
    while queue:
        node = queue.pop(0)
        visited += 1
        for dependent in sorted(dependents[node]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)
                queue.sort()
    if visited != len(adjacency):
        blocked = sorted(node for node, degree in indegree.items() if degree > 0)
        _diag(
            diagnostics,
            "DEPENDENCY_CYCLE",
            "$.steps",
            f"dependency cycle detected among steps {blocked}",
        )


def _collect_merge_semantics(
    manifest: dict[str, Any],
    diagnostics: list[Diagnostic],
) -> dict[str, dict[str, Any]]:
    merge_rows: dict[str, dict[str, Any]] = {}
    raw = manifest.get("merge_semantics", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        _diag(
            diagnostics,
            "MALFORMED_MERGE_SEMANTICS",
            "$.merge_semantics",
            "merge_semantics must be a list",
        )
        return merge_rows
    for idx, row in enumerate(raw):
        path = f"$.merge_semantics[{idx}]"
        if not isinstance(row, dict):
            _diag(diagnostics, "MALFORMED_MERGE_SEMANTICS", path, "merge_semantics entries must be objects")
            continue
        artifact_contract = row.get("artifact_contract")
        name = row.get("name")
        producers = _normalize_string_list(
            row.get("producers"),
            diagnostics,
            f"{path}.producers",
            "MALFORMED_MERGE_SEMANTICS",
            allow_empty=False,
        )
        if not _is_nonempty_string(artifact_contract):
            _diag(
                diagnostics,
                "MALFORMED_MERGE_SEMANTICS",
                f"{path}.artifact_contract",
                "artifact_contract must be a non-empty string",
            )
            continue
        normalized_artifact = artifact_contract.strip()
        if not _is_nonempty_string(name):
            _diag(
                diagnostics,
                "MALFORMED_MERGE_SEMANTICS",
                f"{path}.name",
                "name must be a non-empty string",
                artifact_contract=normalized_artifact,
            )
            continue
        if producers is None:
            continue
        if normalized_artifact in merge_rows:
            _diag(
                diagnostics,
                "DUPLICATE_MERGE_SEMANTICS",
                path,
                f"merge_semantics already declared for artifact '{normalized_artifact}'",
                artifact_contract=normalized_artifact,
            )
            continue
        merge_rows[normalized_artifact] = {
            "artifact_contract": normalized_artifact,
            "name": name.strip(),
            "producers": sorted(set(producers)),
            "_path": path,
        }
    return merge_rows


def _validate_artifact_graph(
    manifest: dict[str, Any],
    normalized_steps: list[dict[str, Any]],
    steps_by_id: dict[str, dict[str, Any]],
    dependency_ancestors: dict[str, set[str]],
    diagnostics: list[Diagnostic],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    merge_rows = _collect_merge_semantics(manifest, diagnostics)
    producers_by_artifact: dict[str, list[str]] = {}
    consumers_by_artifact: dict[str, list[str]] = {}

    for step in sorted(normalized_steps, key=lambda item: item["order_index"]):
        step_id = step["step_id"]
        for artifact in step.get("produces") or []:
            producers_by_artifact.setdefault(artifact, []).append(step_id)
        for artifact in step.get("consumes") or []:
            consumers_by_artifact.setdefault(artifact, []).append(step_id)

    for artifact, producers in sorted(producers_by_artifact.items()):
        normalized_producers = sorted(producers)
        if len(normalized_producers) > 1:
            merge_row = merge_rows.get(artifact)
            if merge_row is None:
                _diag(
                    diagnostics,
                    "DUPLICATE_PRODUCERS",
                    "$.steps",
                    f"artifact '{artifact}' has duplicate producers {normalized_producers} but no merge_semantics declaration",
                    artifact_contract=artifact,
                )
            elif merge_row["producers"] != normalized_producers:
                _diag(
                    diagnostics,
                    "INCOMPLETE_MERGE_SEMANTICS",
                    merge_row["_path"],
                    f"merge_semantics for artifact '{artifact}' must name all producers {normalized_producers}; got {merge_row['producers']}",
                    artifact_contract=artifact,
                )

    for step in sorted(normalized_steps, key=lambda item: item["order_index"]):
        step_id = step["step_id"]
        path = step["_path"]
        for idx, artifact in enumerate(step.get("consumes") or []):
            if artifact not in producers_by_artifact:
                _diag(
                    diagnostics,
                    "MISSING_PRODUCER",
                    f"{path}.consumes[{idx}]",
                    f"artifact '{artifact}' is consumed by step '{step_id}' but no step produces it",
                    step_id=step_id,
                    artifact_contract=artifact,
                )
                continue
            producer_step_ids = sorted(producers_by_artifact.get(artifact, []))
            for producer_step_id in producer_step_ids:
                producer_step = steps_by_id[producer_step_id]
                if producer_step["run_sequence"] >= step["run_sequence"]:
                    _diag(
                        diagnostics,
                        "FUTURE_PRODUCER",
                        f"{path}.consumes[{idx}]",
                        f"artifact '{artifact}' producer '{producer_step_id}' must precede consumer '{step_id}'",
                        step_id=step_id,
                        artifact_contract=artifact,
                    )
                if producer_step_id not in dependency_ancestors.get(step_id, set()):
                    _diag(
                        diagnostics,
                        "MISSING_DEPENDENCY_PATH",
                        f"{path}.consumes[{idx}]",
                        f"artifact '{artifact}' producer '{producer_step_id}' is not a dependency ancestor of consumer '{step_id}'",
                        step_id=step_id,
                        artifact_contract=artifact,
                    )
        for idx, downstream_step_id in enumerate(step.get("invalidates") or []):
            ref_path = f"{path}.invalidates[{idx}]"
            if downstream_step_id not in steps_by_id:
                _diag(
                    diagnostics,
                    "INVALID_INVALIDATES_REFERENCE",
                    ref_path,
                    f"invalidates references unknown step '{downstream_step_id}'",
                    step_id=step_id,
                )
                continue
            if downstream_step_id == step_id:
                _diag(
                    diagnostics,
                    "INVALID_INVALIDATES_REFERENCE",
                    ref_path,
                    f"step '{step_id}' cannot invalidate itself",
                    step_id=step_id,
                )
                continue
            if steps_by_id[downstream_step_id]["run_sequence"] <= step["run_sequence"]:
                _diag(
                    diagnostics,
                    "INVALID_INVALIDATES_REFERENCE",
                    ref_path,
                    f"invalidates target '{downstream_step_id}' must be downstream of '{step_id}'",
                    step_id=step_id,
                )

    for artifact, producers in sorted(producers_by_artifact.items()):
        consumers = consumers_by_artifact.get(artifact, [])
        if consumers:
            continue
        for producer_step_id in sorted(producers):
            producer_step = steps_by_id[producer_step_id]
            if producer_step.get("terminal_output") is True:
                continue
            _diag(
                diagnostics,
                "ORPHAN_PRODUCED_ARTIFACT",
                f"{producer_step['_path']}.produces",
                f"artifact '{artifact}' is produced by step '{producer_step_id}' but has no consumer; declare terminal_output=true if it is terminal",
                step_id=producer_step_id,
                artifact_contract=artifact,
            )

    return producers_by_artifact, consumers_by_artifact


def _validate_artifact_contract_registry(
    manifest: dict[str, Any],
    steps_by_id: dict[str, dict[str, Any]],
    producers_by_artifact: dict[str, list[str]],
    consumers_by_artifact: dict[str, list[str]],
    validator_ids: set[str],
    diagnostics: list[Diagnostic],
) -> None:
    raw = manifest.get("artifact_contracts")
    if not isinstance(raw, list) or not raw:
        _diag(
            diagnostics,
            "MALFORMED_ARTIFACT_CONTRACT_REGISTRY",
            "$.artifact_contracts",
            "artifact_contracts must be a non-empty list of objects",
        )
        return
    contracts: dict[str, dict[str, Any]] = {}
    for idx, row in enumerate(raw):
        path = f"$.artifact_contracts[{idx}]"
        if not isinstance(row, dict):
            _diag(diagnostics, "MALFORMED_ARTIFACT_CONTRACT", path, "artifact contract must be an object")
            continue
        contract_id = row.get("id")
        relative_path = row.get("path")
        kind = row.get("kind")
        terminal = row.get("terminal")
        freshness_policy = row.get("freshness_policy", "must_refresh")
        producers = _normalize_string_list(
            row.get("producer_step_ids"),
            diagnostics,
            f"{path}.producer_step_ids",
            "MALFORMED_ARTIFACT_CONTRACT",
            allow_empty=False,
            duplicate_code="DUPLICATE_ARTIFACT_PRODUCER",
        )
        consumers = _normalize_string_list(
            row.get("consumer_step_ids"),
            diagnostics,
            f"{path}.consumer_step_ids",
            "MALFORMED_ARTIFACT_CONTRACT",
            allow_empty=True,
            duplicate_code="DUPLICATE_ARTIFACT_CONSUMER",
        )
        contract_validators = _normalize_string_list(
            row.get("validators"),
            diagnostics,
            f"{path}.validators",
            "MALFORMED_ARTIFACT_CONTRACT",
            allow_empty=False,
            duplicate_code="DUPLICATE_ARTIFACT_VALIDATOR",
        )
        if not _is_nonempty_string(contract_id):
            _diag(diagnostics, "MALFORMED_ARTIFACT_CONTRACT", f"{path}.id", "artifact contract id must be a non-empty string")
            continue
        normalized_id = contract_id.strip()
        if normalized_id in contracts:
            _diag(diagnostics, "DUPLICATE_ARTIFACT_CONTRACT", f"{path}.id", f"duplicate artifact contract id '{normalized_id}'", artifact_contract=normalized_id)
            continue
        if not _is_nonempty_string(relative_path):
            _diag(diagnostics, "MALFORMED_ARTIFACT_PATH", f"{path}.path", "artifact path must be a non-empty workspace-relative path", artifact_contract=normalized_id)
        else:
            normalized_path = Path(relative_path.strip())
            if normalized_path.is_absolute() or ".." in normalized_path.parts or PLACEHOLDER_RE.search(relative_path) or LEGACY_PLACEHOLDER_RE.search(relative_path):
                _diag(diagnostics, "MALFORMED_ARTIFACT_PATH", f"{path}.path", "artifact path must be workspace-relative and contain no placeholders or parent traversal", artifact_contract=normalized_id)
        if kind not in {"file", "directory"}:
            _diag(diagnostics, "MALFORMED_ARTIFACT_KIND", f"{path}.kind", "artifact contract kind must be 'file' or 'directory'", artifact_contract=normalized_id)
        if freshness_policy not in {"must_refresh", "validate_existing"}:
            _diag(
                diagnostics,
                "MALFORMED_ARTIFACT_FRESHNESS_POLICY",
                f"{path}.freshness_policy",
                "freshness_policy must be 'must_refresh' or 'validate_existing'",
                artifact_contract=normalized_id,
            )
        if not isinstance(terminal, bool):
            _diag(diagnostics, "MALFORMED_ARTIFACT_CONTRACT", f"{path}.terminal", "artifact terminal must be a boolean", artifact_contract=normalized_id)
        for validator_idx, validator_id in enumerate(contract_validators or []):
            if validator_id not in validator_ids:
                _diag(
                    diagnostics,
                    "UNKNOWN_ARTIFACT_VALIDATOR",
                    f"{path}.validators[{validator_idx}]",
                    f"artifact contract references unknown validator '{validator_id}'",
                    artifact_contract=normalized_id,
                )
        contracts[normalized_id] = {
            "producer_step_ids": sorted(producers or []),
            "consumer_step_ids": sorted(consumers or []),
            "terminal": terminal,
            "freshness_policy": freshness_policy,
            "_path": path,
        }

    graph_ids = set(producers_by_artifact) | set(consumers_by_artifact)
    for artifact in sorted(graph_ids - set(contracts)):
        _diag(
            diagnostics,
            "UNKNOWN_ARTIFACT_CONTRACT",
            "$.steps",
            f"step graph references artifact '{artifact}' absent from artifact_contracts",
            artifact_contract=artifact,
        )
    for artifact in sorted(set(contracts) - graph_ids):
        _diag(
            diagnostics,
            "UNREFERENCED_ARTIFACT_CONTRACT",
            contracts[artifact]["_path"],
            f"artifact contract '{artifact}' is not produced or consumed by any step",
            artifact_contract=artifact,
        )
    for artifact in sorted(graph_ids & set(contracts)):
        contract = contracts[artifact]
        actual_producers = sorted(producers_by_artifact.get(artifact, []))
        actual_consumers = sorted(consumers_by_artifact.get(artifact, []))
        if contract["producer_step_ids"] != actual_producers:
            _diag(
                diagnostics,
                "ARTIFACT_PRODUCER_REGISTRY_MISMATCH",
                f"{contract['_path']}.producer_step_ids",
                f"artifact '{artifact}' registry producers {contract['producer_step_ids']} do not match step graph {actual_producers}",
                artifact_contract=artifact,
            )
        if contract["consumer_step_ids"] != actual_consumers:
            _diag(
                diagnostics,
                "ARTIFACT_CONSUMER_REGISTRY_MISMATCH",
                f"{contract['_path']}.consumer_step_ids",
                f"artifact '{artifact}' registry consumers {contract['consumer_step_ids']} do not match step graph {actual_consumers}",
                artifact_contract=artifact,
            )
        expected_terminal = bool(actual_producers and not actual_consumers)
        if contract["terminal"] is not expected_terminal:
            _diag(
                diagnostics,
                "ARTIFACT_TERMINAL_REGISTRY_MISMATCH",
                f"{contract['_path']}.terminal",
                f"artifact '{artifact}' terminal must be {str(expected_terminal).lower()} for its declared routes",
                artifact_contract=artifact,
            )
        if contract["freshness_policy"] == "validate_existing":
            for producer_step_id in contract["producer_step_ids"]:
                producer = steps_by_id.get(producer_step_id, {})
                verification = producer.get("how_to_verify_done")
                step_class = producer.get("class", "")
                if (
                    producer.get("phase") != "intake"
                    or not isinstance(step_class, str)
                    or not step_class.startswith("manual")
                    or not isinstance(verification, dict)
                    or verification.get("attestation_required") is not True
                ):
                    _diag(
                        diagnostics,
                        "INVALID_VALIDATE_EXISTING_POLICY",
                        f"{contract['_path']}.freshness_policy",
                        "validate_existing is restricted to attested manual intake producers",
                        step_id=producer_step_id,
                        artifact_contract=artifact,
                    )
        for step_id in contract["producer_step_ids"] + contract["consumer_step_ids"]:
            if step_id not in steps_by_id:
                _diag(
                    diagnostics,
                    "UNKNOWN_ARTIFACT_ROUTE_STEP",
                    contract["_path"],
                    f"artifact '{artifact}' references unknown step '{step_id}'",
                    step_id=step_id,
                    artifact_contract=artifact,
                )


def _validate_reasoner_routes(
    manifest: dict[str, Any],
    steps_by_id: dict[str, dict[str, Any]],
    producers_by_artifact: dict[str, list[str]],
    consumers_by_artifact: dict[str, list[str]],
    diagnostics: list[Diagnostic],
) -> None:
    raw_registry = manifest.get("reasoner_registry")
    registered_by_step: dict[str, dict[str, str]] = {}
    if not isinstance(raw_registry, list):
        _diag(diagnostics, "MALFORMED_REASONER_REGISTRY", "$.reasoner_registry", "reasoner_registry must be a list")
        raw_registry = []
    seen_reasoner_ids: set[str] = set()
    for idx, row in enumerate(raw_registry):
        path = f"$.reasoner_registry[{idx}]"
        if not isinstance(row, dict):
            _diag(diagnostics, "MALFORMED_REASONER_REGISTRY", path, "reasoner registry entries must be objects")
            continue
        reasoner_id = row.get("id")
        step_id = row.get("step_id")
        ledger_artifact = row.get("ledger_artifact")
        if not all(_is_nonempty_string(value) for value in (reasoner_id, step_id, ledger_artifact)):
            _diag(diagnostics, "MALFORMED_REASONER_REGISTRY", path, "reasoner registry entries require id, step_id, and ledger_artifact")
            continue
        normalized_id = reasoner_id.strip()
        normalized_step = step_id.strip()
        if normalized_id in seen_reasoner_ids or normalized_step in registered_by_step:
            _diag(diagnostics, "DUPLICATE_REASONER_REGISTRY_ENTRY", path, f"duplicate reasoner registry id or step for '{normalized_id}'")
            continue
        seen_reasoner_ids.add(normalized_id)
        registered_by_step[normalized_step] = {
            "id": normalized_id,
            "ledger_artifact": ledger_artifact.strip(),
            "_path": path,
        }
    raw = manifest.get("reasoner_routes", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        _diag(diagnostics, "MALFORMED_REASONER_ROUTES", "$.reasoner_routes", "reasoner_routes must be a list")
        return
    route_counts: dict[str, int] = {}
    for idx, row in enumerate(raw):
        path = f"$.reasoner_routes[{idx}]"
        if not isinstance(row, dict):
            _diag(diagnostics, "MALFORMED_REASONER_ROUTE", path, "reasoner_routes entries must be objects")
            continue
        step_id = row.get("step_id")
        reasoner_id = row.get("reasoner_id")
        ledger_artifact = row.get("ledger_artifact")
        producer_step_id = row.get("producer_step_id")
        consumer_step_ids = _normalize_string_list(
            row.get("consumer_step_ids"),
            diagnostics,
            f"{path}.consumer_step_ids",
            "INCOMPLETE_REASONER_ROUTE",
            allow_empty=False,
        )
        required_pairs = (
            ("step_id", step_id),
            ("reasoner_id", reasoner_id),
            ("ledger_artifact", ledger_artifact),
            ("producer_step_id", producer_step_id),
            ("queue_step_id", row.get("queue_step_id")),
            ("question_step_id", row.get("question_step_id")),
            ("proof_step_id", row.get("proof_step_id")),
            ("resolution_step_id", row.get("resolution_step_id")),
        )
        missing_scalar = False
        for field_name, value in required_pairs:
            if not _is_nonempty_string(value):
                _diag(
                    diagnostics,
                    "INCOMPLETE_REASONER_ROUTE",
                    f"{path}.{field_name}",
                    f"reasoner route field '{field_name}' must be a non-empty string",
                )
                missing_scalar = True
        if missing_scalar or consumer_step_ids is None:
            continue
        normalized_step_id = step_id.strip()
        normalized_reasoner_id = reasoner_id.strip()
        normalized_ledger = ledger_artifact.strip()
        normalized_producer = producer_step_id.strip()
        route_counts[normalized_step_id] = route_counts.get(normalized_step_id, 0) + 1
        if normalized_step_id not in steps_by_id:
            _diag(
                diagnostics,
                "INVALID_REASONER_ROUTE",
                f"{path}.step_id",
                f"reasoner route references unknown step '{normalized_step_id}'",
                step_id=normalized_step_id,
            )
            continue
        if steps_by_id[normalized_step_id]["phase"] != "reasoning":
            _diag(
                diagnostics,
                "INVALID_REASONER_ROUTE",
                f"{path}.step_id",
                f"reasoner route step '{normalized_step_id}' must have phase 'reasoning'",
                step_id=normalized_step_id,
            )
        registry_row = registered_by_step.get(normalized_step_id)
        if registry_row is None:
            _diag(
                diagnostics,
                "MISSING_REASONER_REGISTRY_ENTRY",
                f"{path}.step_id",
                f"reasoner route step '{normalized_step_id}' is absent from reasoner_registry",
                step_id=normalized_step_id,
            )
        elif registry_row["id"] != normalized_reasoner_id or registry_row["ledger_artifact"] != normalized_ledger:
            _diag(
                diagnostics,
                "REASONER_REGISTRY_ROUTE_MISMATCH",
                path,
                f"reasoner route for '{normalized_step_id}' does not match its registry id and ledger artifact",
                step_id=normalized_step_id,
                artifact_contract=normalized_ledger,
            )
        if normalized_producer not in steps_by_id:
            _diag(
                diagnostics,
                "INVALID_REASONER_ROUTE",
                f"{path}.producer_step_id",
                f"reasoner route references unknown producer step '{normalized_producer}'",
                step_id=normalized_step_id,
                artifact_contract=normalized_ledger,
            )
            continue
        produced_by = sorted(producers_by_artifact.get(normalized_ledger, []))
        if not produced_by:
            _diag(
                diagnostics,
                "INVALID_REASONER_ROUTE",
                f"{path}.ledger_artifact",
                f"reasoner ledger artifact '{normalized_ledger}' has no producer",
                step_id=normalized_step_id,
                artifact_contract=normalized_ledger,
            )
        elif normalized_producer not in produced_by:
            _diag(
                diagnostics,
                "INVALID_REASONER_ROUTE",
                f"{path}.producer_step_id",
                f"producer step '{normalized_producer}' does not produce ledger artifact '{normalized_ledger}'",
                step_id=normalized_step_id,
                artifact_contract=normalized_ledger,
            )
        for consumer_idx, consumer_step_id in enumerate(consumer_step_ids):
            if consumer_step_id not in steps_by_id:
                _diag(
                    diagnostics,
                    "INVALID_REASONER_ROUTE",
                    f"{path}.consumer_step_ids[{consumer_idx}]",
                    f"reasoner route references unknown consumer step '{consumer_step_id}'",
                    step_id=normalized_step_id,
                    artifact_contract=normalized_ledger,
                )
                continue
            known_consumers = set(consumers_by_artifact.get(normalized_ledger, []))
            if consumer_step_id not in known_consumers:
                _diag(
                    diagnostics,
                    "INVALID_REASONER_ROUTE",
                    f"{path}.consumer_step_ids[{consumer_idx}]",
                    f"consumer step '{consumer_step_id}' does not consume ledger artifact '{normalized_ledger}'",
                    step_id=normalized_step_id,
                    artifact_contract=normalized_ledger,
                )
        route_fields = (
            "queue_step_id",
            "question_step_id",
            "proof_step_id",
            "resolution_step_id",
        )
        declared_consumers = set(consumer_step_ids)
        for field_name in route_fields:
            consumer_step_id = row[field_name].strip()
            if consumer_step_id not in declared_consumers:
                _diag(
                    diagnostics,
                    "INCOMPLETE_REASONER_ROUTE",
                    f"{path}.{field_name}",
                    f"{field_name} '{consumer_step_id}' must be listed in consumer_step_ids",
                    step_id=normalized_step_id,
                    artifact_contract=normalized_ledger,
                )
            if consumer_step_id not in consumers_by_artifact.get(normalized_ledger, []):
                _diag(
                    diagnostics,
                    "INVALID_REASONER_ROUTE",
                    f"{path}.{field_name}",
                    f"{field_name} '{consumer_step_id}' does not consume ledger artifact '{normalized_ledger}'",
                    step_id=normalized_step_id,
                    artifact_contract=normalized_ledger,
                )
    reasoning_step_ids = sorted(
        step_id
        for step_id, step in steps_by_id.items()
        if step.get("phase") == "reasoning" and step.get("class") != "orchestration"
    )
    for step_id in reasoning_step_ids:
        count = route_counts.get(step_id, 0)
        step_path = steps_by_id[step_id]["_path"]
        if count == 0:
            _diag(
                diagnostics,
                "MISSING_REASONER_ROUTE",
                f"{step_path}.phase",
                f"reasoning step '{step_id}' must have exactly one reasoner_routes row",
                step_id=step_id,
            )
        elif count > 1:
            _diag(
                diagnostics,
                "DUPLICATE_REASONER_ROUTE",
                "$.reasoner_routes",
                f"reasoning step '{step_id}' has {count} reasoner_routes rows; expected exactly one",
                step_id=step_id,
            )
        if step_id not in registered_by_step:
            _diag(
                diagnostics,
                "MISSING_REASONER_REGISTRY_ENTRY",
                f"{step_path}.phase",
                f"reasoning step '{step_id}' must have exactly one reasoner_registry row",
                step_id=step_id,
            )
    for step_id, row in sorted(registered_by_step.items()):
        if step_id not in steps_by_id:
            _diag(
                diagnostics,
                "INVALID_REASONER_REGISTRY_ENTRY",
                row["_path"],
                f"reasoner registry references unknown step '{step_id}'",
                step_id=step_id,
            )
        elif steps_by_id[step_id].get("phase") != "reasoning":
            _diag(
                diagnostics,
                "INVALID_REASONER_REGISTRY_ENTRY",
                row["_path"],
                f"reasoner registry step '{step_id}' must have phase 'reasoning'",
                step_id=step_id,
            )


def _render_result(manifest_path: str, diagnostics: list[Diagnostic]) -> dict[str, Any]:
    sorted_diagnostics = sorted(
        diagnostics,
        key=lambda item: (
            item.path,
            item.code,
            item.step_id or "",
            item.artifact_contract or "",
            item.message,
        ),
    )
    return {
        "schema": SCHEMA,
        "manifest_path": manifest_path,
        "valid": not sorted_diagnostics,
        "error_count": len(sorted_diagnostics),
        "diagnostics": [asdict(item) for item in sorted_diagnostics],
    }


def validate_manifest(manifest: Any, *, manifest_path: str = "<memory>") -> dict[str, Any]:
    diagnostics: list[Diagnostic] = []
    top_level = _validate_top_level(manifest, diagnostics)
    if top_level is None:
        return _render_result(manifest_path, diagnostics)

    (
        normalized_steps,
        steps_by_id,
        order_by_step_id,
        step_id_by_order,
        run_sequence_by_step_id,
        step_id_by_run_sequence,
    ) = _validate_steps(top_level["steps"], diagnostics)
    _validate_sequence_contiguity(
        step_id_by_order,
        diagnostics,
        code="NON_CONTIGUOUS_ORDER_INDEX",
        label="order_index",
    )
    _validate_sequence_contiguity(
        step_id_by_run_sequence,
        diagnostics,
        code="NON_CONTIGUOUS_RUN_SEQUENCE",
        label="run_sequence",
    )
    validator_ids = _validate_registries_and_targets(top_level, normalized_steps, diagnostics)
    adjacency = _validate_dependencies(normalized_steps, steps_by_id, run_sequence_by_step_id, diagnostics)
    _validate_cycles(adjacency, diagnostics)
    dependency_ancestors = _compute_dependency_ancestors(adjacency)
    producers_by_artifact, consumers_by_artifact = _validate_artifact_graph(
        top_level,
        normalized_steps,
        steps_by_id,
        dependency_ancestors,
        diagnostics,
    )
    _validate_artifact_contract_registry(
        top_level,
        steps_by_id,
        producers_by_artifact,
        consumers_by_artifact,
        validator_ids,
        diagnostics,
    )
    _validate_reasoner_routes(
        top_level,
        steps_by_id,
        producers_by_artifact,
        consumers_by_artifact,
        diagnostics,
    )
    return _render_result(manifest_path, diagnostics)


def validate_manifest_file(path: str | Path) -> dict[str, Any]:
    manifest_path = str(Path(path).expanduser().resolve())
    try:
        manifest = _load_json(Path(manifest_path))
    except (OSError, ValueError) as exc:
        return _render_result(
            manifest_path,
            [
                Diagnostic(
                    severity="error",
                    code="MANIFEST_LOAD_ERROR",
                    path="$",
                    message=f"failed to load manifest: {exc}",
                )
            ],
        )
    return validate_manifest(manifest, manifest_path=manifest_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", required=True, help="Path to a pipeline manifest JSON file")
    args = parser.parse_args(argv)

    result = validate_manifest_file(args.manifest)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
