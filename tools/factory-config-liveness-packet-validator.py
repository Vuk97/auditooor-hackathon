#!/usr/bin/env python3
"""Validate factory/config/liveness provider packets before dispatch.

The generic dispatch-template preflight proves that a prompt has the broad
source-extract/adversarial-kill inputs. This validator adds lane-specific
structural checks for the factory-config-liveness packet variants so Kimi and
Minimax calibration samples start from comparable, machine-checkable packets.

It is intentionally offline and advisory: passing validation means the packet
shape is ready for provider use, not that any candidate is true.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover - repo tooling depends on PyYAML
    print(f"factory-config-liveness-packet-validator: PyYAML required ({exc})", file=sys.stderr)
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent
PACKET_DIR = REPO_ROOT / "reference" / "dispatch-packets"

EXTRACTION_TASK = "factory-config-liveness-extraction"
KILL_TASK = "factory-config-liveness-kill"
TASK_TYPES = (EXTRACTION_TASK, KILL_TASK)

LINE_REF_RE = re.compile(r"^[^\s:]+(?::\d+(?:-\d+)?)$")
EXTRACTION_CLASSES = {
    "factory-created-instance",
    "mutable-config-edge",
    "liveness-dependency",
}
KILL_VERDICTS = {
    "KEEP_FOR_LOCAL_VERIFICATION",
    "REJECT_SELF_CONFIG",
    "REJECT_ADMIN_ONLY",
    "REJECT_OOS",
    "REJECT_MOCK_OR_TEST_ONLY",
    "REJECT_MISSING_LIVE_PROOF",
    "REJECT_DUPLICATE",
    "NEEDS_MORE_SOURCE",
}


def _strip_markdown_heading(text: str) -> str:
    lines = text.splitlines()
    while lines and (not lines[0].strip() or lines[0].lstrip().startswith("#")):
        lines.pop(0)
    return "\n".join(lines).strip() + "\n"


def load_packet(path: Path) -> Dict[str, Any]:
    try:
        data = yaml.safe_load(_strip_markdown_heading(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML parse failed: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("packet body must parse as a YAML mapping")
    return data


def _present(data: Dict[str, Any], field: str, errors: List[str]) -> Any:
    value = data.get(field)
    if value in (None, "", []):
        errors.append(f"missing required field: {field}")
    return value


def _string_field(data: Dict[str, Any], field: str, errors: List[str]) -> str:
    value = _present(data, field, errors)
    if value in (None, "", []):
        return ""
    if not isinstance(value, str):
        errors.append(f"{field} must be a string")
        return ""
    return value


def _list_field(data: Dict[str, Any], field: str, errors: List[str]) -> List[Any]:
    value = _present(data, field, errors)
    if value in (None, "", []):
        return []
    if not isinstance(value, list):
        errors.append(f"{field} must be a non-empty list")
        return []
    if not value:
        errors.append(f"{field} must be a non-empty list")
    return value


def _check_line_refs(values: Iterable[Any], field: str, errors: List[str]) -> None:
    for idx, value in enumerate(values):
        if not isinstance(value, str):
            errors.append(f"{field}[{idx}] must be a string line reference")
            continue
        if not LINE_REF_RE.match(value):
            errors.append(f"{field}[{idx}] must include an exact file:line or file:line-line reference")


def _check_expected_shape(value: str, token: str, errors: List[str]) -> None:
    if token not in value:
        errors.append(f"expected_output_shape must mention {token} exactly")


def _check_live_state_list(value: Any, field: str, errors: List[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{field} must be a non-empty list")
        return
    for idx, row in enumerate(value):
        if not isinstance(row, dict):
            errors.append(f"{field}[{idx}] must be a mapping")
            continue
        for key in ("check_id", "expected_value"):
            if row.get(key) in (None, ""):
                errors.append(f"{field}[{idx}] missing {key}")


def validate_extraction_packet(data: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    _string_field(data, "workspace_path", errors)
    target_files = _list_field(data, "target_files", errors)
    _check_line_refs(target_files, "target_files", errors)
    _list_field(data, "topology_artifacts", errors)
    hypotheses = _list_field(data, "hypotheses", errors)
    if hypotheses and not all(isinstance(item, str) and item.strip() for item in hypotheses):
        errors.append("hypotheses must contain non-empty strings")
    _present(data, "prior_failed_attempts", errors)
    expected = _string_field(data, "expected_output_shape", errors)
    _check_expected_shape(expected, "factory_config_liveness_candidate_v1", errors)
    for token in (
        "candidate_id",
        "class",
        "source_files_and_lines",
        "factory_or_config_source",
        "affected_instance_or_role",
        "non_privileged_trigger_path",
        "required_live_state",
        "self_config_risk",
        "oos_risk",
        "impact_hypothesis",
        "minimum_local_verification",
        "handoff_to_minimax",
    ):
        if expected and token not in expected:
            errors.append(f"expected_output_shape missing candidate field: {token}")
    return errors


def _validate_candidate(candidate: Any, idx: int, errors: List[str]) -> None:
    prefix = f"candidate_list[{idx}]"
    if not isinstance(candidate, dict):
        errors.append(f"{prefix} must be a mapping")
        return
    for field in (
        "candidate_id",
        "class",
        "source_files_and_lines",
        "factory_or_config_source",
        "affected_instance_or_role",
        "non_privileged_trigger_path",
        "required_live_state",
        "self_config_risk",
        "oos_risk",
        "impact_hypothesis",
        "minimum_local_verification",
        "handoff_to_minimax",
    ):
        if candidate.get(field) in (None, "", []):
            errors.append(f"{prefix} missing {field}")
    candidate_id = candidate.get("candidate_id")
    if isinstance(candidate_id, str) and not candidate_id.startswith("FCL-"):
        errors.append(f"{prefix}.candidate_id must start with FCL-")
    cls = candidate.get("class")
    if cls not in EXTRACTION_CLASSES:
        errors.append(f"{prefix}.class must be one of {sorted(EXTRACTION_CLASSES)}")
    source_refs = candidate.get("source_files_and_lines")
    if isinstance(source_refs, list):
        _check_line_refs(source_refs, f"{prefix}.source_files_and_lines", errors)
    factory_ref = candidate.get("factory_or_config_source")
    if isinstance(factory_ref, str) and factory_ref != "unknown" and not LINE_REF_RE.match(factory_ref):
        errors.append(f"{prefix}.factory_or_config_source must be unknown or an exact line reference")
    _check_live_state_list(candidate.get("required_live_state"), f"{prefix}.required_live_state", errors)
    local_checks = candidate.get("minimum_local_verification")
    if not isinstance(local_checks, list) or not local_checks:
        errors.append(f"{prefix}.minimum_local_verification must be a non-empty list")
    handoff = candidate.get("handoff_to_minimax")
    if handoff not in {"include", "exclude"}:
        errors.append(f"{prefix}.handoff_to_minimax must be include or exclude")


def validate_kill_packet(data: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    _string_field(data, "workspace_path", errors)
    candidates = _list_field(data, "candidate_list", errors)
    for idx, candidate in enumerate(candidates):
        _validate_candidate(candidate, idx, errors)
    snippets = _list_field(data, "source_snippets", errors)
    if snippets and not all(isinstance(item, str) and ":" in item for item in snippets):
        errors.append("source_snippets must contain source-cited strings")
    _list_field(data, "topology_artifacts", errors)
    _present(data, "oos_text", errors)
    truncation = _string_field(data, "truncation_flag", errors)
    if truncation and truncation not in {"complete", "truncated"}:
        errors.append("truncation_flag must be complete or truncated")
    expected = _string_field(data, "expected_output_shape", errors)
    _check_expected_shape(expected, "factory_config_liveness_kill_v1", errors)
    for token in (
        "candidate_id",
        "verdict",
        "kill_reason",
        "contradiction_citation",
        "required_next_check",
        "confidence",
    ):
        if expected and token not in expected:
            errors.append(f"expected_output_shape missing kill field: {token}")
    return errors


def validate_packet(data: Dict[str, Any], task_type: str) -> List[str]:
    if task_type == EXTRACTION_TASK:
        return validate_extraction_packet(data)
    if task_type == KILL_TASK:
        return validate_kill_packet(data)
    raise ValueError(f"unknown task type: {task_type}")


def _default_packet_for_task(task_type: str) -> Path:
    if task_type == EXTRACTION_TASK:
        return PACKET_DIR / "factory-config-liveness-extraction.example.md"
    if task_type == KILL_TASK:
        return PACKET_DIR / "factory-config-liveness-kill.example.md"
    raise ValueError(f"unknown task type: {task_type}")


def _result_payload(packet: Path, task_type: str, errors: Sequence[str]) -> Dict[str, Any]:
    return {
        "ok": not errors,
        "packet": str(packet),
        "task_type": task_type,
        "errors": list(errors),
        "advisory_only": True,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate factory-config-liveness extraction/kill packets structurally."
    )
    parser.add_argument("--task-type", choices=TASK_TYPES, required=True)
    parser.add_argument("--packet", help="packet markdown/YAML file to validate")
    parser.add_argument("--json", action="store_true", help="emit JSON result")
    args = parser.parse_args(argv)

    packet = Path(args.packet).expanduser() if args.packet else _default_packet_for_task(args.task_type)
    if not packet.is_file():
        print(f"packet not found: {packet}", file=sys.stderr)
        return 2
    try:
        data = load_packet(packet)
        errors = validate_packet(data, args.task_type)
    except ValueError as exc:
        errors = [str(exc)]

    payload = _result_payload(packet, args.task_type, errors)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif errors:
        print(f"factory-config-liveness packet REFUSE: {packet}", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
    else:
        print(
            f"factory-config-liveness packet OK: {packet} "
            f"({args.task_type}, advisory-only)"
        )
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
