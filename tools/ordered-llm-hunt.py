#!/usr/bin/env python3
"""Dispatch every typed question from the frozen Step 2h zero-day bus.

Step 3 consumes only the immutable bus plus current workspace baselines and the
Step 0f backend attestation. It never reinterprets raw reasoner ledgers, corpus
fuel, novelty feeds, legacy hunt sidecars, or mtime-based freshness signals.
Provider responses are nonterminal hunt evidence, never proof or resolution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCHEMA = "auditooor.ordered_llm_hunt.v2"
RECEIPT_SCHEMA = "auditooor.ordered_llm_hunt_receipt.v2"
BUS_RECEIPT_SCHEMA = "auditooor.zero_day_freeze_receipt.v1"
OBLIGATION_SCHEMA = "auditooor.zero_day_obligation.v1"
QUESTION_SCHEMA = "auditooor.zero_day_question.v1"
EMPTY_SCHEMA = "auditooor.zero_day_examined_empty.v1"
FUEL_SCHEMA = "auditooor.zero_day_fuel.v1"
SIDECAR_SCHEMA = "auditooor.ordered_hunt_sidecar.v2"
OUTPUT_RELATIVE = Path(".auditooor") / "ordered_hunt"
BUS_RELATIVE = Path(".auditooor") / "zero_day_bus"
INVENTORY_RELATIVE = Path(".auditooor") / "inscope_units.jsonl"
ATTESTATION_RELATIVE = Path(".auditooor") / "attestations" / "step-0f.json"
RULES_RELATIVE = Path(".auditooor") / "program_rules.json"
AXES = (
    "asset_invariant",
    "state_transition",
    "adversarial_sequence",
    "assumption_negation",
    "cross_module_composition",
    "production_reachability",
    "economic_consensus_impact",
    "dedup_oos_awareness",
    "executable_falsification",
)
PROVENANCE_HASH_FIELDS = (
    "manifest_sha256",
    "workspace_identity_sha256",
    "source_snapshot_sha256",
    "scope_sha256",
    "severity_sha256",
    "targets_sha256",
    "program_rules_sha256",
    "pipeline_tooling_sha256",
)
SAFE_ENVIRONMENT = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM")
BAD_RESULT_TOKENS = frozenset({"warning", "warn", "degraded", "partial", "failed", "error", "blocked"})
RESULT_KEYS = frozenset({
    "applies_to_target", "confidence", "candidate_finding", "file_line",
    "code_excerpt", "severity_estimate", "rubric_row_cited", "dupe_check",
    "falsification_attempt", "notes",
})


class HuntError(RuntimeError):
    """A fail-closed ordered hunt error with a stable diagnostic code."""


@dataclass(frozen=True)
class Backend:
    provider: str
    model: str
    route: str
    argv_template: tuple[str, ...]
    output_mode: str
    environment: Mapping[str, str]


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], Path, Mapping[str, str], int], CommandResult]


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _json_bytes(value: Any) -> bytes:
    return json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(_canonical(value), handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise HuntError(f"missing_{label}:{path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HuntError(f"malformed_{label}:{path}") from exc
    if not isinstance(value, dict):
        raise HuntError(f"malformed_{label}:{path}")
    return value


def _load_jsonl(path: Path, label: str, *, allow_empty: bool) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise HuntError(f"missing_{label}:{path}")
    rows: list[dict[str, Any]] = []
    try:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise HuntError(f"malformed_{label}:row-{number}")
            rows.append(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HuntError(f"malformed_{label}:{path}") from exc
    if not rows and not allow_empty:
        raise HuntError(f"empty_{label}:{path}")
    return rows


def _selected_environment(extra: Mapping[str, Any] | None) -> dict[str, str]:
    environment = {name: os.environ[name] for name in SAFE_ENVIRONMENT if name in os.environ}
    if extra:
        for name, value in extra.items():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                raise HuntError("backend_environment_name_invalid")
            if not isinstance(value, str) or not value:
                raise HuntError("backend_environment_value_invalid")
            if any(token in name for token in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
                raise HuntError("backend_environment_secret_forbidden")
            environment[name] = value
    return environment


def _truthy_verification(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() in {"pass", "passed", "verified", "ok", "success"}


def _backend_from_attestation(attestation: Mapping[str, Any], provider_config: Mapping[str, Any] | None,
                              requested_provider: str | None) -> Backend:
    required = ("available_tier", "backend_verified_by", "provider", "model", "dispatch_route",
                "verification_command", "verification_result")
    if any(not isinstance(attestation.get(field), str) or not attestation[field].strip() for field in required):
        raise HuntError("backend_attestation_malformed")
    if not _truthy_verification(attestation.get("verification_result")):
        raise HuntError("backend_attestation_not_verified")
    provider = str(attestation["provider"]).strip()
    if requested_provider and requested_provider != provider:
        raise HuntError("selected_provider_mismatches_attestation")
    route = str(attestation["dispatch_route"]).strip()
    model = str(attestation["model"]).strip()
    if route == "codex-cli" and provider in {"codex", "codex-cli"}:
        return Backend(provider, model, route,
                       ("codex", "exec", "--full-auto", "--output-last-message", "{output_file}", "{prompt}"),
                       "file", _selected_environment(attestation.get("environment")))
    config = (provider_config or {}).get(provider)
    if not isinstance(config, Mapping):
        raise HuntError("backend_route_not_configured")
    argv = config.get("argv")
    output_mode = config.get("output", "stdout")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise HuntError("backend_argv_not_configured")
    if output_mode not in {"stdout", "file"}:
        raise HuntError("backend_output_mode_invalid")
    if output_mode == "file" and "{output_file}" not in argv:
        raise HuntError("backend_output_file_placeholder_missing")
    if "{prompt}" not in argv and "{prompt_file}" not in argv:
        raise HuntError("backend_prompt_placeholder_missing")
    environment = config.get("environment", {})
    if environment is not None and not isinstance(environment, Mapping):
        raise HuntError("backend_environment_malformed")
    return Backend(provider, model, route, tuple(argv), str(output_mode), _selected_environment(environment))


def _inventory_unit_id(row: Mapping[str, Any], number: int) -> str:
    for key in ("inventory_unit_id", "unit_id", "id"):
        declared = row.get(key)
        if isinstance(declared, str) and declared.strip():
            return declared.strip()
    identity = {
        key: row[key]
        for key in ("file", "path", "contract", "function", "fn", "start_line", "line")
        if row.get(key) not in {None, ""}
    }
    if not identity:
        raise HuntError(f"inventory_row_missing_identity:{number}")
    return "zdu_" + _stable_hash(identity)


def _current_inputs(workspace: Path) -> dict[str, Any]:
    workspace = workspace.resolve()
    inventory_path = workspace / INVENTORY_RELATIVE
    inventory_rows = _load_jsonl(inventory_path, "inscope_inventory", allow_empty=True)
    source_rows: list[dict[str, Any]] = []
    sources: dict[str, dict[str, Any]] = {}
    unit_ids: list[str] = []
    for number, row in enumerate(inventory_rows, start=1):
        relative = row.get("file") or row.get("path")
        if not isinstance(relative, str) or not relative.strip():
            raise HuntError(f"inventory_row_missing_file:{number}")
        candidate = Path(relative)
        source = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
        try:
            rel = source.relative_to(workspace).as_posix()
        except ValueError as exc:
            raise HuntError(f"inventory_source_outside_workspace:{number}") from exc
        if not source.is_file() or source.is_symlink():
            raise HuntError(f"inventory_source_missing:{rel}")
        row_hash = _sha256_file(source)
        sources[rel] = {"path": source, "sha256": row_hash, "size": source.stat().st_size}
        source_rows.append({"path": rel, "sha256": row_hash, "size": source.stat().st_size})
        if row.get("applicable") is not False and row.get("in_scope") is not False:
            unit_ids.append(_inventory_unit_id(row, number))
    if len(unit_ids) != len(set(unit_ids)):
        raise HuntError("inventory_duplicate_unit_id")
    scope = workspace / "SCOPE.md"
    severity = workspace / "SEVERITY.md"
    rules = workspace / RULES_RELATIVE
    for path, label in ((scope, "scope"), (severity, "severity"), (rules, "program_rules")):
        if not path.is_file() or path.is_symlink() or not path.read_text(encoding="utf-8").strip():
            raise HuntError(f"missing_{label}:{path}")
    source_snapshot = _stable_hash({
        "mode": "inscope_inventory",
        "inventory_sha256": _sha256_file(inventory_path),
        "sources": sorted(source_rows, key=lambda item: item["path"]),
    })
    return {
        "inventory_path": inventory_path,
        "inventory_rows": inventory_rows,
        "inventory_sha256": _sha256_file(inventory_path),
        "unit_ids": sorted(unit_ids),
        "sources": sources,
        "source_snapshot_sha256": source_snapshot,
        "scope_sha256": _sha256_file(scope),
        "severity_sha256": _sha256_file(severity),
        "program_rules_sha256": _sha256_file(rules),
    }


def _validate_empty_proofs(rows: list[dict[str, Any]], receipt: Mapping[str, Any],
                           current: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not current["unit_ids"]:
        raise HuntError("no_applicable_inventory_units")
    reasoner_receipt_ids = set(receipt["reasoner_receipt_ids"])
    by_unit: dict[str, dict[str, Any]] = {}
    for proof in rows:
        if proof.get("schema") != EMPTY_SCHEMA:
            raise HuntError("examined_empty_schema_invalid")
        body = {key: proof[key] for key in (
            "inventory_unit_id", "examined_axes", "reasoner_step_ids",
            "reasoner_receipt_ids", "source_refs", "input_fingerprint",
        ) if key in proof}
        if set(body) != {"inventory_unit_id", "examined_axes", "reasoner_step_ids",
                         "reasoner_receipt_ids", "source_refs", "input_fingerprint"}:
            raise HuntError("examined_empty_proof_malformed")
        if proof.get("empty_proof_id") != "zde_" + _stable_hash(body):
            raise HuntError("examined_empty_proof_id_mismatch")
        unit_id = proof.get("inventory_unit_id")
        if not isinstance(unit_id, str) or unit_id in by_unit:
            raise HuntError("examined_empty_unit_linkage_invalid")
        if proof.get("examined_axes") != list(AXES):
            raise HuntError("examined_empty_axis_coverage_mismatch")
        reasoners = proof.get("reasoner_step_ids")
        reasoner_receipts = proof.get("reasoner_receipt_ids")
        refs = proof.get("source_refs")
        if not isinstance(reasoners, list) or not reasoners or reasoners != sorted(set(reasoners)):
            raise HuntError("examined_empty_reasoner_linkage_invalid")
        if (not isinstance(reasoner_receipts, list) or not reasoner_receipts
                or reasoner_receipts != sorted(set(reasoner_receipts))
                or any(not _is_hash(item) or item not in reasoner_receipt_ids for item in reasoner_receipts)):
            raise HuntError("examined_empty_receipt_linkage_invalid")
        if not isinstance(refs, list) or not refs or refs != sorted(set(refs)):
            raise HuntError("examined_empty_source_binding_missing")
        if proof.get("input_fingerprint") != receipt.get("input_fingerprint"):
            raise HuntError("examined_empty_revision_linkage_mismatch")
        by_unit[unit_id] = proof
    if sorted(by_unit) != current["unit_ids"]:
        raise HuntError("examined_empty_unit_coverage_mismatch")
    return [by_unit[unit_id] for unit_id in sorted(by_unit)]


def _validate_fuel_ref(ref: Any, obligation: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(ref, dict):
        raise HuntError("zero_day_question_fuel_ref_malformed")
    payload = ref.get("payload")
    if not isinstance(payload, dict) or payload.get("schema") != FUEL_SCHEMA:
        raise HuntError("zero_day_question_fuel_payload_untyped")
    computed = "zdf_" + _stable_hash(payload)
    if ref.get("fuel_id") != computed or ref.get("source_row_sha256") != _stable_hash(payload):
        raise HuntError("zero_day_question_fuel_hash_mismatch")
    if ref.get("fuel_kind") != payload.get("fuel_kind") or ref.get("producer_step_id") != payload.get("producer_step_id"):
        raise HuntError("zero_day_question_fuel_producer_linkage_mismatch")
    if payload.get("obligation_id") != obligation.get("obligation_id") or payload.get("revision_id") != obligation.get("revision_id"):
        raise HuntError("zero_day_question_fuel_parent_linkage_mismatch")
    payload_refs = payload.get("source_refs")
    if (not isinstance(payload_refs, list) or not payload_refs
            or any(not isinstance(item, str) or not item.strip() for item in payload_refs)
            or sorted(set(payload_refs)) != obligation.get("source_refs")):
        raise HuntError("zero_day_question_fuel_source_linkage_mismatch")
    logical = obligation["logical"]
    if payload.get("asset_invariant") != logical.get("asset_invariant") or payload.get("impact_class") != logical.get("impact_class"):
        raise HuntError("zero_day_question_fuel_logical_linkage_mismatch")
    return ref


def _validate_bus(workspace: Path, current: Mapping[str, Any]) -> dict[str, Any]:
    bus = workspace / BUS_RELATIVE
    receipt_path = bus / "freeze_receipt.json"
    obligations_path = bus / "obligations.jsonl"
    questions_path = bus / "questions.jsonl"
    empty_path = bus / "examined_empty.jsonl"
    receipt = _load_json(receipt_path, "zero_day_bus_receipt")
    obligations = _load_jsonl(obligations_path, "zero_day_obligations", allow_empty=True)
    questions = _load_jsonl(questions_path, "zero_day_questions", allow_empty=True)
    empty_rows = _load_jsonl(empty_path, "zero_day_examined_empty", allow_empty=True)
    if receipt.get("schema") != BUS_RECEIPT_SCHEMA:
        raise HuntError("zero_day_bus_receipt_schema_invalid")
    if (not _is_hash(receipt.get("manifest_sha256")) or not _is_hash(receipt.get("state_sha256"))
            or not _is_hash(receipt.get("input_fingerprint"))):
        raise HuntError("zero_day_bus_receipt_fingerprint_malformed")
    if receipt.get("obligations_sha256") != _sha256_file(obligations_path):
        raise HuntError("zero_day_obligations_hash_mismatch")
    if receipt.get("questions_sha256") != _sha256_file(questions_path):
        raise HuntError("zero_day_questions_hash_mismatch")
    if receipt.get("obligation_count") != len(obligations):
        raise HuntError("zero_day_obligation_count_mismatch")
    if receipt.get("question_count") != len(questions):
        raise HuntError("zero_day_question_count_mismatch")
    if receipt.get("examined_empty_sha256") != _sha256_file(empty_path):
        raise HuntError("zero_day_examined_empty_hash_mismatch")
    if receipt.get("examined_empty_count") != len(empty_rows):
        raise HuntError("zero_day_examined_empty_count_mismatch")
    receipt_body = dict(receipt)
    receipt_body.pop("receipt_id", None)
    if receipt.get("receipt_id") != _stable_hash(receipt_body):
        raise HuntError("zero_day_bus_receipt_hash_mismatch")
    provenance = receipt.get("provenance")
    if not isinstance(provenance, dict) or any(not _is_hash(provenance.get(field)) for field in PROVENANCE_HASH_FIELDS):
        raise HuntError("zero_day_bus_provenance_malformed")
    if receipt.get("manifest_sha256") != provenance.get("manifest_sha256"):
        raise HuntError("zero_day_bus_manifest_linkage_mismatch")
    current_hashes = {
        "source_snapshot_sha256": current["source_snapshot_sha256"],
        "scope_sha256": current["scope_sha256"],
        "severity_sha256": current["severity_sha256"],
        "program_rules_sha256": current["program_rules_sha256"],
    }
    if any(provenance.get(field) != value for field, value in current_hashes.items()):
        raise HuntError("zero_day_bus_current_fingerprint_mismatch")
    current_combined = _stable_hash(current_hashes)
    if receipt.get("source_scope_severity_rules_fingerprint") != current_combined:
        raise HuntError("zero_day_bus_combined_fingerprint_mismatch")
    if receipt.get("inventory_sha256") != current["inventory_sha256"] or receipt.get("inventory_count") != len(current["unit_ids"]):
        raise HuntError("zero_day_bus_inventory_linkage_mismatch")
    producer_ids = receipt.get("producer_receipt_ids")
    if not isinstance(producer_ids, list) or producer_ids != sorted(set(producer_ids)) or any(not _is_hash(item) for item in producer_ids):
        raise HuntError("zero_day_bus_producer_receipts_malformed")
    reasoner_ids = receipt.get("reasoner_receipt_ids")
    if not isinstance(reasoner_ids, list) or reasoner_ids != sorted(set(reasoner_ids)) or any(not _is_hash(item) for item in reasoner_ids):
        raise HuntError("zero_day_bus_reasoner_receipts_malformed")
    if any(item not in producer_ids for item in reasoner_ids):
        raise HuntError("zero_day_bus_reasoner_receipt_linkage_mismatch")
    fuel_artifacts = receipt.get("fuel_artifact_sha256")
    if not isinstance(fuel_artifacts, dict) or any(not isinstance(key, str) or not _is_hash(value) for key, value in fuel_artifacts.items()):
        raise HuntError("zero_day_bus_fuel_artifacts_malformed")
    expected_input = _stable_hash({
        "manifest_sha256": receipt.get("manifest_sha256"),
        "state_sha256": receipt.get("state_sha256"),
        "producer_receipt_ids": producer_ids,
        "reasoner_receipt_ids": reasoner_ids,
        "fuel_artifact_hashes": fuel_artifacts,
        "fuel_rows_sha256": receipt.get("fuel_rows_sha256"),
        "inventory_sha256": receipt.get("inventory_sha256"),
        "source_scope_severity_rules_fingerprint": receipt.get("source_scope_severity_rules_fingerprint"),
        "pipeline_tooling_sha256": provenance.get("pipeline_tooling_sha256"),
    })
    if receipt.get("input_fingerprint") != expected_input:
        raise HuntError("zero_day_input_fingerprint_mismatch")

    obligation_by_parent: dict[tuple[str, str], dict[str, Any]] = {}
    for obligation in obligations:
        if obligation.get("schema") != OBLIGATION_SCHEMA:
            raise HuntError("zero_day_obligation_schema_invalid")
        logical = obligation.get("logical")
        logical_fields = {"target_unit", "asset_invariant", "violation_relation", "actor_model", "impact_class"}
        if (not isinstance(logical, dict) or set(logical) != logical_fields
                or any(not isinstance(logical[field], str) or not logical[field].strip() for field in logical_fields)
                or obligation.get("obligation_id") != "zdo_" + _stable_hash(logical)):
            raise HuntError("zero_day_obligation_id_mismatch")
        fingerprint = obligation.get("input_fingerprint")
        if not _is_hash(fingerprint) or obligation.get("revision_id") != "zdr_" + fingerprint:
            raise HuntError("zero_day_revision_linkage_mismatch")
        if obligation.get("producer_receipt_id") not in reasoner_ids:
            raise HuntError("zero_day_obligation_producer_linkage_mismatch")
        if not _is_hash(obligation.get("source_row_sha256")):
            raise HuntError("zero_day_obligation_source_row_hash_invalid")
        refs = obligation.get("source_refs")
        if (not isinstance(refs, list) or not refs or refs != sorted(set(refs))
                or not all(isinstance(ref, str) and ref.strip() for ref in refs)):
            raise HuntError("zero_day_obligation_source_binding_missing")
        fuel_ids = obligation.get("fuel_ids")
        if not isinstance(fuel_ids, list) or fuel_ids != sorted(set(fuel_ids)) or any(not isinstance(item, str) for item in fuel_ids):
            raise HuntError("zero_day_obligation_fuel_ids_malformed")
        parent = (obligation["obligation_id"], obligation["revision_id"])
        if parent in obligation_by_parent:
            raise HuntError("zero_day_obligation_parent_duplicate")
        obligation_by_parent[parent] = obligation

    questions_by_parent: dict[tuple[str, str], list[dict[str, Any]]] = {parent: [] for parent in obligation_by_parent}
    question_ids: set[str] = set()
    for question in questions:
        if question.get("schema") != QUESTION_SCHEMA:
            raise HuntError("zero_day_question_schema_invalid")
        parents = question.get("parent_ids")
        if not isinstance(parents, list) or len(parents) != 2 or not all(isinstance(item, str) for item in parents):
            raise HuntError("zero_day_question_parent_linkage_malformed")
        parent = (parents[0], parents[1])
        obligation = obligation_by_parent.get(parent)
        if obligation is None:
            raise HuntError("zero_day_question_parent_missing")
        axis = question.get("axis")
        if axis not in AXES:
            raise HuntError("zero_day_question_revision_linkage_mismatch")
        fuel_refs = question.get("fuel_refs")
        if not isinstance(fuel_refs, list):
            raise HuntError("zero_day_question_fuel_refs_malformed")
        validated_fuel = [_validate_fuel_ref(ref, obligation) for ref in fuel_refs]
        if [ref["fuel_id"] for ref in validated_fuel] != sorted(set(ref["fuel_id"] for ref in validated_fuel)):
            raise HuntError("zero_day_question_fuel_refs_not_canonical")
        if obligation.get("fuel_ids") != [ref["fuel_id"] for ref in validated_fuel]:
            raise HuntError("zero_day_obligation_fuel_linkage_mismatch")
        question_fingerprint = _stable_hash({
            "obligation_input_fingerprint": obligation["input_fingerprint"],
            "fuel_source_row_sha256": [ref["source_row_sha256"] for ref in validated_fuel],
        })
        if question.get("input_fingerprint") != question_fingerprint:
            raise HuntError("zero_day_question_revision_linkage_mismatch")
        question_body = {
            "obligation_id": parent[0], "revision_id": parent[1], "axis": axis,
            "input_fingerprint": question_fingerprint,
        }
        question_id = question.get("question_id")
        if question_id != "zdq_" + _stable_hash(question_body) or question_id in question_ids:
            raise HuntError("zero_day_question_id_mismatch")
        required = question.get("required_evidence")
        if required != ["source_citation", "local_or_chain_evidence", "non_provider_terminal_verdict"]:
            raise HuntError("zero_day_question_required_evidence_malformed")
        if not isinstance(question.get("proof_route"), str) or not question["proof_route"].strip():
            raise HuntError("zero_day_question_proof_route_malformed")
        question_ids.add(question_id)
        questions_by_parent[parent].append(question)

    for parent, parent_questions in questions_by_parent.items():
        axes = [question["axis"] for question in parent_questions]
        if len(parent_questions) != len(AXES) or set(axes) != set(AXES) or len(axes) != len(set(axes)):
            raise HuntError(f"zero_day_question_axis_set_incomplete:{parent[0]}:{parent[1]}")
    if len(questions) != len(obligations) * len(AXES):
        raise HuntError("zero_day_question_denominator_mismatch")
    fuel_by_id: dict[str, dict[str, Any]] = {}
    for question in questions:
        for ref in question["fuel_refs"]:
            prior = fuel_by_id.get(ref["fuel_id"])
            if prior is not None and prior != ref:
                raise HuntError("zero_day_fuel_id_conflict")
            fuel_by_id[ref["fuel_id"]] = ref
    all_fuel = sorted(fuel_by_id.values(), key=lambda ref: (ref["producer_step_id"], ref["fuel_id"]))
    if receipt.get("fuel_row_count") != len(all_fuel) or receipt.get("fuel_rows_sha256") != _stable_hash(all_fuel):
        raise HuntError("zero_day_fuel_denominator_mismatch")
    fuel_counts = receipt.get("fuel_counts")
    actual_counts: dict[str, int] = {}
    for ref in all_fuel:
        actual_counts[ref["producer_step_id"]] = actual_counts.get(ref["producer_step_id"], 0) + 1
    if not isinstance(fuel_counts, dict) or any(not isinstance(value, int) or value < 0 for value in fuel_counts.values()):
        raise HuntError("zero_day_fuel_counts_malformed")
    if any(actual_counts.get(step_id, 0) != count for step_id, count in fuel_counts.items()) or any(step_id not in fuel_counts for step_id in actual_counts):
        raise HuntError("zero_day_fuel_count_linkage_mismatch")
    empty_proofs: list[dict[str, Any]] = []
    if questions:
        if empty_rows:
            raise HuntError("zero_day_examined_empty_with_questions")
    else:
        if obligations:
            raise HuntError("zero_day_obligation_without_questions")
        empty_proofs = _validate_empty_proofs(empty_rows, receipt, current)
    ordered_questions = sorted(
        questions,
        key=lambda question: (
            -int(question.get("priority") or 0),
            question["parent_ids"][0],
            AXES.index(question["axis"]),
            question["question_id"],
        ),
    )
    return {
        "receipt": receipt,
        "receipt_path": receipt_path,
        "obligations_path": obligations_path,
        "questions_path": questions_path,
        "empty_path": empty_path,
        "obligation_by_parent": obligation_by_parent,
        "questions": ordered_questions,
        "empty_proofs": empty_proofs,
    }


def _subprocess_runner(argv: Sequence[str], cwd: Path, environment: Mapping[str, str], timeout: int) -> CommandResult:
    try:
        result = subprocess.run(list(argv), cwd=cwd, env=dict(environment), text=True,
                                capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise HuntError("provider_task_timeout") from exc
    except OSError as exc:
        raise HuntError("provider_command_unavailable") from exc
    return CommandResult(result.returncode, result.stdout, result.stderr)


def _render_prompt(question: Mapping[str, Any], obligation: Mapping[str, Any], workspace: Path) -> str:
    return (
        "You are executing one immutable Step 3 zero-day hunt question. Read the real in-scope source. "
        "Your response is nonterminal hunt evidence and cannot prove or resolve the parent obligation.\n\n"
        f"WORKSPACE: {workspace}\nQUESTION_ID: {question['question_id']}\n"
        f"PARENT_OBLIGATION_ID: {obligation['obligation_id']}\nREVISION_ID: {obligation['revision_id']}\n"
        f"AXIS: {question['axis']}\nLOGICAL OBLIGATION: {json.dumps(obligation['logical'], sort_keys=True)}\n"
        f"SOURCE REFS: {json.dumps(obligation['source_refs'], sort_keys=True)}\n"
        f"PROOF ROUTE: {question['proof_route']}\nREQUIRED EVIDENCE: {json.dumps(question['required_evidence'])}\n\n"
        "Return exactly one JSON object with these keys: applies_to_target, confidence, candidate_finding, "
        "file_line, code_excerpt, severity_estimate, rubric_row_cited, dupe_check, falsification_attempt, notes. "
        "Do not claim terminal proof, resolution, or filing readiness."
    )


def _render_argv(template: Sequence[str], prompt: str, prompt_file: Path, output_file: Path,
                 workspace: Path) -> list[str]:
    values = {"{prompt}": prompt, "{prompt_file}": str(prompt_file),
              "{output_file}": str(output_file), "{workspace}": str(workspace)}
    return [values.get(item, item) for item in template]


def _validate_provider_result(result: Any, workspace: Path,
                              sources: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    if not isinstance(result, dict) or not RESULT_KEYS.issubset(result):
        raise HuntError("provider_result_malformed")
    if result.get("terminal") is True or result.get("provider_response_terminal") is True:
        raise HuntError("provider_result_terminal_claim_forbidden")
    if result.get("degraded") is True or result.get("warning") or result.get("warnings"):
        raise HuntError("provider_result_degraded")
    if any(isinstance(result.get(key), str) and result[key].strip().lower() in BAD_RESULT_TOKENS
           for key in ("status", "outcome", "verdict", "confidence")):
        raise HuntError("provider_result_degraded")
    if result.get("applies_to_target") not in {"yes", "no", "maybe"}:
        raise HuntError("provider_result_hunt_classification_invalid")
    file_line = result.get("file_line")
    if not isinstance(file_line, str) or ":" not in file_line:
        raise HuntError("provider_result_source_binding_missing")
    raw_path, raw_line = file_line.rsplit(":", 1)
    if not raw_line.lstrip("Ll").isdigit():
        raise HuntError("provider_result_source_binding_invalid")
    source = Path(raw_path)
    source = source.resolve() if source.is_absolute() else (workspace / source).resolve()
    try:
        relative = source.relative_to(workspace).as_posix()
    except ValueError as exc:
        raise HuntError("provider_result_source_outside_workspace") from exc
    if relative not in sources or not source.is_file() or source.is_symlink():
        raise HuntError("provider_result_source_not_in_inventory")
    line = int(raw_line.lstrip("Ll"))
    source_lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    if line < 1 or line > len(source_lines):
        raise HuntError("provider_result_source_line_invalid")
    excerpt = result.get("code_excerpt")
    if not isinstance(excerpt, str) or not excerpt.strip():
        raise HuntError("provider_result_code_excerpt_missing")
    # Providers may normalize indentation or line wrapping.  Match non-whitespace
    # source text, but only in a short forward window rooted at the claimed line.
    # This makes the citation replayable without requiring an exact formatter.
    normalized_excerpt = re.sub(r"\s+", "", excerpt)
    window = "\n".join(source_lines[line - 1:line + 11])
    if normalized_excerpt not in re.sub(r"\s+", "", window):
        raise HuntError("provider_result_code_excerpt_source_mismatch")
    return result


def _dispatch_one(question: Mapping[str, Any], obligation: Mapping[str, Any], workspace: Path,
                  output_dir: Path, backend: Backend, sources: Mapping[str, Mapping[str, Any]],
                  runner: CommandRunner, timeout: int) -> dict[str, Any]:
    task_id = str(question["question_id"])
    prompt = _render_prompt(question, obligation, workspace)
    prompt_path = output_dir / "prompts" / f"{task_id}.txt"
    raw_output = output_dir / "provider_output" / f"{task_id}.json"
    sidecar_path = output_dir / "sidecars" / f"{task_id}.json"
    _atomic_text(prompt_path, prompt)
    argv = _render_argv(backend.argv_template, prompt, prompt_path, raw_output, workspace)
    command_hash = _stable_hash({"template": list(backend.argv_template),
                                 "provider": backend.provider, "model": backend.model})
    result = runner(argv, workspace, backend.environment, timeout)
    if result.returncode != 0:
        combined = (result.stderr + "\n" + result.stdout).lower()
        if any(token in combined for token in ("auth", "unauthorized", "forbidden", "credential")):
            raise HuntError(f"provider_auth_failed:{task_id}")
        raise HuntError(f"provider_task_failed:{task_id}")
    if backend.output_mode == "stdout":
        _atomic_text(raw_output, result.stdout)
    if not raw_output.is_file():
        raise HuntError(f"provider_sidecar_missing:{task_id}")
    try:
        parsed = json.loads(raw_output.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HuntError(f"provider_sidecar_malformed:{task_id}") from exc
    parsed = _validate_provider_result(parsed, workspace, sources)
    sidecar = {
        "schema": SIDECAR_SCHEMA,
        "task_id": task_id,
        "question_id": question["question_id"],
        "parent_ids": question["parent_ids"],
        "axis": question["axis"],
        "input_fingerprint": question["input_fingerprint"],
        "workspace": workspace.name,
        "workspace_path": str(workspace),
        "provider": backend.provider,
        "model": backend.model,
        "status": "captured",
        "evidence_class": "nonterminal-hunt-evidence",
        "terminal": False,
        "prompt_sha256": _sha256_bytes(prompt.encode("utf-8")),
        "command_sha256": command_hash,
        "result": json.dumps(_canonical(parsed), sort_keys=True, separators=(",", ":")),
    }
    _atomic_json(sidecar_path, sidecar)
    return {
        "task_id": task_id,
        "question_id": question["question_id"],
        "parent_ids": question["parent_ids"],
        "axis": question["axis"],
        "provider": backend.provider,
        "model": backend.model,
        "evidence_class": "nonterminal-hunt-evidence",
        "terminal": False,
        "prompt_sha256": sidecar["prompt_sha256"],
        "command_sha256": command_hash,
        "sidecar_path": str(sidecar_path),
        "sidecar_sha256": _sha256_file(sidecar_path),
    }


def validate_current_ordered_hunt(workspace: str | Path) -> dict[str, Any]:
    """Validate the complete current Step 3 artifact set against the frozen bus.

    Later phases must consume this projection rather than reinterpreting legacy
    reasoner ledgers or treating a provider response as terminal evidence.
    """
    root = Path(workspace).expanduser().resolve()
    current = _current_inputs(root)
    bus = _validate_bus(root, current)
    output = root / OUTPUT_RELATIVE
    manifest_path = output / "manifest.json"
    receipt_path = output / "receipt.json"
    manifest = _load_json(manifest_path, "ordered_hunt_manifest")
    receipt = _load_json(receipt_path, "ordered_hunt_receipt")
    expected_questions = {row["question_id"]: row for row in bus["questions"]}
    denominator = len(expected_questions)

    if manifest.get("schema") != SCHEMA or manifest.get("status") not in {"completed", "completed-examined-empty"}:
        raise HuntError("ordered_hunt_manifest_not_terminal")
    if manifest.get("errors") not in (None, []):
        raise HuntError("ordered_hunt_manifest_has_errors")
    if (manifest.get("bus_receipt_id") != bus["receipt"].get("receipt_id")
            or manifest.get("bus_input_fingerprint") != bus["receipt"].get("input_fingerprint")):
        raise HuntError("ordered_hunt_stale_relative_to_freeze")
    expected_bus_hashes = {
        "freeze_receipt_sha256": _sha256_file(bus["receipt_path"]),
        "obligations_sha256": _sha256_file(bus["obligations_path"]),
        "questions_sha256": _sha256_file(bus["questions_path"]),
        "examined_empty_sha256": _sha256_file(bus["empty_path"]),
    }
    if manifest.get("bus_fingerprints") != expected_bus_hashes:
        raise HuntError("ordered_hunt_bus_fingerprints_mismatch")
    expected_current = {
        "inventory_sha256": current["inventory_sha256"],
        "source_snapshot_sha256": current["source_snapshot_sha256"],
        "scope_sha256": current["scope_sha256"],
        "severity_sha256": current["severity_sha256"],
        "program_rules_sha256": current["program_rules_sha256"],
    }
    current_fingerprints = manifest.get("current_fingerprints")
    if not isinstance(current_fingerprints, dict) or any(
            current_fingerprints.get(key) != value for key, value in expected_current.items()):
        raise HuntError("ordered_hunt_stale_relative_to_current_inputs")
    if manifest.get("all_typed_questions_denominator") != denominator:
        raise HuntError("ordered_hunt_question_denominator_mismatch")
    if manifest.get("dispatched_count") != denominator or manifest.get("completed_count") != denominator:
        raise HuntError("ordered_hunt_question_denominator_incomplete")

    tasks = manifest.get("tasks")
    reconciliation = manifest.get("reconciliation")
    if not isinstance(tasks, list) or not isinstance(reconciliation, dict):
        raise HuntError("ordered_hunt_task_reconciliation_malformed")
    task_ids = [row.get("task_id") for row in tasks if isinstance(row, dict)]
    expected_ids = list(expected_questions)
    if len(task_ids) != len(tasks) or len(task_ids) != len(set(task_ids)):
        raise HuntError("ordered_hunt_task_ids_malformed")
    if (set(reconciliation.get("expected_task_ids") or []) != set(expected_ids)
            or set(reconciliation.get("completed_task_ids") or []) != set(expected_ids)
            or reconciliation.get("missing_task_ids") != []):
        raise HuntError("ordered_hunt_reconciliation_incomplete")
    if set(task_ids) != set(expected_ids):
        raise HuntError("ordered_hunt_task_set_mismatch")

    sidecars_by_task: dict[str, dict[str, Any]] = {}
    for task in tasks:
        if not isinstance(task, dict):
            raise HuntError("ordered_hunt_task_malformed")
        task_id = task["task_id"]
        question = expected_questions[task_id]
        if (task.get("question_id") != question["question_id"]
                or task.get("parent_ids") != question["parent_ids"]
                or task.get("axis") != question["axis"]):
            raise HuntError(f"ordered_hunt_task_linkage_mismatch:{task_id}")
        if (not _is_hash(task.get("prompt_sha256")) or not _is_hash(task.get("command_sha256"))
                or not isinstance(task.get("provider"), str) or not task["provider"]
                or not isinstance(task.get("model"), str) or not task["model"]
                or task.get("terminal") is not False
                or task.get("evidence_class") != "nonterminal-hunt-evidence"):
            raise HuntError(f"ordered_hunt_task_semantics_malformed:{task_id}")
        raw_sidecar = task.get("sidecar_path")
        if not isinstance(raw_sidecar, str) or not raw_sidecar:
            raise HuntError(f"ordered_hunt_sidecar_missing:{task_id}")
        candidate = Path(raw_sidecar)
        sidecar_path = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
        canonical_sidecars = (output / "sidecars").resolve()
        if canonical_sidecars not in sidecar_path.parents or not sidecar_path.is_file() or sidecar_path.is_symlink():
            raise HuntError(f"ordered_hunt_sidecar_outside_workspace:{task_id}")
        if task.get("sidecar_sha256") != _sha256_file(sidecar_path):
            raise HuntError(f"ordered_hunt_sidecar_hash_mismatch:{task_id}")
        sidecar = _load_json(sidecar_path, f"ordered_hunt_sidecar:{task_id}")
        linked_fields = ("question_id", "parent_ids", "axis", "prompt_sha256", "command_sha256", "provider", "model")
        if (sidecar.get("schema") != SIDECAR_SCHEMA or sidecar.get("status") != "captured"
                or sidecar.get("task_id") != task_id or sidecar.get("terminal") is not False
                or sidecar.get("evidence_class") != "nonterminal-hunt-evidence"
                or any(sidecar.get(key) != task.get(key) for key in linked_fields)):
            raise HuntError(f"ordered_hunt_sidecar_semantics_malformed:{task_id}")
        sidecars_by_task[task_id] = sidecar

    if denominator == 0:
        if (manifest.get("status") != "completed-examined-empty" or tasks
                or manifest.get("examined_empty_proofs") != bus.get("empty_proofs")):
            raise HuntError("ordered_hunt_examined_empty_malformed")
    elif manifest.get("status") != "completed":
        raise HuntError("ordered_hunt_nonempty_not_completed")
    if (receipt.get("schema") != RECEIPT_SCHEMA
            or receipt.get("manifest_sha256") != _sha256_file(manifest_path)):
        raise HuntError("ordered_hunt_receipt_manifest_mismatch")
    receipt_fields = ("status", "all_typed_questions_denominator", "dispatched_count", "completed_count")
    if (receipt.get("terminal_evidence") is not False
            or any(receipt.get(key) != manifest.get(key) for key in receipt_fields)):
        raise HuntError("ordered_hunt_receipt_semantics_malformed")
    return {
        "workspace": root,
        "current": current,
        "bus": bus,
        "manifest": manifest,
        "receipt": receipt,
        "tasks_by_id": {task["task_id"]: task for task in tasks},
        "sidecars_by_task": sidecars_by_task,
    }


def run_ordered_hunt(workspace: str | Path, *, top_n: int | None = None, timeout: int = 300,
                     provider_config: Mapping[str, Any] | None = None,
                     requested_provider: str | None = None,
                     runner: CommandRunner = _subprocess_runner) -> dict[str, Any]:
    root = Path(workspace).expanduser().resolve()
    if not root.is_dir():
        raise HuntError("workspace_missing")
    if timeout < 1:
        raise HuntError("task_timeout_invalid")
    if top_n is not None and top_n < 1:
        raise HuntError("top_n_invalid")
    output = root / OUTPUT_RELATIVE
    output.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"schema": SCHEMA, "workspace": str(root),
                                "status": "failed", "errors": [], "tasks": []}
    try:
        current = _current_inputs(root)
        bus = _validate_bus(root, current)
        attestation_path = root / ATTESTATION_RELATIVE
        attestation = _load_json(attestation_path, "backend_attestation")
        backend = _backend_from_attestation(attestation, provider_config, requested_provider)
        questions = bus["questions"]
        denominator = len(questions)
        worklist_rows = [{
            "task_id": question["question_id"],
            "question_id": question["question_id"],
            "parent_ids": question["parent_ids"],
            "axis": question["axis"],
            "input_fingerprint": question["input_fingerprint"],
        } for question in questions]
        _atomic_text(output / "worklist.jsonl", "".join(
            json.dumps(_canonical(row), sort_keys=True, separators=(",", ":")) + "\n"
            for row in worklist_rows
        ))
        manifest.update({
            "status": "running",
            "provider": backend.provider,
            "model": backend.model,
            "route": backend.route,
            "bus_receipt_id": bus["receipt"]["receipt_id"],
            "bus_input_fingerprint": bus["receipt"]["input_fingerprint"],
            "bus_fingerprints": {
                "freeze_receipt_sha256": _sha256_file(bus["receipt_path"]),
                "obligations_sha256": _sha256_file(bus["obligations_path"]),
                "questions_sha256": _sha256_file(bus["questions_path"]),
                "examined_empty_sha256": _sha256_file(bus["empty_path"]),
            },
            "current_fingerprints": {
                "inventory_sha256": current["inventory_sha256"],
                "source_snapshot_sha256": current["source_snapshot_sha256"],
                "scope_sha256": current["scope_sha256"],
                "severity_sha256": current["severity_sha256"],
                "program_rules_sha256": current["program_rules_sha256"],
                "attestation_sha256": _sha256_file(attestation_path),
            },
            "all_typed_questions_denominator": denominator,
            "scheduled_priority_count": min(top_n, denominator) if top_n else denominator,
            "dispatched_count": 0,
            "completed_count": 0,
        })
        if not questions:
            manifest.update({
                "status": "completed-examined-empty",
                "examined_empty_proofs": bus["empty_proofs"],
                "reconciliation": {"expected_task_ids": [], "completed_task_ids": [], "missing_task_ids": []},
            })
        else:
            for question in questions:
                parent = (question["parent_ids"][0], question["parent_ids"][1])
                manifest["dispatched_count"] += 1
                manifest["tasks"].append(_dispatch_one(
                    question, bus["obligation_by_parent"][parent], root, output,
                    backend, current["sources"], runner, timeout,
                ))
                manifest["completed_count"] += 1
            expected = [question["question_id"] for question in questions]
            completed = [task["task_id"] for task in manifest["tasks"]]
            missing = sorted(set(expected) - set(completed))
            if manifest["dispatched_count"] != denominator or manifest["completed_count"] != denominator or missing:
                raise HuntError("provider_partial_batch")
            manifest.update({
                "status": "completed",
                "reconciliation": {
                    "expected_task_ids": expected,
                    "completed_task_ids": completed,
                    "missing_task_ids": missing,
                },
            })
    except HuntError as exc:
        manifest["status"] = "failed"
        manifest["errors"].append(str(exc))
        manifest.setdefault("all_typed_questions_denominator", 0)
        manifest.setdefault("dispatched_count", len(manifest.get("tasks", [])))
        manifest.setdefault("completed_count", len(manifest.get("tasks", [])))
    _atomic_json(output / "manifest.json", manifest)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "manifest_sha256": _sha256_file(output / "manifest.json"),
        "status": manifest["status"],
        "terminal_evidence": False,
        "all_typed_questions_denominator": manifest.get("all_typed_questions_denominator", 0),
        "dispatched_count": manifest.get("dispatched_count", 0),
        "completed_count": manifest.get("completed_count", 0),
    }
    _atomic_json(output / "receipt.json", receipt)
    if manifest["status"] not in {"completed", "completed-examined-empty"}:
        raise HuntError(manifest["errors"][0] if manifest["errors"] else "ordered_hunt_failed")
    return manifest


def _load_provider_config(path: str | None) -> Mapping[str, Any] | None:
    if not path:
        return None
    value = _load_json(Path(path).expanduser().resolve(), "provider_config")
    providers = value.get("providers", value)
    if not isinstance(providers, Mapping):
        raise HuntError("provider_config_malformed")
    return providers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", "--ws", required=True)
    parser.add_argument("--top-n", type=int, default=None,
                        help="Priority scheduling only. Every typed bus question still dispatches.")
    parser.add_argument("--task-timeout", type=int, default=300)
    parser.add_argument("--provider", default=None, help="Must exactly match Step 0f when supplied.")
    parser.add_argument("--provider-config", default=None,
                        help="JSON map for explicit non-Codex provider argv routes.")
    args = parser.parse_args(argv)
    try:
        manifest = run_ordered_hunt(
            args.workspace,
            top_n=args.top_n,
            timeout=args.task_timeout,
            requested_provider=args.provider,
            provider_config=_load_provider_config(args.provider_config),
        )
    except HuntError as exc:
        print(json.dumps({"schema": SCHEMA, "status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(_canonical(manifest), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
