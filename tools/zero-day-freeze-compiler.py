#!/usr/bin/env python3
"""Compile receipt-bound reasoner ledgers into the typed zero-day obligation bus.

This is the read-only replacement core for Step 2h.  It never executes a
producer.  Instead it freezes the current Pipeline V2 receipt graph and fails
closed when an input, ledger, route, or producer binding is not exact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import zero_day_fuel_identity as fuel_identity


OBLIGATION_SCHEMA = "auditooor.zero_day_obligation.v1"
QUESTION_SCHEMA = "auditooor.zero_day_question.v1"
EMPTY_LEDGER_SCHEMA = "auditooor.reasoner_examined_empty.v2"
COVERAGE_LEDGER_SCHEMA = "auditooor.reasoner_coverage.v1"
EMPTY_SCHEMA = "auditooor.zero_day_examined_empty.v1"
FUEL_SCHEMA = fuel_identity.FUEL_SCHEMA
IDENTITY_MAP_SCHEMA = fuel_identity.IDENTITY_MAP_SCHEMA
RECEIPT_SCHEMA = "auditooor.zero_day_freeze_receipt.v1"
PIPELINE_MANIFEST_SCHEMA = "auditooor.pipeline_manifest.v2"
PIPELINE_STATE_SCHEMA = "auditooor.pipeline_state.v2"
PIPELINE_RECEIPT_SCHEMA = "auditooor.pipeline_receipt.v2"
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
ROUTE_FIELDS = ("queue_step_id", "question_step_id", "proof_step_id", "resolution_step_id")
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
FUEL_STEPS = {
    "step-4c": "artifact.step-4c",
    "step-2g-novelty-flywheel": "artifact.step-2g-novelty-flywheel",
}
STEP4C_HUNT_REPORT_CONTRACT = "artifact.step-4c-hunt-report"
AWARENESS_LEDGER_CONTRACT = "artifact.step-0d-awareness"
AWARENESS_LEDGER_SCHEMA = "auditooor.awareness_ledger.v1"
AWARENESS_LOGICAL_FIELDS = (
    "target_unit",
    "asset_invariant",
    "violation_relation",
    "actor_model",
    "impact_class",
)
INVENTORY_RELATIVE = Path(".auditooor") / "inscope_units.jsonl"


class FreezeError(RuntimeError):
    """Raised for a non-freezable pipeline state."""


def canonical(value: Any) -> Any:
    return fuel_identity.canonical(value)


def digest(value: Any) -> str:
    return fuel_identity.digest(value)


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def path_sha256(path: Path) -> str:
    if path.is_file() and not path.is_symlink():
        return file_sha256(path)
    if path.is_dir() and not path.is_symlink():
        rows = [
            {"path": item.relative_to(path).as_posix(), "sha256": file_sha256(item), "size": item.stat().st_size}
            for item in sorted(path.rglob("*"))
            if item.is_file() and not item.is_symlink()
        ]
        return digest(rows)
    return digest({"missing": path.name})


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FreezeError(f"malformed_{label}:{path}") from exc
    if not isinstance(data, dict):
        raise FreezeError(f"malformed_{label}:{path}")
    return data


def resolve_path(workspace: Path, raw: Any) -> Path:
    value = str(raw or "").strip()
    if not value:
        raise FreezeError("missing_artifact_path")
    path = Path(value)
    return path if path.is_absolute() else workspace / path


def is_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    body = dict(receipt)
    body.pop("receipt_id", None)
    body.pop("self_hash", None)
    return digest(body)


def validate_receipt(receipt: Mapping[str, Any], state: Mapping[str, Any], step_id: str) -> None:
    if receipt.get("schema") != PIPELINE_RECEIPT_SCHEMA:
        raise FreezeError(f"invalid_receipt_schema:{step_id}")
    if receipt.get("step_id") != step_id:
        raise FreezeError(f"receipt_step_mismatch:{step_id}")
    if receipt.get("status") not in {"succeeded", "not_applicable"}:
        raise FreezeError(f"receipt_not_successful:{step_id}")
    expected = receipt_digest(receipt)
    if receipt.get("receipt_id") != expected or receipt.get("self_hash") != expected:
        raise FreezeError(f"receipt_hash_mismatch:{step_id}")
    for field in PROVENANCE_FIELDS:
        if not is_hash(state.get(field)) or receipt.get(field) != state.get(field):
            raise FreezeError(f"receipt_provenance_mismatch:{step_id}:{field}")
    if not isinstance(receipt.get("output_artifacts"), list):
        raise FreezeError(f"malformed_receipt_outputs:{step_id}")


def receipt_path(receipts_dir: Path, step_id: str, receipt_id: str) -> Path:
    candidates: list[Path] = []
    step_dir = receipts_dir / step_id
    if step_dir.is_dir():
        candidates.extend(sorted(step_dir.glob("*.json")))
    for path in candidates:
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(row, dict) and row.get("receipt_id") == receipt_id:
            return path
    raise FreezeError(f"missing_current_receipt:{step_id}")


def current_receipts(state: Mapping[str, Any], receipts_dir: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    steps = state.get("steps")
    if not isinstance(steps, dict):
        raise FreezeError("malformed_pipeline_state_steps")
    for step_id, entry in sorted(steps.items()):
        if not isinstance(entry, dict):
            raise FreezeError(f"malformed_state_step:{step_id}")
        receipt_id = entry.get("current_receipt_id")
        if receipt_id is None:
            continue
        if not is_hash(receipt_id):
            raise FreezeError(f"invalid_current_receipt_id:{step_id}")
        path = receipt_path(receipts_dir, step_id, receipt_id)
        result[step_id] = load_json(path, f"receipt:{step_id}")
    return result


def output_by_contract(receipt: Mapping[str, Any], contract: str) -> dict[str, Any] | None:
    matches = [row for row in receipt.get("output_artifacts", []) if isinstance(row, dict) and row.get("artifact_contract") == contract]
    if len(matches) > 1:
        raise FreezeError(f"duplicate_receipt_output_contract:{receipt.get('step_id')}:{contract}")
    return matches[0] if matches else None


def verify_artifact(workspace: Path, artifact: Mapping[str, Any], label: str) -> Path:
    claimed = artifact.get("sha256")
    if not is_hash(claimed):
        raise FreezeError(f"invalid_artifact_hash:{label}")
    path = resolve_path(workspace, artifact.get("path"))
    if not path.exists():
        raise FreezeError(f"missing_artifact:{label}")
    if path_sha256(path) != claimed:
        raise FreezeError(f"artifact_hash_mismatch:{label}")
    return path


def manifest_context(manifest: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if manifest.get("schema") != PIPELINE_MANIFEST_SCHEMA:
        raise FreezeError("invalid_manifest_schema")
    steps = manifest.get("steps")
    contracts = manifest.get("artifact_contracts")
    registry = manifest.get("reasoner_registry")
    routes = manifest.get("reasoner_routes")
    if not all(isinstance(value, list) for value in (steps, contracts, registry, routes)):
        raise FreezeError("malformed_manifest_registry")
    by_id = {row.get("step_id"): row for row in steps if isinstance(row, dict) and isinstance(row.get("step_id"), str)}
    contract_by_id = {row.get("id"): row for row in contracts if isinstance(row, dict) and isinstance(row.get("id"), str)}
    registry_by_id = {row.get("step_id"): row for row in registry if isinstance(row, dict) and isinstance(row.get("step_id"), str)}
    routes_by_id = {row.get("step_id"): row for row in routes if isinstance(row, dict) and isinstance(row.get("step_id"), str)}
    if (
        len(by_id) != len(steps)
        or len(contract_by_id) != len(contracts)
        or len(registry_by_id) != len(registry)
        or len(routes_by_id) != len(routes)
    ):
        raise FreezeError("duplicate_manifest_identifier")
    return by_id, contract_by_id, registry_by_id, routes_by_id


def reasoner_steps(registry: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Return only manifest-registered reasoners.

    Phase and class are deliberately ignored. Orchestration steps can live in
    the reasoning phase without being obligation producers.
    """
    return sorted(registry)


def verify_route(step_id: str, registry: Mapping[str, Mapping[str, Any]], routes: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
    row = registry.get(step_id)
    route = routes.get(step_id)
    if not isinstance(row, Mapping) or not isinstance(route, Mapping):
        raise FreezeError(f"incomplete_reasoner_route:{step_id}")
    ledger = row.get("ledger_artifact")
    if not isinstance(ledger, str) or route.get("ledger_artifact") != ledger:
        raise FreezeError(f"incomplete_reasoner_route:{step_id}")
    if route.get("producer_step_id") != step_id:
        raise FreezeError(f"incomplete_reasoner_route:{step_id}")
    consumers = route.get("consumer_step_ids")
    if not isinstance(consumers, list) or any(not isinstance(route.get(field), str) or route[field] not in consumers for field in ROUTE_FIELDS):
        raise FreezeError(f"incomplete_reasoner_route:{step_id}")
    return row


def pick(row: Mapping[str, Any], names: Iterable[str], label: str) -> str:
    for name in names:
        value = row.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, list) and value and all(isinstance(item, str) and item.strip() for item in value):
            return " | ".join(sorted(item.strip() for item in value))
    raise FreezeError(f"malformed_ledger_row_missing_{label}")


def normalized_fields(row: Mapping[str, Any]) -> dict[str, str]:
    target = row.get("target_unit")
    if not isinstance(target, str) or not target.strip():
        parts = [str(row[name]).strip() for name in ("contract", "function", "file") if isinstance(row.get(name), str) and str(row[name]).strip()]
        target = "::".join(parts)
    if not isinstance(target, str) or not target.strip():
        raise FreezeError("malformed_ledger_row_missing_target_unit")
    return {
        "target_unit": target.strip(),
        "asset_invariant": pick(row, ("asset_invariant", "asset_or_invariant", "expected_invariant", "invariant", "asset"), "asset_invariant"),
        "violation_relation": pick(row, ("violation_relation", "suspected_violation", "violation", "hypothesis"), "violation_relation"),
        "actor_model": pick(row, ("actor_model", "attacker_model", "attacker", "actor"), "actor_model"),
        "impact_class": pick(row, ("impact_class", "impact_rubric_row", "impact", "severity_tier", "severity"), "impact_class"),
    }


def provider_terminal(row: Mapping[str, Any]) -> bool:
    return fuel_identity.provider_terminal(row)


def load_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise FreezeError(f"missing_ledger:{label}") from exc
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FreezeError(f"malformed_ledger:{label}:line={index}") from exc
        if not isinstance(row, dict):
            raise FreezeError(f"malformed_ledger:{label}:line={index}")
        rows.append(row)
    return rows


def empty_row(row: Mapping[str, Any], step_id: str, receipt_id: str) -> bool:
    refs = row.get("source_refs")
    units = row.get("applicable_inventory_unit_ids")
    axes = row.get("examined_axes")
    return (
        row.get("schema") == EMPTY_LEDGER_SCHEMA
        and row.get("reasoner_step_id") == step_id
        and row.get("producer_step_id") in {None, step_id}
        and (row.get("producer_receipt_id") is None or row.get("producer_receipt_id") == receipt_id)
        and isinstance(row.get("source_grounded_explanation"), str)
        and bool(row["source_grounded_explanation"].strip())
        and isinstance(refs, list)
        and bool(refs)
        and all(isinstance(item, str) and item.strip() for item in refs)
        and isinstance(units, list)
        and all(isinstance(item, str) and item.strip() for item in units)
        and len(units) == len(set(units))
        and isinstance(axes, list)
        and set(axes) == set(AXES)
        and len(axes) == len(AXES)
    )


def coverage_row(row: Mapping[str, Any], step_id: str, receipt_id: str) -> bool:
    """Validate a reasoner's complete applicable-unit examination receipt."""
    applicable = row.get("applicable_inventory_unit_ids")
    examined = row.get("examined_inventory_unit_ids")
    axes = row.get("examined_axes")
    refs = row.get("source_refs")
    return (
        row.get("schema") == COVERAGE_LEDGER_SCHEMA
        and row.get("reasoner_step_id") == step_id
        and row.get("producer_step_id") in {None, step_id}
        and (row.get("producer_receipt_id") is None or row.get("producer_receipt_id") == receipt_id)
        and isinstance(row.get("source_grounded_explanation"), str)
        and bool(row["source_grounded_explanation"].strip())
        and isinstance(applicable, list)
        and isinstance(examined, list)
        and all(isinstance(item, str) and item.strip() for item in applicable + examined)
        and len(applicable) == len(set(applicable))
        and len(examined) == len(set(examined))
        and set(applicable) == set(examined)
        and isinstance(axes, list)
        and set(axes) == set(AXES)
        and len(axes) == len(AXES)
        and isinstance(refs, list)
        and bool(refs)
        and all(isinstance(item, str) and item.strip() for item in refs)
    )


def validate_reasoner_coverage(
    row: Mapping[str, Any],
    step_id: str,
    receipt_id: str,
    inventory: Mapping[str, Mapping[str, Any]],
) -> None:
    if not coverage_row(row, step_id, receipt_id):
        raise FreezeError(f"malformed_reasoner_coverage:{step_id}")
    unknown = sorted(set(row["applicable_inventory_unit_ids"]) - set(inventory))
    if unknown:
        raise FreezeError(f"reasoner_coverage_unknown_inventory_unit:{step_id}:{unknown[0]}")


def axis_spec(axis: str, fields: Mapping[str, str]) -> tuple[list[str], str]:
    required = ["source_citation", "local_or_chain_evidence", "non_provider_terminal_verdict"]
    detail = {
        "asset_invariant": f"Show preservation or violation of {fields['asset_invariant']}.",
        "state_transition": "Show the exact state before and after the transition.",
        "adversarial_sequence": f"Execute the attacker sequence for {fields['actor_model']}.",
        "assumption_negation": "Negate each trusted precondition and record the surviving guard.",
        "cross_module_composition": "Trace all participating modules and their shared state.",
        "production_reachability": "Prove the path reaches a production entry point without privileged shortcuts.",
        "economic_consensus_impact": f"Measure the rewarded impact class {fields['impact_class']}.",
        "dedup_oos_awareness": "Compare root cause, execution path, and fix against known issues and OOS rules.",
        "executable_falsification": "Run a reproducible positive assertion and a clean negative control.",
    }[axis]
    if axis == "dedup_oos_awareness":
        required.append("current_semantic_awareness_ledger")
    return required, detail


def dependency_closure(by_id: Mapping[str, Mapping[str, Any]], root: str) -> set[str]:
    if root not in by_id:
        return set()
    visited: set[str] = set()
    todo = [root]
    while todo:
        step_id = todo.pop()
        if step_id in visited:
            continue
        visited.add(step_id)
        deps = by_id[step_id].get("depends_on", [])
        if not isinstance(deps, list) or any(dep not in by_id for dep in deps):
            raise FreezeError(f"malformed_dependencies:{step_id}")
        todo.extend(deps)
    return visited


def inventory_unit_id(row: Mapping[str, Any]) -> str:
    for key in ("inventory_unit_id", "unit_id", "id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    identity = {
        key: row[key]
        for key in ("file", "path", "contract", "function", "fn", "start_line", "line")
        if row.get(key) not in {None, ""}
    }
    if not identity:
        raise FreezeError("malformed_inventory_unit_identity")
    return "zdu_" + digest(identity)


def load_inventory(workspace: Path) -> tuple[dict[str, dict[str, Any]], str]:
    path = workspace / INVENTORY_RELATIVE
    rows = load_jsonl(path, "inscope_inventory")
    if not rows:
        raise FreezeError("empty_inscope_inventory")
    units: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("applicable") is False or row.get("in_scope") is False:
            continue
        unit_id = inventory_unit_id(row)
        prior = units.get(unit_id)
        normalized = canonical(row)
        if prior is not None and prior != normalized:
            raise FreezeError(f"conflicting_inventory_unit:{unit_id}")
        units[unit_id] = normalized
    if not units:
        raise FreezeError("no_applicable_inventory_units")
    return units, file_sha256(path)


def require_source_refs(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item.strip() for item in value):
        raise FreezeError(f"missing_source_identity:{label}")
    return sorted({item.strip() for item in value})


def fuel_artifact_path(
    workspace: Path,
    receipts: Mapping[str, Mapping[str, Any]],
    contracts: Mapping[str, Mapping[str, Any]],
    step_id: str,
) -> tuple[Path, Mapping[str, Any]]:
    contract_id = FUEL_STEPS[step_id]
    receipt = receipts.get(step_id)
    contract = contracts.get(contract_id)
    if not isinstance(receipt, Mapping):
        raise FreezeError(f"missing_required_fuel_receipt:{step_id}")
    if not isinstance(contract, Mapping) or not isinstance(contract.get("path"), str):
        raise FreezeError(f"missing_fuel_contract:{step_id}")
    artifact = output_by_contract(receipt, contract_id)
    if artifact is None:
        raise FreezeError(f"fuel_not_produced_by_current_receipt:{step_id}")
    path = verify_artifact(workspace, artifact, f"fuel:{step_id}")
    if path.resolve() != resolve_path(workspace, contract["path"]).resolve():
        raise FreezeError(f"fuel_path_contract_mismatch:{step_id}")
    return path, artifact


def load_fuel_rows(step_id: str, path: Path) -> list[dict[str, Any]]:
    return load_jsonl(path, f"{step_id}_fuel")


def step4c_hunt_report_path(
    workspace: Path,
    receipts: Mapping[str, Mapping[str, Any]],
    contracts: Mapping[str, Mapping[str, Any]],
) -> tuple[Path, Mapping[str, Any]]:
    receipt = receipts.get("step-4c")
    contract = contracts.get(STEP4C_HUNT_REPORT_CONTRACT)
    if not isinstance(receipt, Mapping):
        raise FreezeError("missing_required_hunt_report_receipt")
    if not isinstance(contract, Mapping) or not isinstance(contract.get("path"), str):
        raise FreezeError("missing_hunt_report_contract")
    artifact = output_by_contract(receipt, STEP4C_HUNT_REPORT_CONTRACT)
    if artifact is None:
        raise FreezeError("hunt_report_not_produced_by_current_receipt")
    path = verify_artifact(workspace, artifact, "step4c_hunt_report")
    if path.resolve() != resolve_path(workspace, contract["path"]).resolve():
        raise FreezeError("hunt_report_path_contract_mismatch")
    return path, artifact


def awareness_ledger_path(
    workspace: Path,
    receipts: Mapping[str, Mapping[str, Any]],
    contracts: Mapping[str, Mapping[str, Any]],
) -> tuple[Path, Mapping[str, Any]]:
    receipt = receipts.get("step-0d")
    contract = contracts.get(AWARENESS_LEDGER_CONTRACT)
    if not isinstance(receipt, Mapping):
        raise FreezeError("missing_awareness_ledger_receipt")
    if not isinstance(contract, Mapping) or not isinstance(contract.get("path"), str):
        raise FreezeError("missing_awareness_ledger_contract")
    artifact = output_by_contract(receipt, AWARENESS_LEDGER_CONTRACT)
    if artifact is None:
        raise FreezeError("awareness_ledger_not_produced_by_current_receipt")
    path = verify_artifact(workspace, artifact, "awareness_ledger")
    if path.resolve() != resolve_path(workspace, contract["path"]).resolve():
        raise FreezeError("awareness_ledger_path_contract_mismatch")
    return path, artifact


def validate_awareness_ledger(path: Path) -> dict[str, Any]:
    ledger = load_json(path, "awareness_ledger")
    if ledger.get("schema") != AWARENESS_LEDGER_SCHEMA:
        raise FreezeError("invalid_awareness_ledger_schema")
    if ledger.get("fail_closed") is not False or ledger.get("validation_errors"):
        raise FreezeError("awareness_ledger_not_complete")
    if not isinstance(ledger.get("audit_pin"), str) or not ledger["audit_pin"].strip():
        raise FreezeError("awareness_ledger_pin_missing")
    candidates = ledger.get("candidates")
    if not isinstance(candidates, list):
        raise FreezeError("awareness_ledger_candidates_malformed")
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping) or candidate.get("terminal") is not True:
            raise FreezeError(f"awareness_ledger_unresolved_candidate:{index}")
    return ledger


def awareness_exclusions(
    ledger: Mapping[str, Any], obligations: list[dict[str, Any]]
) -> tuple[set[str], list[dict[str, Any]]]:
    """Bind reviewed awareness exclusions to exact immutable obligations.

    A team-aware candidate is never matched by title, path substring, or a
    generated identifier. The reviewer supplies the full logical obligation
    identity. If it cannot bind to a current reasoner obligation, freeze stops
    instead of silently treating a broad known issue as an exclusion.
    """
    by_id: dict[str, list[dict[str, Any]]] = {}
    for obligation in obligations:
        by_id.setdefault(obligation["obligation_id"], []).append(obligation)
    excluded_ids: set[str] = set()
    rows: list[dict[str, Any]] = []
    candidates = ledger.get("candidates")
    assert isinstance(candidates, list)
    for index, candidate in enumerate(candidates):
        assert isinstance(candidate, Mapping)
        if candidate.get("novelty_blocked") is not True:
            continue
        candidate_id = candidate.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id:
            raise FreezeError(f"awareness_candidate_id_missing:{index}")
        source_ids = candidate.get("source_ids")
        if not isinstance(source_ids, list) or not source_ids or any(not isinstance(item, str) or not item for item in source_ids):
            raise FreezeError(f"awareness_candidate_source_ids_missing:{candidate_id}")
        logical = candidate.get("obligation_logical")
        if not isinstance(logical, Mapping):
            raise FreezeError(f"awareness_obligation_binding_missing:{candidate_id}")
        normalized = {field: logical.get(field) for field in AWARENESS_LOGICAL_FIELDS}
        if any(not isinstance(value, str) or not value for value in normalized.values()):
            raise FreezeError(f"awareness_obligation_binding_invalid:{candidate_id}")
        obligation_id = "zdo_" + digest(normalized)
        matched = by_id.get(obligation_id, [])
        if not matched:
            raise FreezeError(f"awareness_binding_no_current_obligation:{candidate_id}")
        excluded_ids.add(obligation_id)
        for obligation in matched:
            rows.append({
                "schema": "auditooor.zero_day_awareness_exclusion.v1",
                "candidate_id": candidate_id,
                "awareness_state": candidate.get("state"),
                "source_ids": sorted(source_ids),
                "obligation_id": obligation["obligation_id"],
                "revision_id": obligation["revision_id"],
                "logical": normalized,
            })
    rows.sort(key=lambda row: (row["obligation_id"], row["revision_id"], row["candidate_id"]))
    return excluded_ids, rows


def validate_step4c_hunt_report(path: Path, fuel_path: Path, fuel_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Require a fresh Step 4c report alongside its typed JSONL fuel artifact.

    An empty JSONL file is meaningful only when the report proves the corpus produced
    no eligible hypotheses or hacker questions. This prevents an empty file from
    masquerading as a completed corpus pass.
    """

    report = load_json(path, "step4c_hunt_report")
    if report.get("schema") != "auditooor.corpus_driven_hunt.v1":
        raise FreezeError("invalid_step4c_hunt_report_schema")
    if report.get("error"):
        raise FreezeError("step4c_hunt_report_error")
    if not isinstance(report.get("eligible"), int) or report["eligible"] < 0:
        raise FreezeError("step4c_hunt_report_eligible_invalid")
    hypotheses = report.get("hypotheses")
    questions = report.get("hacker_questions")
    if not isinstance(hypotheses, list) or not isinstance(questions, list):
        raise FreezeError("step4c_hunt_report_candidates_invalid")
    claimed_fuel = report.get("zero_day_fuel")
    if not isinstance(claimed_fuel, Mapping):
        raise FreezeError("step4c_hunt_report_missing_fuel_attestation")
    claimed_path = claimed_fuel.get("path")
    claimed_rows = claimed_fuel.get("rows")
    if not isinstance(claimed_path, str) or not isinstance(claimed_rows, int):
        raise FreezeError("step4c_hunt_report_fuel_attestation_invalid")
    if Path(claimed_path).resolve() != fuel_path.resolve() or claimed_rows != len(fuel_rows):
        raise FreezeError("step4c_hunt_report_fuel_attestation_mismatch")
    if not fuel_rows and (report["eligible"] != 0 or hypotheses or questions):
        raise FreezeError("step4c_empty_fuel_without_exhaustive_empty_report")
    return report


def link_fuel_rows(
    fuel_inputs: Mapping[str, list[dict[str, Any]]],
    obligations: list[dict[str, Any]],
) -> tuple[dict[tuple[str, str], list[dict[str, Any]]], list[dict[str, Any]]]:
    by_revision = {(row["obligation_id"], row["revision_id"]): row for row in obligations}
    linked: dict[tuple[str, str], list[dict[str, Any]]] = {}
    all_rows: list[dict[str, Any]] = []
    seen_fuel_ids: set[str] = set()
    for step_id in sorted(fuel_inputs):
        for index, raw in enumerate(fuel_inputs[step_id]):
            row = dict(raw)
            # Older in-memory callers annotated the expected kind. It is never
            # part of the signed fuel body and cannot influence identity.
            row.pop("_expected_fuel_kind", None)
            if row.get("schema") != FUEL_SCHEMA:
                raise FreezeError(f"untyped_unlinked_fuel:{step_id}:row={index}")
            kind = row.get("fuel_kind")
            if step_id == "step-4c" and kind not in {"corpus_hacker_question", "corpus_hypothesis"}:
                raise FreezeError(f"fuel_kind_mismatch:{step_id}:row={index}")
            if step_id == "step-2g-novelty-flywheel" and kind != "novelty_flywheel":
                raise FreezeError(f"fuel_kind_mismatch:{step_id}:row={index}")
            if row.get("producer_step_id") != step_id:
                raise FreezeError(f"fuel_producer_mismatch:{step_id}:row={index}")
            if provider_terminal(row):
                raise FreezeError(f"provider_response_terminal_evidence:{step_id}:row={index}")
            if not any(
                isinstance(row.get(field), str) and row[field].strip()
                for field in ("question", "question_text", "hypothesis", "statement", "title")
            ):
                raise FreezeError(f"fuel_question_identity_missing:{step_id}:row={index}")
            obligation_id = row.get("obligation_id")
            revision_id = row.get("revision_id")
            obligation = by_revision.get((obligation_id, revision_id))
            if obligation is None:
                raise FreezeError(f"unlinked_fuel:{step_id}:row={index}")
            source_refs = require_source_refs(row.get("source_refs"), f"fuel:{step_id}:row={index}")
            if source_refs != sorted(set(obligation["source_refs"])):
                raise FreezeError(f"fuel_source_identity_mismatch:{step_id}:row={index}")
            if row.get("asset_invariant") != obligation["logical"]["asset_invariant"]:
                raise FreezeError(f"fuel_invariant_identity_mismatch:{step_id}:row={index}")
            if row.get("impact_class") != obligation["logical"]["impact_class"]:
                raise FreezeError(f"fuel_impact_identity_mismatch:{step_id}:row={index}")
            supplied_fuel_id = row.pop("fuel_id", None)
            fuel_body = canonical(row)
            computed_id = "zdf_" + digest(fuel_body)
            if supplied_fuel_id is not None and supplied_fuel_id != computed_id:
                raise FreezeError(f"fuel_id_mismatch:{step_id}:row={index}")
            if computed_id in seen_fuel_ids:
                raise FreezeError(f"duplicate_fuel_id:{computed_id}")
            seen_fuel_ids.add(computed_id)
            linked_row = {
                "fuel_id": computed_id,
                "fuel_kind": kind,
                "producer_step_id": step_id,
                "source_row_sha256": digest(fuel_body),
                "payload": fuel_body,
            }
            key = (str(obligation_id), str(revision_id))
            linked.setdefault(key, []).append(linked_row)
            all_rows.append(linked_row)
    for values in linked.values():
        values.sort(key=lambda item: item["fuel_id"])
    all_rows.sort(key=lambda item: (item["producer_step_id"], item["fuel_id"]))
    return linked, all_rows


def build_empty_proofs(
    inventory: Mapping[str, Mapping[str, Any]],
    empty_rows: Mapping[str, Mapping[str, Any]],
    receipts: Mapping[str, Mapping[str, Any]],
    input_fingerprint: str,
) -> list[dict[str, Any]]:
    coverage: dict[str, dict[str, set[str]]] = {
        unit_id: {axis: set() for axis in AXES} for unit_id in inventory
    }
    for step_id, row in empty_rows.items():
        for unit_id in row["applicable_inventory_unit_ids"]:
            if unit_id not in inventory:
                raise FreezeError(f"empty_proof_unknown_inventory_unit:{step_id}:{unit_id}")
            for axis in row["examined_axes"]:
                coverage[unit_id][axis].add(step_id)
    proofs: list[dict[str, Any]] = []
    for unit_id in sorted(inventory):
        missing = [axis for axis in AXES if not coverage[unit_id][axis]]
        if missing:
            raise FreezeError(f"starved_empty_inventory_unit:{unit_id}:axes={','.join(missing)}")
        reasoners = sorted({step_id for axis in AXES for step_id in coverage[unit_id][axis]})
        refs: set[str] = set()
        inventory_refs = inventory[unit_id].get("source_refs")
        if isinstance(inventory_refs, list):
            refs.update(str(item).strip() for item in inventory_refs if str(item).strip())
        for step_id in reasoners:
            refs.update(empty_rows[step_id]["source_refs"])
        if not refs:
            raise FreezeError(f"empty_proof_missing_source_identity:{unit_id}")
        proof_body = {
            "inventory_unit_id": unit_id,
            "examined_axes": list(AXES),
            "reasoner_step_ids": reasoners,
            "reasoner_receipt_ids": sorted(receipts[step_id]["receipt_id"] for step_id in reasoners),
            "source_refs": sorted(refs),
            "input_fingerprint": input_fingerprint,
        }
        proofs.append({"schema": EMPTY_SCHEMA, "empty_proof_id": "zde_" + digest(proof_body), **proof_body})
    return proofs


def compile_identity_map(
    workspace: Path,
    manifest_path: Path,
    state_path: Path,
    receipts_dir: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Derive exact reasoner identities before fuel producers run.

    This intentionally validates only the current reasoner dependency context.
    Step 4c and the flywheel are fuel producers, so their receipts must not be
    required while preparing the map they consume.
    """
    manifest = load_json(manifest_path, "manifest")
    state = load_json(state_path, "pipeline_state")
    if state.get("schema") != PIPELINE_STATE_SCHEMA:
        raise FreezeError("invalid_pipeline_state_schema")
    manifest_hash = digest(manifest)
    if state.get("manifest_sha256") != manifest_hash:
        raise FreezeError("manifest_hash_mismatch")
    for field in PROVENANCE_FIELDS:
        if not is_hash(state.get(field)):
            raise FreezeError(f"invalid_state_provenance:{field}")
    by_id, contracts, registry, routes = manifest_context(manifest)
    selected = reasoner_steps(registry)
    if not selected:
        raise FreezeError("empty_reasoner_registry")
    if any(step_id not in by_id for step_id in selected):
        raise FreezeError("reasoner_registry_unknown_step")
    receipts = current_receipts(state, receipts_dir)
    reasoner_context_steps: set[str] = set()
    for step_id in selected:
        reasoner_context_steps.update(dependency_closure(by_id, step_id))
    reasoner_context_steps.difference_update(FUEL_STEPS)
    for step_id in sorted(reasoner_context_steps):
        receipt = receipts.get(step_id)
        if receipt is None:
            raise FreezeError(f"missing_current_receipt:{step_id}")
        validate_receipt(receipt, state, step_id)
        state_outputs = state["steps"][step_id].get("current_output_artifacts")
        if state_outputs != receipt.get("output_artifacts"):
            raise FreezeError(f"state_receipt_output_mismatch:{step_id}")
        for artifact in receipt["output_artifacts"]:
            if not isinstance(artifact, dict):
                raise FreezeError(f"malformed_receipt_outputs:{step_id}")
            verify_artifact(workspace, artifact, f"{step_id}:{artifact.get('artifact_contract')}")
    revision_base = {field: state[field] for field in PROVENANCE_FIELDS}
    revision_base["all_substrate_and_producer_receipt_ids"] = sorted(
        receipts[step_id]["receipt_id"] for step_id in reasoner_context_steps
    )
    revision_base["manifest_sha256"] = manifest_hash
    rows: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    for step_id in selected:
        registration = verify_route(step_id, registry, routes)
        producer = receipts.get(step_id)
        if producer is None:
            raise FreezeError(f"missing_reasoner_receipt:{step_id}")
        contract_id = registration["ledger_artifact"]
        contract = contracts.get(contract_id)
        if not isinstance(contract, Mapping) or not isinstance(contract.get("path"), str):
            raise FreezeError(f"missing_reasoner_ledger_contract:{step_id}")
        artifact = output_by_contract(producer, contract_id)
        if artifact is None:
            raise FreezeError(f"ledger_not_produced_by_current_receipt:{step_id}")
        ledger_path = verify_artifact(workspace, artifact, f"ledger:{step_id}")
        if ledger_path.resolve() != resolve_path(workspace, contract["path"]).resolve():
            raise FreezeError(f"ledger_path_contract_mismatch:{step_id}")
        ledger_rows = load_jsonl(ledger_path, step_id)
        if len(ledger_rows) == 1 and ledger_rows[0].get("schema") == EMPTY_LEDGER_SCHEMA:
            if not empty_row(ledger_rows[0], step_id, producer["receipt_id"]):
                raise FreezeError(f"malformed_examined_empty:{step_id}")
            continue
        if not ledger_rows:
            raise FreezeError(f"untyped_empty_ledger:{step_id}")
        coverage_rows = [row for row in ledger_rows if row.get("schema") == COVERAGE_LEDGER_SCHEMA]
        if len(coverage_rows) != 1:
            raise FreezeError(f"missing_or_ambiguous_reasoner_coverage:{step_id}")
        inventory, _ = load_inventory(workspace)
        validate_reasoner_coverage(coverage_rows[0], step_id, producer["receipt_id"], inventory)
        ledger_rows = [row for row in ledger_rows if row.get("schema") != COVERAGE_LEDGER_SCHEMA]
        if not ledger_rows:
            raise FreezeError(f"reasoner_coverage_without_obligations:{step_id}")
        for source_row in ledger_rows:
            if provider_terminal(source_row):
                raise FreezeError(f"provider_response_terminal_evidence:{step_id}")
            if source_row.get("producer_step_id") not in {None, step_id}:
                raise FreezeError(f"ledger_producer_step_mismatch:{step_id}")
            if source_row.get("producer_receipt_id") is not None and source_row.get("producer_receipt_id") != producer["receipt_id"]:
                raise FreezeError(f"ledger_receipt_binding_mismatch:{step_id}")
            fields = normalized_fields(source_row)
            logical = {
                "target_unit": fields["target_unit"],
                "asset_invariant": fields["asset_invariant"],
                "violation_relation": fields["violation_relation"],
                "actor_model": fields["actor_model"],
                "impact_class": fields["impact_class"],
            }
            identity = fuel_identity.obligation_identity(
                logical=logical,
                revision_base=revision_base,
                producer_receipt_id=producer["receipt_id"],
                ledger_sha256=str(artifact["sha256"]),
                source_row=source_row,
            )
            prior = seen.get(identity["obligation_id"])
            if prior is not None and prior != identity["source_row_sha256"]:
                raise FreezeError(f"conflicting_duplicate_logical_row:{identity['obligation_id']}")
            seen[identity["obligation_id"]] = identity["source_row_sha256"]
            rows.append(fuel_identity.identity_map_row(
                producer_step_id=step_id,
                producer_receipt_id=producer["receipt_id"],
                identity=identity,
                source_refs=require_source_refs(source_row.get("source_refs"), f"reasoner:{step_id}"),
                logical=logical,
            ))
            invariant_ids = source_row.get("broken_invariant_ids")
            function = source_row.get("function")
            if invariant_ids is None or function is None:
                continue
            if (
                not isinstance(invariant_ids, list)
                or not invariant_ids
                or any(not isinstance(value, str) or not value.strip() for value in invariant_ids)
                or not isinstance(function, str)
                or not function.strip()
            ):
                raise FreezeError(f"malformed_step4c_binding_fields:{step_id}")
            for invariant_id in sorted(set(invariant_ids)):
                for fuel_kind in ("corpus_hypothesis", "corpus_hacker_question"):
                    try:
                        rows.append(fuel_identity.corpus_binding_map_row(
                            producer_step_id=step_id,
                            producer_receipt_id=producer["receipt_id"],
                            identity=identity,
                            source_refs=require_source_refs(source_row.get("source_refs"), f"reasoner:{step_id}"),
                            logical=logical,
                            invariant_id=invariant_id,
                            function=function,
                            fuel_kind=fuel_kind,
                        ))
                    except fuel_identity.FuelIdentityError as exc:
                        raise FreezeError(f"malformed_step4c_binding_fields:{step_id}") from exc
    rows.sort(key=lambda row: (row["obligation_id"], row["revision_id"], row["identity_key"]))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(json.dumps(canonical(row), separators=(",", ":"), ensure_ascii=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    return {
        "schema": IDENTITY_MAP_SCHEMA,
        "identity_map_path": str(output_path),
        "identity_count": len(rows),
        "reasoner_receipt_ids": sorted(receipts[step_id]["receipt_id"] for step_id in reasoner_context_steps),
        "manifest_sha256": manifest_hash,
        "identity_map_sha256": file_sha256(output_path),
    }


def compile_freeze(workspace: Path, manifest_path: Path, state_path: Path, receipts_dir: Path, output_dir: Path) -> dict[str, Any]:
    manifest = load_json(manifest_path, "manifest")
    state = load_json(state_path, "pipeline_state")
    if state.get("schema") != PIPELINE_STATE_SCHEMA:
        raise FreezeError("invalid_pipeline_state_schema")
    manifest_hash = digest(manifest)
    if state.get("manifest_sha256") != manifest_hash:
        raise FreezeError("manifest_hash_mismatch")
    for field in PROVENANCE_FIELDS:
        if not is_hash(state.get(field)):
            raise FreezeError(f"invalid_state_provenance:{field}")
    by_id, contracts, registry, routes = manifest_context(manifest)
    selected = reasoner_steps(registry)
    if not selected:
        raise FreezeError("empty_reasoner_registry")
    if any(step_id not in by_id for step_id in selected):
        raise FreezeError("reasoner_registry_unknown_step")
    receipts = current_receipts(state, receipts_dir)
    missing_fuel_steps = sorted(set(FUEL_STEPS) - set(by_id))
    if missing_fuel_steps:
        raise FreezeError("missing_required_fuel_step:" + ",".join(missing_fuel_steps))
    closure = dependency_closure(by_id, "step-2h-reasoner-regen")
    closure.discard("step-2h-reasoner-regen")
    if not closure:
        for step_id in selected:
            closure.update(dependency_closure(by_id, step_id))
        closure.update(FUEL_STEPS)
    for step_id in sorted(closure):
        if step_id not in receipts:
            raise FreezeError(f"missing_current_receipt:{step_id}")
        validate_receipt(receipts[step_id], state, step_id)
        state_outputs = state["steps"][step_id].get("current_output_artifacts")
        if state_outputs != receipts[step_id].get("output_artifacts"):
            raise FreezeError(f"state_receipt_output_mismatch:{step_id}")
        for artifact in receipts[step_id]["output_artifacts"]:
            if not isinstance(artifact, dict):
                raise FreezeError(f"malformed_receipt_outputs:{step_id}")
            verify_artifact(workspace, artifact, f"{step_id}:{artifact.get('artifact_contract')}")
    for fuel_step in FUEL_STEPS:
        if fuel_step in by_id and fuel_step not in receipts:
            raise FreezeError(f"missing_required_fuel_receipt:{fuel_step}")
    inventory, inventory_sha256 = load_inventory(workspace)
    obligations: list[dict[str, Any]] = []
    empty_rows: dict[str, dict[str, Any]] = {}
    all_receipt_ids = sorted(receipt["receipt_id"] for receipt in receipts.values() if receipt.get("step_id") in closure)
    reasoner_context_steps: set[str] = set()
    for step_id in selected:
        reasoner_context_steps.update(dependency_closure(by_id, step_id))
    reasoner_context_steps.difference_update(FUEL_STEPS)
    obligation_receipt_ids = sorted(
        receipts[step_id]["receipt_id"]
        for step_id in reasoner_context_steps
        if step_id in receipts
    )
    revision_base = {field: state[field] for field in PROVENANCE_FIELDS}
    revision_base["all_substrate_and_producer_receipt_ids"] = obligation_receipt_ids
    revision_base["manifest_sha256"] = manifest_hash
    for step_id in selected:
        registration = verify_route(step_id, registry, routes)
        if step_id not in receipts:
            raise FreezeError(f"missing_reasoner_receipt:{step_id}")
        contract_id = registration["ledger_artifact"]
        contract = contracts.get(contract_id)
        if not isinstance(contract, Mapping) or not isinstance(contract.get("path"), str):
            raise FreezeError(f"missing_reasoner_ledger_contract:{step_id}")
        producer = receipts[step_id]
        artifact = output_by_contract(producer, contract_id)
        if artifact is None:
            raise FreezeError(f"ledger_not_produced_by_current_receipt:{step_id}")
        ledger_path = verify_artifact(workspace, artifact, f"ledger:{step_id}")
        declared_path = resolve_path(workspace, contract["path"])
        if ledger_path.resolve() != declared_path.resolve():
            raise FreezeError(f"ledger_path_contract_mismatch:{step_id}")
        rows = load_jsonl(ledger_path, step_id)
        if len(rows) == 1 and rows[0].get("schema") == EMPTY_LEDGER_SCHEMA:
            if not empty_row(rows[0], step_id, producer["receipt_id"]):
                raise FreezeError(f"malformed_examined_empty:{step_id}")
            empty_rows[step_id] = canonical(rows[0])
            continue
        if not rows:
            raise FreezeError(f"untyped_empty_ledger:{step_id}")
        coverage_rows = [row for row in rows if row.get("schema") == COVERAGE_LEDGER_SCHEMA]
        if len(coverage_rows) != 1:
            raise FreezeError(f"missing_or_ambiguous_reasoner_coverage:{step_id}")
        validate_reasoner_coverage(coverage_rows[0], step_id, producer["receipt_id"], inventory)
        rows = [row for row in rows if row.get("schema") != COVERAGE_LEDGER_SCHEMA]
        if not rows:
            raise FreezeError(f"reasoner_coverage_without_obligations:{step_id}")
        for row in rows:
            if provider_terminal(row):
                raise FreezeError(f"provider_response_terminal_evidence:{step_id}")
            if row.get("producer_step_id") not in {None, step_id}:
                raise FreezeError(f"ledger_producer_step_mismatch:{step_id}")
            if row.get("producer_receipt_id") is not None and row.get("producer_receipt_id") != producer["receipt_id"]:
                raise FreezeError(f"ledger_receipt_binding_mismatch:{step_id}")
            fields = normalized_fields(row)
            logical = {"target_unit": fields["target_unit"], "asset_invariant": fields["asset_invariant"], "violation_relation": fields["violation_relation"], "actor_model": fields["actor_model"], "impact_class": fields["impact_class"]}
            identity = fuel_identity.obligation_identity(
                logical=logical,
                revision_base=revision_base,
                producer_receipt_id=producer["receipt_id"],
                ledger_sha256=str(artifact["sha256"]),
                source_row=row,
            )
            source_refs = require_source_refs(row.get("source_refs"), f"reasoner:{step_id}")
            obligations.append({
                "schema": OBLIGATION_SCHEMA,
                "obligation_id": identity["obligation_id"],
                "revision_id": identity["revision_id"],
                "producer_step_id": step_id,
                "reasoner_id": (
                    registration.get("reasoner_id")
                    or registration.get("id")
                    or routes[step_id].get("reasoner_id")
                    or step_id
                ),
                "producer_receipt_id": producer["receipt_id"],
                "logical": logical,
                "source_row_sha256": identity["source_row_sha256"],
                "source_refs": source_refs,
                "proof_task_kind": row.get("proof_task_kind", "executable_falsification"),
                "required_positive_assertions": row.get("required_positive_assertions", []),
                "required_negative_controls": row.get("required_negative_controls", []),
                "input_fingerprint": identity["input_fingerprint"],
            })
    seen: dict[str, str] = {}
    for obligation in obligations:
        prior = seen.get(obligation["obligation_id"])
        if prior is not None and prior != obligation["source_row_sha256"]:
            raise FreezeError(f"conflicting_duplicate_logical_row:{obligation['obligation_id']}")
        seen[obligation["obligation_id"]] = obligation["source_row_sha256"]
    obligations = sorted({(row["obligation_id"], row["revision_id"]): row for row in obligations}.values(), key=lambda row: (row["obligation_id"], row["revision_id"]))
    if not obligations and len(empty_rows) != len(selected):
        missing = sorted(set(selected) - set(empty_rows))
        raise FreezeError("empty_global_obligation_set_without_explanations:" + ",".join(missing))

    fuel_inputs: dict[str, list[dict[str, Any]]] = {}
    fuel_artifact_hashes: dict[str, str] = {}
    for step_id in FUEL_STEPS:
        if step_id not in by_id:
            continue
        path, artifact = fuel_artifact_path(workspace, receipts, contracts, step_id)
        fuel_inputs[step_id] = load_fuel_rows(step_id, path)
        fuel_artifact_hashes[step_id] = str(artifact["sha256"])
    step4c_report_path, step4c_report_artifact = step4c_hunt_report_path(workspace, receipts, contracts)
    validate_step4c_hunt_report(
        step4c_report_path,
        fuel_artifact_path(workspace, receipts, contracts, "step-4c")[0],
        fuel_inputs["step-4c"],
    )
    awareness_path, awareness_artifact = awareness_ledger_path(workspace, receipts, contracts)
    awareness_ledger = validate_awareness_ledger(awareness_path)
    excluded_obligation_ids, awareness_exclusion_rows = awareness_exclusions(awareness_ledger, obligations)
    obligations = [row for row in obligations if row["obligation_id"] not in excluded_obligation_ids]
    if not obligations and len(empty_rows) != len(selected) and not awareness_exclusion_rows:
        missing = sorted(set(selected) - set(empty_rows))
        raise FreezeError("empty_global_obligation_set_without_explanations:" + ",".join(missing))
    linked_fuel, all_fuel_rows = link_fuel_rows(fuel_inputs, obligations)
    for obligation in obligations:
        key = (obligation["obligation_id"], obligation["revision_id"])
        obligation["fuel_ids"] = [row["fuel_id"] for row in linked_fuel.get(key, [])]

    questions: list[dict[str, Any]] = []
    for obligation in obligations:
        key = (obligation["obligation_id"], obligation["revision_id"])
        fuel_refs = linked_fuel.get(key, [])
        question_input_fingerprint = digest({
            "obligation_input_fingerprint": obligation["input_fingerprint"],
            "fuel_source_row_sha256": [row["source_row_sha256"] for row in fuel_refs],
        })
        for axis in AXES:
            required, route = axis_spec(axis, obligation["logical"])
            question_body = {"obligation_id": obligation["obligation_id"], "revision_id": obligation["revision_id"], "axis": axis, "input_fingerprint": question_input_fingerprint}
            questions.append({
                "schema": QUESTION_SCHEMA,
                "question_id": "zdq_" + digest(question_body),
                "parent_ids": [obligation["obligation_id"], obligation["revision_id"]],
                "axis": axis,
                "required_evidence": required,
                "proof_route": route,
                "fuel_refs": fuel_refs,
                "input_fingerprint": question_input_fingerprint,
            })
    questions.sort(key=lambda row: (row["parent_ids"], row["axis"]))

    source_scope_severity_rules_fingerprint = digest({
        "source_snapshot_sha256": state["source_snapshot_sha256"],
        "scope_sha256": state["scope_sha256"],
        "severity_sha256": state["severity_sha256"],
        "program_rules_sha256": state["program_rules_sha256"],
    })
    freeze_input_fingerprint = digest({
        "manifest_sha256": manifest_hash,
        "state_sha256": file_sha256(state_path),
        "producer_receipt_ids": all_receipt_ids,
        "reasoner_receipt_ids": obligation_receipt_ids,
        "fuel_artifact_hashes": fuel_artifact_hashes,
        "step4c_hunt_report_sha256": str(step4c_report_artifact["sha256"]),
        "awareness_ledger_sha256": str(awareness_artifact["sha256"]),
        "fuel_rows_sha256": digest(all_fuel_rows),
        "inventory_sha256": inventory_sha256,
        "source_scope_severity_rules_fingerprint": source_scope_severity_rules_fingerprint,
        "pipeline_tooling_sha256": state["pipeline_tooling_sha256"],
    })
    empty_proofs = (
        build_empty_proofs(inventory, empty_rows, receipts, freeze_input_fingerprint)
        if not obligations and empty_rows
        else []
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    obligations_path = output_dir / "obligations.jsonl"
    questions_path = output_dir / "questions.jsonl"
    empty_proofs_path = output_dir / "examined_empty.jsonl"
    awareness_exclusions_path = output_dir / "awareness_exclusions.jsonl"
    obligations_text = "".join(json.dumps(canonical(row), separators=(",", ":"), ensure_ascii=True) + "\n" for row in obligations)
    questions_text = "".join(json.dumps(canonical(row), separators=(",", ":"), ensure_ascii=True) + "\n" for row in questions)
    empty_proofs_text = "".join(json.dumps(canonical(row), separators=(",", ":"), ensure_ascii=True) + "\n" for row in empty_proofs)
    obligations_path.write_text(obligations_text, encoding="utf-8")
    questions_path.write_text(questions_text, encoding="utf-8")
    empty_proofs_path.write_text(empty_proofs_text, encoding="utf-8")
    awareness_exclusions_path.write_text(
        "".join(json.dumps(canonical(row), separators=(",", ":"), ensure_ascii=True) + "\n" for row in awareness_exclusion_rows),
        encoding="utf-8",
    )
    fuel_counts = {
        step_id: len(fuel_inputs.get(step_id, []))
        for step_id in sorted(FUEL_STEPS)
        if step_id in by_id
    }
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "manifest_sha256": manifest_hash,
        "state_sha256": file_sha256(state_path),
        "provenance": {field: state[field] for field in PROVENANCE_FIELDS},
        "producer_receipt_ids": all_receipt_ids,
        "reasoner_receipt_ids": obligation_receipt_ids,
        "reasoner_count": len(selected),
        "obligation_count": len(obligations),
        "question_count": len(questions),
        "examined_empty_count": len(empty_proofs),
        "empty_explanations": {key: empty_rows[key]["source_grounded_explanation"] for key in sorted(empty_rows)},
        "inventory_count": len(inventory),
        "inventory_sha256": inventory_sha256,
        "fuel_artifact_sha256": fuel_artifact_hashes,
        "step4c_hunt_report_sha256": str(step4c_report_artifact["sha256"]),
        "awareness_ledger_sha256": str(awareness_artifact["sha256"]),
        "awareness_exclusion_count": len(awareness_exclusion_rows),
        "awareness_exclusions_sha256": file_sha256(awareness_exclusions_path),
        "fuel_counts": fuel_counts,
        "fuel_row_count": len(all_fuel_rows),
        "fuel_rows_sha256": digest(all_fuel_rows),
        "source_scope_severity_rules_fingerprint": source_scope_severity_rules_fingerprint,
        "obligations_sha256": file_sha256(obligations_path),
        "questions_sha256": file_sha256(questions_path),
        "examined_empty_sha256": file_sha256(empty_proofs_path),
        "input_fingerprint": freeze_input_fingerprint,
    }
    receipt["receipt_id"] = digest(receipt)
    (output_dir / "freeze_receipt.json").write_text(json.dumps(canonical(receipt), separators=(",", ":"), ensure_ascii=True) + "\n", encoding="utf-8")
    return receipt


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    repo = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=repo / "tools" / "readme_runbook_steps.json")
    parser.add_argument("--state", type=Path)
    parser.add_argument("--receipts-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--write-identity-map", action="store_true",
                        help="derive receipt-bound reasoner identities before fuel producers run")
    parser.add_argument("--identity-map-out", type=Path,
                        help="identity-map output path; also enables --write-identity-map")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    args.identity_map_requested = bool(args.write_identity_map or args.identity_map_out is not None)
    audit = args.workspace / ".auditooor"
    args.state = args.state or audit / "pipeline" / "state.json"
    args.receipts_dir = args.receipts_dir or args.state.parent / "receipts"
    args.output_dir = args.output_dir or audit / "zero_day_bus"
    args.identity_map_out = args.identity_map_out or audit / "zero_day_identity_map.jsonl"
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.identity_map_requested:
            receipt = compile_identity_map(
                args.workspace.resolve(), args.manifest.resolve(), args.state.resolve(),
                args.receipts_dir.resolve(), args.identity_map_out.resolve(),
            )
        else:
            receipt = compile_freeze(args.workspace.resolve(), args.manifest.resolve(), args.state.resolve(), args.receipts_dir.resolve(), args.output_dir.resolve())
    except FreezeError as exc:
        print(f"zero-day-freeze-compiler: FAIL {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(canonical(receipt), separators=(",", ":"), ensure_ascii=True))
    elif args.identity_map_requested:
        print(f"zero-day-freeze-compiler: PASS identity-map={receipt['identity_count']}")
    else:
        print(f"zero-day-freeze-compiler: PASS obligations={receipt['obligation_count']} questions={receipt['question_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
