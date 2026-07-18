#!/usr/bin/env python3
"""Project validated frozen obligations and Step 3 evidence into a proof queue.

Legacy exploit queues remain discovery inputs. This tool creates the only queue
eligible for canonical proof conversion: one row per current frozen obligation,
with every Q0-Q8 nonterminal hunt sidecar attached to its exact parent.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping


QUEUE_SCHEMA = "auditooor.exploit_queue.v1"
PROJECTION_SCHEMA = "auditooor.zero_day_proof_queue_projection.v1"
PROOF_TASK_QUEUE_ROLE = "proof_tasks"
HUNT_TOOL = Path(__file__).with_name("ordered-llm-hunt.py")


class ProjectionError(RuntimeError):
    """Fail-closed proof-queue projection error."""


def _load_hunt_module() -> Any:
    spec = importlib.util.spec_from_file_location("auditooor_ordered_llm_hunt_projection", HUNT_TOOL)
    if spec is None or spec.loader is None:
        raise ProjectionError("ordered_hunt_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, RuntimeError) as exc:
        raise ProjectionError("ordered_hunt_validator_unavailable") from exc
    return module


HUNT = _load_hunt_module()


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _relative(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace).as_posix()
    except ValueError as exc:
        raise ProjectionError("proof_queue_path_outside_workspace") from exc


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(_canonical(value), handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _provider_result(sidecar: Mapping[str, Any], workspace: Path,
                     sources: Mapping[str, Mapping[str, Any]], task_id: str) -> dict[str, Any]:
    raw = sidecar.get("result")
    if not isinstance(raw, str) or not raw:
        raise ProjectionError(f"proof_queue_sidecar_result_missing:{task_id}")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProjectionError(f"proof_queue_sidecar_result_malformed:{task_id}") from exc
    try:
        return HUNT._validate_provider_result(result, workspace, sources)
    except HUNT.HuntError as exc:
        raise ProjectionError(f"proof_queue_sidecar_result_invalid:{task_id}:{exc}") from exc


def project(validated: Mapping[str, Any]) -> dict[str, Any]:
    workspace = validated.get("workspace")
    current = validated.get("current")
    bus = validated.get("bus")
    tasks_by_id = validated.get("tasks_by_id")
    sidecars_by_task = validated.get("sidecars_by_task")
    if (not isinstance(workspace, Path) or not isinstance(current, dict) or not isinstance(bus, dict)
            or not isinstance(tasks_by_id, dict) or not isinstance(sidecars_by_task, dict)):
        raise ProjectionError("proof_queue_validator_result_malformed")
    workspace = workspace.resolve()
    receipt = bus.get("receipt")
    obligations = bus.get("obligation_by_parent")
    questions = bus.get("questions")
    sources = current.get("sources")
    if (not isinstance(receipt, dict) or not isinstance(obligations, dict)
            or not isinstance(questions, list) or not isinstance(sources, dict)):
        raise ProjectionError("proof_queue_validator_result_malformed")

    questions_by_parent: dict[tuple[str, str], list[dict[str, Any]]] = {
        parent: [] for parent in obligations
    }
    for question in questions:
        if not isinstance(question, dict):
            raise ProjectionError("proof_queue_question_malformed")
        parent_ids = question.get("parent_ids")
        if not isinstance(parent_ids, list) or len(parent_ids) != 2:
            raise ProjectionError("proof_queue_question_parent_malformed")
        parent = (parent_ids[0], parent_ids[1])
        if parent not in questions_by_parent:
            raise ProjectionError("proof_queue_question_parent_unknown")
        questions_by_parent[parent].append(question)

    rows: list[dict[str, Any]] = []
    for ordinal, parent in enumerate(sorted(obligations), start=1):
        obligation = obligations[parent]
        if not isinstance(obligation, dict):
            raise ProjectionError("proof_queue_obligation_malformed")
        logical = obligation.get("logical")
        if not isinstance(logical, dict):
            raise ProjectionError("proof_queue_obligation_logical_malformed")
        expected_questions = sorted(questions_by_parent[parent], key=lambda row: HUNT.AXES.index(row["axis"]))
        if len(expected_questions) != len(HUNT.AXES):
            raise ProjectionError(f"proof_queue_question_axis_incomplete:{parent[0]}:{parent[1]}")
        evidence: list[dict[str, Any]] = []
        applies: list[str] = []
        for question in expected_questions:
            task_id = question["question_id"]
            task = tasks_by_id.get(task_id)
            sidecar = sidecars_by_task.get(task_id)
            if not isinstance(task, dict) or not isinstance(sidecar, dict):
                raise ProjectionError(f"proof_queue_task_or_sidecar_missing:{task_id}")
            result = _provider_result(sidecar, workspace, sources, task_id)
            applies.append(result["applies_to_target"])
            raw_path = task.get("sidecar_path")
            if not isinstance(raw_path, str) or not raw_path:
                raise ProjectionError(f"proof_queue_sidecar_path_missing:{task_id}")
            sidecar_path = Path(raw_path)
            sidecar_path = sidecar_path.resolve() if sidecar_path.is_absolute() else (workspace / sidecar_path).resolve()
            evidence.append({
                "question_id": task_id,
                "axis": question["axis"],
                "sidecar_path": _relative(sidecar_path, workspace),
                "sidecar_sha256": task["sidecar_sha256"],
                "applies_to_target": result["applies_to_target"],
            })
        if set(applies) - {"yes", "no", "maybe"}:
            raise ProjectionError(f"proof_queue_provider_classification_invalid:{parent[0]}:{parent[1]}")
        row_id = "zdpq_" + _stable_hash({"freeze_receipt_id": receipt.get("receipt_id"), "parent_ids": parent})
        rows.append({
            "lead_id": row_id,
            "obligation_id": parent[0],
            "revision_id": parent[1],
            "title": f"Frozen obligation: {logical['violation_relation']}",
            "source": "typed-zero-day-bus",
            "source_refs": obligation["source_refs"],
            "attack_class": logical["violation_relation"],
            "likely_severity": "unknown",
            "severity_confidence": "low",
            "attacker_control": "partial",
            "impact_path": logical["impact_class"],
            "impact_class": logical["impact_class"],
            "impact_id": logical["impact_class"],
            "proof_path": "missing",
            "learning_route": "source-proof",
            "next_command": "Execute the obligation's required local proof route and negative control.",
            "blockers": ["nonterminal-provider-evidence-requires-local-proof"],
            "source_artifacts_complete": False,
            "source_artifact_gaps": ["local-or-chain-evidence", "non-provider-terminal-verdict"],
            "quality_gate_status": "needs_source",
            "proof_status": "needs_source",
            "zero_day_proof_projection": {
                "schema": PROJECTION_SCHEMA,
                "freeze_receipt_id": receipt["receipt_id"],
                "freeze_input_fingerprint": receipt["input_fingerprint"],
                "obligation_source_row_sha256": obligation["source_row_sha256"],
                "parent_ids": [parent[0], parent[1]],
                "selection_ordinal": ordinal,
                "question_evidence": evidence,
            },
        })
    projection = {
        "schema": PROJECTION_SCHEMA,
        "freeze_receipt_id": receipt["receipt_id"],
        "freeze_input_fingerprint": receipt["input_fingerprint"],
        "obligation_count": len(rows),
        "question_denominator": len(questions),
        "queue_sha256": _stable_hash(rows),
    }
    return {
        "schema": QUEUE_SCHEMA,
        "queue_role": PROOF_TASK_QUEUE_ROLE,
        "queue": rows,
        "entries": [],
        "zero_day_proof_projection": projection,
    }


def run(workspace: Path, output_path: Path) -> dict[str, Any]:
    root = workspace.expanduser().resolve()
    output = output_path.resolve()
    _relative(output, root)
    if output.exists() or output.is_symlink():
        if output.is_symlink() or not output.is_file():
            raise ProjectionError("proof_queue_output_not_regular_file")
        output.unlink()
    try:
        validated = HUNT.validate_current_ordered_hunt(root)
    except HUNT.HuntError as exc:
        raise ProjectionError(str(exc)) from exc
    payload = project(validated)
    _atomic_json(output, payload)
    return payload["zero_day_proof_projection"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", "--ws", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = run(args.workspace, args.out)
    except ProjectionError as exc:
        print(f"FAIL zero-day-proof-queue-projection: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(receipt, sort_keys=True))
    else:
        print("pass-zero-day-proof-queue-projection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
