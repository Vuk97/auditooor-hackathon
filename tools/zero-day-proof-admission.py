#!/usr/bin/env python3
"""Admit proof-conversion queue rows only from the current frozen zero-day bus.

The Step 2h freeze receipt is the only authority for Step 4e proof work. This
adapter preserves the established exploit-queue envelope for existing consumers,
but writes a distinct admitted copy whose actionable rows have an exact current
``(obligation_id, revision_id)`` parent. It never modifies the producer queue.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping


QUEUE_SCHEMA = "auditooor.exploit_queue.v1"
ADMISSION_SCHEMA = "auditooor.zero_day_proof_admission.v1"
PROOF_TASK_QUEUE_ROLE = "proof_tasks"
HUNT_TOOL = Path(__file__).with_name("ordered-llm-hunt.py")


class AdmissionError(RuntimeError):
    """Fail-closed proof-admission error with a stable diagnostic code."""


def _load_hunt_module() -> Any:
    spec = importlib.util.spec_from_file_location("auditooor_ordered_llm_hunt", HUNT_TOOL)
    if spec is None or spec.loader is None:
        raise AdmissionError("ordered_hunt_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, RuntimeError) as exc:
        raise AdmissionError("ordered_hunt_validator_unavailable") from exc
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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_queue(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise AdmissionError("proof_admission_queue_missing")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdmissionError("proof_admission_queue_malformed") from exc
    if not isinstance(payload, dict) or payload.get("schema") != QUEUE_SCHEMA:
        raise AdmissionError("proof_admission_queue_schema_invalid")
    if payload.get("queue_role") != PROOF_TASK_QUEUE_ROLE:
        raise AdmissionError("proof_admission_queue_role_invalid")
    if not isinstance(payload.get("queue"), list) or any(not isinstance(row, dict) for row in payload["queue"]):
        raise AdmissionError("proof_admission_queue_rows_invalid")
    return payload


def load_frozen_bus(workspace: Path) -> dict[str, Any]:
    """Reuse Step 3's complete current-input and freeze-receipt verifier."""
    try:
        return HUNT._validate_bus(workspace, HUNT._current_inputs(workspace))
    except HUNT.HuntError as exc:
        raise AdmissionError(str(exc)) from exc


def _inside_workspace(path: Path, workspace: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise AdmissionError(f"proof_admission_{label}_outside_workspace") from exc
    return resolved


def _row_parent(row: Mapping[str, Any], number: int) -> tuple[str, str]:
    obligation_id = row.get("obligation_id")
    revision_id = row.get("revision_id")
    if not isinstance(obligation_id, str) or not obligation_id:
        raise AdmissionError(f"proof_admission_obligation_id_missing:row-{number}")
    if not isinstance(revision_id, str) or not revision_id:
        raise AdmissionError(f"proof_admission_revision_id_missing:row-{number}")
    return obligation_id, revision_id


def admit_queue(queue_payload: Mapping[str, Any], queue_sha256: str, queue_path: Path,
                workspace: Path, bus: Mapping[str, Any]) -> dict[str, Any]:
    """Return a provenance-bound queue copy, rejecting every unbound row."""
    rows = queue_payload.get("queue")
    parents = bus.get("obligation_by_parent")
    receipt = bus.get("receipt")
    if not isinstance(rows, list) or not isinstance(parents, dict) or not isinstance(receipt, dict):
        raise AdmissionError("proof_admission_validator_result_malformed")

    admitted_rows: list[dict[str, Any]] = []
    admitted_parents: list[dict[str, str]] = []
    for number, source_row in enumerate(rows, start=1):
        if not isinstance(source_row, dict):
            raise AdmissionError(f"proof_admission_queue_rows_invalid:row-{number}")
        parent = _row_parent(source_row, number)
        obligation = parents.get(parent)
        if not isinstance(obligation, dict):
            raise AdmissionError(f"proof_admission_parent_not_current:row-{number}")
        row = copy.deepcopy(source_row)
        row["zero_day_proof_admission"] = {
            "freeze_receipt_id": receipt["receipt_id"],
            "input_fingerprint": receipt["input_fingerprint"],
            "obligation_source_row_sha256": obligation["source_row_sha256"],
            "parent_ids": [parent[0], parent[1]],
        }
        admitted_rows.append(row)
        admitted_parents.append({"obligation_id": parent[0], "revision_id": parent[1]})

    admission = {
        "schema": ADMISSION_SCHEMA,
        "admission_id": "zdpa_" + _stable_hash({
            "freeze_receipt_id": receipt.get("receipt_id"),
            "input_queue_sha256": queue_sha256,
            "parents": admitted_parents,
        }),
        "freeze_receipt_id": receipt.get("receipt_id"),
        "freeze_input_fingerprint": receipt.get("input_fingerprint"),
        "input_queue_path": queue_path.relative_to(workspace).as_posix(),
        "input_queue_sha256": queue_sha256,
        "admitted_count": len(admitted_rows),
        "admitted_parents": admitted_parents,
        "queue_role": PROOF_TASK_QUEUE_ROLE,
    }
    output = copy.deepcopy(dict(queue_payload))
    output["queue"] = admitted_rows
    output["zero_day_proof_admission"] = admission
    return output


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


def run(workspace: Path, queue_path: Path, output_path: Path) -> dict[str, Any]:
    workspace = workspace.resolve()
    queue_path = _inside_workspace(queue_path, workspace, "queue")
    output_path = _inside_workspace(output_path, workspace, "output")
    if queue_path == output_path:
        raise AdmissionError("proof_admission_output_overwrites_source")
    if output_path.exists() or output_path.is_symlink():
        if output_path.is_symlink() or not output_path.is_file():
            raise AdmissionError("proof_admission_output_not_regular_file")
        output_path.unlink()
    payload = _load_queue(queue_path)
    bus = load_frozen_bus(workspace)
    admitted = admit_queue(payload, _sha256_file(queue_path), queue_path, workspace, bus)
    _atomic_json(output_path, admitted)
    return admitted["zero_day_proof_admission"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = run(args.workspace, args.queue, args.out)
    except AdmissionError as exc:
        print(f"FAIL zero-day-proof-admission: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(receipt, sort_keys=True))
    else:
        print("pass-zero-day-proof-admission")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
