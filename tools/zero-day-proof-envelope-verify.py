#!/usr/bin/env python3
"""Materialize and verify immutable envelopes for typed zero-day proof queues.

The canonical Step 4e queue is admitted from a frozen obligation bus. Downstream
consumers may add local proof, impact, OOS, and terminal evidence, but they must
not alter or replace its parent identity. This tool derives a stable envelope
manifest from an admitted queue and compares a later consumer queue to it using
only exact, typed fields. It deliberately has no title, function, or fuzzy-ID
matching path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping


QUEUE_SCHEMA = "auditooor.exploit_queue.v1"
PROJECTION_SCHEMA = "auditooor.zero_day_proof_queue_projection.v1"
ADMISSION_SCHEMA = "auditooor.zero_day_proof_admission.v1"
ENVELOPE_SCHEMA = "auditooor.zero_day_proof_envelope.v1"
TERMINAL_VERDICT_SCHEMA = "auditooor.zero_day_proof_terminal_verdict.v1"
PROOF_TASK_QUEUE_ROLE = "proof_tasks"
DEFAULT_ENVELOPE_REL = ".auditooor/zero_day_proof_envelope.json"
_SOURCE_CITE_RE = re.compile(r"\.\w+:L?\d+")


class EnvelopeError(RuntimeError):
    """Fail-closed typed-proof envelope error with a stable diagnostic."""


def terminal_record_matches(entry: Mapping[str, Any], row: Mapping[str, Any]) -> bool:
    """Return whether a row's terminal record preserves its exact typed identity."""
    record = row.get("terminal_join")
    if not isinstance(record, Mapping) or record.get("schema") != TERMINAL_VERDICT_SCHEMA:
        record = row.get("zero_day_proof_terminal_verdict")
    if not isinstance(record, Mapping) or record.get("schema") != TERMINAL_VERDICT_SCHEMA:
        return False
    if record.get("parent_ids") != entry.get("parent_ids"):
        return False
    if record.get("envelope_id") != entry.get("envelope_id"):
        return False
    cite = str(record.get("source_cite") or record.get("evidence_ref") or "")
    return bool(_SOURCE_CITE_RE.search(cite))


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonical(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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


def _inside_workspace(path: Path, workspace: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise EnvelopeError(f"proof_envelope_{label}_outside_workspace") from exc
    return resolved


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise EnvelopeError(f"proof_envelope_{label}_missing")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"proof_envelope_{label}_malformed") from exc
    if not isinstance(payload, dict):
        raise EnvelopeError(f"proof_envelope_{label}_malformed")
    return payload


def _nonempty_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnvelopeError(code)
    return value


def _parent_ids(value: Any, code: str) -> tuple[str, str]:
    if not isinstance(value, list) or len(value) != 2:
        raise EnvelopeError(code)
    return (_nonempty_string(value[0], code), _nonempty_string(value[1], code))


def _entry_from_row(row: Mapping[str, Any], number: int, admission: Mapping[str, Any]) -> dict[str, Any]:
    lead_id = _nonempty_string(row.get("lead_id"), f"proof_envelope_lead_id_missing:row-{number}")
    parent = (
        _nonempty_string(row.get("obligation_id"), f"proof_envelope_obligation_id_missing:row-{number}"),
        _nonempty_string(row.get("revision_id"), f"proof_envelope_revision_id_missing:row-{number}"),
    )
    projection = row.get("zero_day_proof_projection")
    row_admission = row.get("zero_day_proof_admission")
    if not isinstance(projection, dict):
        raise EnvelopeError(f"proof_envelope_projection_missing:row-{number}")
    if not isinstance(row_admission, dict):
        raise EnvelopeError(f"proof_envelope_admission_missing:row-{number}")
    if projection.get("schema") != PROJECTION_SCHEMA:
        raise EnvelopeError(f"proof_envelope_projection_schema_invalid:row-{number}")
    projection_parent = _parent_ids(projection.get("parent_ids"), f"proof_envelope_projection_parent_invalid:row-{number}")
    admission_parent = _parent_ids(row_admission.get("parent_ids"), f"proof_envelope_admission_parent_invalid:row-{number}")
    if projection_parent != parent or admission_parent != parent:
        raise EnvelopeError(f"proof_envelope_parent_mismatch:row-{number}")
    protected = {
        "lead_id": lead_id,
        "parent_ids": list(parent),
        "freeze_receipt_id": _nonempty_string(projection.get("freeze_receipt_id"), f"proof_envelope_receipt_missing:row-{number}"),
        "freeze_input_fingerprint": _nonempty_string(projection.get("freeze_input_fingerprint"), f"proof_envelope_fingerprint_missing:row-{number}"),
        "obligation_source_row_sha256": _nonempty_string(
            projection.get("obligation_source_row_sha256"), f"proof_envelope_source_hash_missing:row-{number}"
        ),
        "selection_ordinal": projection.get("selection_ordinal"),
        "question_evidence_sha256": _stable_hash(projection.get("question_evidence")),
        "admission_id": _nonempty_string(admission.get("admission_id"), "proof_envelope_admission_id_missing"),
        "admission_input_queue_sha256": _nonempty_string(
            admission.get("input_queue_sha256"), "proof_envelope_admission_input_hash_missing"
        ),
    }
    if not isinstance(protected["selection_ordinal"], int) or protected["selection_ordinal"] < 1:
        raise EnvelopeError(f"proof_envelope_selection_ordinal_invalid:row-{number}")
    for field in ("freeze_receipt_id", "obligation_source_row_sha256"):
        if row_admission.get(field) != protected[field]:
            raise EnvelopeError(f"proof_envelope_admission_{field}_mismatch:row-{number}")
    if row_admission.get("input_fingerprint") != protected["freeze_input_fingerprint"]:
        raise EnvelopeError(f"proof_envelope_admission_fingerprint_mismatch:row-{number}")
    protected["envelope_id"] = "zdpe_" + _stable_hash(protected)
    return protected


def build_envelope(queue: Mapping[str, Any]) -> dict[str, Any]:
    """Build one immutable identity entry per admitted queue row."""
    if queue.get("schema") != QUEUE_SCHEMA:
        raise EnvelopeError("proof_envelope_queue_schema_invalid")
    if queue.get("queue_role") != PROOF_TASK_QUEUE_ROLE:
        raise EnvelopeError("proof_envelope_queue_role_invalid")
    rows = queue.get("queue")
    admission = queue.get("zero_day_proof_admission")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise EnvelopeError("proof_envelope_queue_rows_invalid")
    if not isinstance(admission, dict) or admission.get("schema") != ADMISSION_SCHEMA:
        raise EnvelopeError("proof_envelope_admission_schema_invalid")
    if admission.get("queue_role") != PROOF_TASK_QUEUE_ROLE:
        raise EnvelopeError("proof_envelope_admission_queue_role_invalid")
    admission_id = _nonempty_string(admission.get("admission_id"), "proof_envelope_admission_id_missing")
    admission_receipt = _nonempty_string(admission.get("freeze_receipt_id"), "proof_envelope_admission_receipt_missing")
    admission_fingerprint = _nonempty_string(
        admission.get("freeze_input_fingerprint"), "proof_envelope_admission_fingerprint_missing"
    )
    admission_input_queue_sha256 = _nonempty_string(
        admission.get("input_queue_sha256"), "proof_envelope_admission_input_hash_missing"
    )
    if admission.get("admitted_count") != len(rows):
        raise EnvelopeError("proof_envelope_admission_count_mismatch")
    admitted_parents = admission.get("admitted_parents")
    if not isinstance(admitted_parents, list) or len(admitted_parents) != len(rows):
        raise EnvelopeError("proof_envelope_admission_parent_set_invalid")
    entries: list[dict[str, Any]] = []
    lead_ids: set[str] = set()
    for number, row in enumerate(rows, start=1):
        entry = _entry_from_row(row, number, admission)
        if entry["lead_id"] in lead_ids:
            raise EnvelopeError(f"proof_envelope_lead_id_duplicate:row-{number}")
        if entry["freeze_receipt_id"] != admission_receipt or entry["freeze_input_fingerprint"] != admission_fingerprint:
            raise EnvelopeError(f"proof_envelope_admission_top_level_mismatch:row-{number}")
        admitted_parent = admitted_parents[number - 1]
        if not isinstance(admitted_parent, dict) or (
                admitted_parent.get("obligation_id"), admitted_parent.get("revision_id")) != tuple(entry["parent_ids"]):
            raise EnvelopeError(f"proof_envelope_admission_parent_set_mismatch:row-{number}")
        lead_ids.add(entry["lead_id"])
        entries.append(entry)
    entries.sort(key=lambda entry: (entry["selection_ordinal"], entry["lead_id"]))
    return {
        "schema": ENVELOPE_SCHEMA,
        "queue_role": PROOF_TASK_QUEUE_ROLE,
        "admission_id": admission_id,
        "freeze_receipt_id": admission_receipt,
        "freeze_input_fingerprint": admission_fingerprint,
        "input_queue_sha256": admission_input_queue_sha256,
        "entry_count": len(entries),
        "entries": entries,
    }


def verify_envelope(envelope: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Verify that a candidate queue preserves every immutable typed identity."""
    if envelope.get("schema") != ENVELOPE_SCHEMA:
        raise EnvelopeError("proof_envelope_schema_invalid")
    entries = envelope.get("entries")
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise EnvelopeError("proof_envelope_entries_invalid")
    expected = {entry.get("lead_id"): entry for entry in entries if isinstance(entry.get("lead_id"), str)}
    if len(expected) != len(entries):
        raise EnvelopeError("proof_envelope_entries_invalid")
    rebuilt = build_envelope(candidate)
    for field in ("queue_role", "admission_id", "freeze_receipt_id", "freeze_input_fingerprint", "input_queue_sha256"):
        if rebuilt.get(field) != envelope.get(field):
            raise EnvelopeError(f"proof_envelope_top_level_identity_mutated:{field}")
    observed = {entry["lead_id"]: entry for entry in rebuilt["entries"]}
    if set(observed) != set(expected):
        missing = sorted(set(expected) - set(observed))
        unknown = sorted(set(observed) - set(expected))
        raise EnvelopeError("proof_envelope_row_set_mismatch:" + json.dumps({"missing": missing, "unknown": unknown}, sort_keys=True))
    for lead_id, expected_entry in expected.items():
        if observed[lead_id] != expected_entry:
            raise EnvelopeError(f"proof_envelope_identity_mutated:{lead_id}")
    return {
        "schema": ENVELOPE_SCHEMA,
        "verdict": "pass-zero-day-proof-envelope",
        "entry_count": len(expected),
        "envelope_sha256": _stable_hash(envelope),
    }


def materialize(workspace: Path, queue_path: Path, output_path: Path) -> dict[str, Any]:
    workspace = workspace.resolve()
    queue_path = _inside_workspace(queue_path, workspace, "queue")
    output_path = _inside_workspace(output_path, workspace, "output")
    if queue_path == output_path:
        raise EnvelopeError("proof_envelope_output_overwrites_source")
    if output_path.exists() or output_path.is_symlink():
        if output_path.is_symlink() or not output_path.is_file():
            raise EnvelopeError("proof_envelope_output_not_regular_file")
        output_path.unlink()
    envelope = build_envelope(_load_json(queue_path, "queue"))
    _atomic_json(output_path, envelope)
    return envelope


def verify(workspace: Path, envelope_path: Path, candidate_path: Path) -> dict[str, Any]:
    workspace = workspace.resolve()
    envelope_path = _inside_workspace(envelope_path, workspace, "manifest")
    candidate_path = _inside_workspace(candidate_path, workspace, "candidate")
    return verify_envelope(_load_json(envelope_path, "manifest"), _load_json(candidate_path, "candidate"))


def verify_persisted(workspace: Path, candidate_path: Path) -> dict[str, Any]:
    """Verify a typed queue against its required workspace-local envelope.

    Terminal consumers must not rebuild an envelope from their current input: that
    proves only internal consistency after a mutation. This helper binds them to
    the immutable Step 4e materialization and rejects a missing, substituted, or
    stale persisted manifest.
    """
    root = workspace.resolve()
    return verify(root, root / DEFAULT_ENVELOPE_REL, candidate_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", "--ws", required=True, type=Path)
    parser.add_argument("--queue", type=Path, help="Admitted typed queue to materialize")
    parser.add_argument("--out", type=Path, help="Envelope manifest output")
    parser.add_argument("--envelope", type=Path, help="Existing envelope manifest to verify")
    parser.add_argument("--candidate-queue", type=Path, help="Downstream queue to compare exactly")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    materialize_mode = args.queue is not None or args.out is not None
    verify_mode = args.envelope is not None or args.candidate_queue is not None
    if materialize_mode == verify_mode or (materialize_mode and (args.queue is None or args.out is None)) or (
            verify_mode and (args.envelope is None or args.candidate_queue is None)):
        parser.error("choose exactly one complete mode: --queue/--out or --envelope/--candidate-queue")
    try:
        result = materialize(args.workspace, args.queue, args.out) if materialize_mode else verify(
            args.workspace, args.envelope, args.candidate_queue
        )
    except EnvelopeError as exc:
        print(f"FAIL zero-day-proof-envelope-verify: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("pass-zero-day-proof-envelope" if verify_mode else "pass-zero-day-proof-envelope-materialize")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
