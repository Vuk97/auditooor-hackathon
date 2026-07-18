"""Deterministic typed zero-day fuel identities shared by producers and freeze.

Producers cannot infer a reasoner obligation from prose, source paths, or model
output.  A caller must provide a one-to-one identity-map entry minted from the
current reasoner ledger.  This module validates that explicit binding and
creates the canonical fuel row consumed by ``zero-day-freeze-compiler.py``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


FUEL_SCHEMA = "auditooor.zero_day_fuel.v1"
IDENTITY_MAP_SCHEMA = "auditooor.zero_day_identity_map.v1"


class FuelIdentityError(ValueError):
    """Raised when a fuel row cannot be bound without guessing."""


def canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): canonical(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple)):
        return [canonical(item) for item in value]
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(canonical(value), separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def obligation_identity(
    *,
    logical: Mapping[str, str],
    revision_base: Mapping[str, Any],
    producer_receipt_id: str,
    ledger_sha256: str,
    source_row: Mapping[str, Any],
) -> dict[str, str]:
    """Return the immutable obligation/revision identity used by full freeze."""
    obligation_id = "zdo_" + digest(logical)
    source_row_sha256 = digest(source_row)
    revision_context = {
        **canonical(revision_base),
        "obligation_id": obligation_id,
        "producer_receipt_id": producer_receipt_id,
        "ledger_sha256": ledger_sha256,
        "source_row_sha256": source_row_sha256,
    }
    return {
        "obligation_id": obligation_id,
        "revision_id": "zdr_" + digest(revision_context),
        "source_row_sha256": source_row_sha256,
        "input_fingerprint": digest(revision_context),
    }


def identity_map_row(
    *,
    producer_step_id: str,
    producer_receipt_id: str,
    identity: Mapping[str, str],
    source_refs: list[str],
    logical: Mapping[str, str],
) -> dict[str, Any]:
    """Create an exact, source-row-addressable map entry without aliases."""
    source_row_sha256 = identity["source_row_sha256"]
    return {
        "schema": IDENTITY_MAP_SCHEMA,
        "identity_key": f"reasoner:{producer_step_id}:{source_row_sha256}",
        "obligation_id": identity["obligation_id"],
        "revision_id": identity["revision_id"],
        "producer_step_id": producer_step_id,
        "producer_receipt_id": producer_receipt_id,
        "source_row_sha256": source_row_sha256,
        "source_refs": sorted(set(source_refs)),
        "asset_invariant": logical["asset_invariant"],
        "impact_class": logical["impact_class"],
    }


def corpus_binding_key(*, fuel_kind: str, invariant_id: str, function: str) -> str:
    """Return a strict Step 4c join key from declared producer fields only."""
    if fuel_kind not in {"corpus_hypothesis", "corpus_hacker_question"}:
        raise FuelIdentityError(f"invalid_corpus_binding_kind:{fuel_kind}")
    if not isinstance(invariant_id, str) or not invariant_id.strip():
        raise FuelIdentityError("missing_corpus_binding_invariant_id")
    if not isinstance(function, str) or not function.strip():
        raise FuelIdentityError("missing_corpus_binding_function")
    return f"{fuel_kind}:{invariant_id.strip()}:{function.strip()}"


def corpus_binding_map_row(
    *,
    producer_step_id: str,
    producer_receipt_id: str,
    identity: Mapping[str, str],
    source_refs: list[str],
    logical: Mapping[str, str],
    invariant_id: str,
    function: str,
    fuel_kind: str,
) -> dict[str, Any]:
    """Project one declared reasoner invariant/function edge for Step 4c.

    This is not a lexical alias. The edge exists only where the reasoner ledger
    itself declares its invariant ID and function, and therefore remains tied to
    the immutable source-row identity.
    """
    return {
        **identity_map_row(
            producer_step_id=producer_step_id,
            producer_receipt_id=producer_receipt_id,
            identity=identity,
            source_refs=source_refs,
            logical=logical,
        ),
        "identity_key": corpus_binding_key(
            fuel_kind=fuel_kind, invariant_id=invariant_id, function=function
        ),
        "binding_kind": "declared_reasoner_invariant_function",
        "binding_invariant_id": invariant_id.strip(),
        "binding_function": function.strip(),
    }


def provider_terminal(row: Mapping[str, Any]) -> bool:
    for key in ("terminal_evidence", "evidence_type", "verdict_evidence", "proof_evidence"):
        value = row.get(key)
        if isinstance(value, str) and "provider" in value.lower():
            return True
    return bool(row.get("provider_response_terminal"))


def _required_text(row: Mapping[str, Any], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise FuelIdentityError(f"missing_identity_{field}")
    return value.strip()


def _source_refs(row: Mapping[str, Any]) -> list[str]:
    value = row.get("source_refs")
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item.strip() for item in value):
        raise FuelIdentityError("missing_identity_source_refs")
    return sorted({item.strip() for item in value})


def identity_map_index(rows: list[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Validate an explicit identity map and reject ambiguous producer keys."""
    index: dict[str, dict[str, Any]] = {}
    for position, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise FuelIdentityError(f"malformed_identity_map_row:{position}")
        key = _required_text(raw, "identity_key")
        link = {
            "obligation_id": _required_text(raw, "obligation_id"),
            "revision_id": _required_text(raw, "revision_id"),
            "source_refs": _source_refs(raw),
            "asset_invariant": _required_text(raw, "asset_invariant"),
            "impact_class": _required_text(raw, "impact_class"),
        }
        if not link["obligation_id"].startswith("zdo_") or not link["revision_id"].startswith("zdr_"):
            raise FuelIdentityError(f"invalid_reasoner_identity:{key}")
        if key in index:
            raise FuelIdentityError(f"ambiguous_identity_map:{key}")
        index[key] = link
    return index


def load_identity_map(path: Path) -> dict[str, dict[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise FuelIdentityError(f"missing_identity_map:{path}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FuelIdentityError(f"malformed_identity_map:{path}:line={line_number}") from exc
        rows.append(row)
    return identity_map_index(rows)


def fuel_row(
    *,
    producer_step_id: str,
    fuel_kind: str,
    identity_key: str,
    identity_index: Mapping[str, Mapping[str, Any]],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a canonical fuel row from a single explicit reasoner identity."""
    if provider_terminal(payload):
        raise FuelIdentityError(f"provider_response_terminal_evidence:{identity_key}")
    link = identity_index.get(identity_key)
    if link is None:
        raise FuelIdentityError(f"unlinked_applicable_fuel:{identity_key}")
    body = {
        "schema": FUEL_SCHEMA,
        "fuel_kind": fuel_kind,
        "producer_step_id": producer_step_id,
        "obligation_id": link["obligation_id"],
        "revision_id": link["revision_id"],
        "source_refs": list(link["source_refs"]),
        "asset_invariant": link["asset_invariant"],
        "impact_class": link["impact_class"],
        **canonical(payload),
    }
    # Identity fields are authoritative and cannot be overridden by producer data.
    body.update({
        "schema": FUEL_SCHEMA,
        "fuel_kind": fuel_kind,
        "producer_step_id": producer_step_id,
        "obligation_id": link["obligation_id"],
        "revision_id": link["revision_id"],
        "source_refs": list(link["source_refs"]),
        "asset_invariant": link["asset_invariant"],
        "impact_class": link["impact_class"],
    })
    return {"fuel_id": "zdf_" + digest(body), **body}
