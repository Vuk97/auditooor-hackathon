#!/usr/bin/env python3
"""Compile a discovered awareness-source catalog into an exact review inventory.

Discovery and semantic disposition are separate responsibilities.  Upstream
collectors enumerate source instances in a pin-bound catalog; this reducer
normalizes that catalog into the ``expected_sources`` contract consumed by the
awareness ledger.  It never infers that a source makes the team aware.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "auditooor.awareness_source_discovery.v1"
SOURCE_KINDS = frozenset({
    "prior_audit", "commit", "pull_request", "issue", "discussion",
    "review_comment", "source_comment", "known_issue_list",
})


class InventoryError(ValueError):
    pass


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def compile_expected_sources(discovery: Mapping[str, Any], audit_pin: str) -> list[dict[str, str]]:
    """Validate one normalized catalog and return stable exact inventory rows."""
    if discovery.get("schema") != SCHEMA:
        raise InventoryError("invalid_awareness_source_discovery_schema")
    pin = _text(audit_pin)
    if not pin or _text(discovery.get("audit_pin")) != pin:
        raise InventoryError("awareness_source_discovery_pin_mismatch")
    coverage = discovery.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != SOURCE_KINDS:
        raise InventoryError("awareness_source_discovery_coverage_incomplete")
    for kind in SOURCE_KINDS:
        item = coverage.get(kind)
        if not isinstance(item, Mapping) or item.get("status") != "complete":
            raise InventoryError("awareness_source_discovery_coverage_incomplete")
    sources = discovery.get("sources")
    if not isinstance(sources, list):
        raise InventoryError("awareness_source_discovery_sources_malformed")
    expected: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(sources):
        if not isinstance(raw, Mapping):
            raise InventoryError(f"awareness_source_discovery_row_{index}_malformed")
        source_id = _text(raw.get("source_id"))
        source_kind = _text(raw.get("source_kind"))
        source_ref = _text(raw.get("source_ref"))
        source_pin = _text(raw.get("pin_binding", raw.get("audit_pin")))
        if not source_id or source_id in seen:
            raise InventoryError(f"awareness_source_discovery_row_{index}_id_invalid")
        if source_kind not in SOURCE_KINDS:
            raise InventoryError(f"awareness_source_discovery_row_{index}_kind_invalid")
        if not source_ref or source_pin != pin:
            raise InventoryError(f"awareness_source_discovery_row_{index}_binding_invalid")
        seen.add(source_id)
        expected.append({
            "source_id": source_id,
            "source_kind": source_kind,
            "source_ref": source_ref,
            "pin_binding": pin,
        })
    return sorted(expected, key=lambda row: row["source_id"])


def load_discovery(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError("awareness_source_discovery_unreadable") from exc
    if not isinstance(value, dict):
        raise InventoryError("awareness_source_discovery_not_object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--discovery", required=True, type=Path)
    parser.add_argument("--audit-pin", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        rows = compile_expected_sources(load_discovery(args.discovery), args.audit_pin)
    except InventoryError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    payload = {"schema": SCHEMA, "audit_pin": args.audit_pin, "expected_sources": rows}
    rendered = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
