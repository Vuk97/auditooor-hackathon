#!/usr/bin/env python3
"""Append a typed, explicit coverage receipt to one reasoner ledger."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SCHEMA = "auditooor.reasoner_coverage.v1"
AXES = (
    "asset_invariant", "state_transition", "adversarial_sequence",
    "assumption_negation", "cross_module_composition",
    "production_reachability", "economic_consensus_impact",
    "dedup_oos_awareness", "executable_falsification",
)


def _inventory(workspace: Path) -> set[str]:
    path = workspace / ".auditooor" / "inscope_units.jsonl"
    if not path.is_file():
        raise ValueError("coverage_inventory_missing")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = {row.get("unit_id") for row in rows if isinstance(row, dict)}
    if not ids or not all(isinstance(value, str) and value for value in ids):
        raise ValueError("coverage_inventory_malformed")
    return ids


def append_coverage(workspace: Path, ledger: Path, step_id: str, units: list[str], refs: list[str]) -> dict:
    workspace, ledger = workspace.resolve(), ledger.resolve()
    if ledger.parent != (workspace / ".auditooor").resolve() or not ledger.is_file():
        raise ValueError("coverage_ledger_not_workspace_local")
    if not units or len(units) != len(set(units)) or not refs or any(not item.strip() for item in refs):
        raise ValueError("coverage_inputs_invalid")
    unknown = sorted(set(units) - _inventory(workspace))
    if unknown:
        raise ValueError(f"coverage_unknown_inventory_unit:{unknown[0]}")
    rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    if any(isinstance(row, dict) and row.get("schema") == SCHEMA for row in rows):
        raise ValueError("coverage_duplicate_record")
    receipt = {
        "schema": SCHEMA, "reasoner_step_id": step_id, "producer_step_id": step_id,
        "source_grounded_explanation": "Explicit applicable units examined across every Q0-Q8 axis.",
        "source_refs": sorted(set(refs)), "applicable_inventory_unit_ids": sorted(units),
        "examined_inventory_unit_ids": sorted(units), "examined_axes": list(AXES),
    }
    ledger.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in [*rows, receipt]), encoding="utf-8")
    return receipt


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", required=True); p.add_argument("--ledger", required=True)
    p.add_argument("--step-id", required=True); p.add_argument("--unit-id", action="append", required=True)
    p.add_argument("--source-ref", action="append", required=True)
    ns = p.parse_args()
    print(json.dumps(append_coverage(Path(ns.workspace), Path(ns.ledger), ns.step_id, ns.unit_id, ns.source_ref), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
