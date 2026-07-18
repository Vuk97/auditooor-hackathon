from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "invariant-discovery-adoption.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("invariant_discovery_adoption", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["invariant_discovery_adoption"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _workspace(tmp: Path) -> Path:
    ws = tmp / "ws"
    aud = ws / ".auditooor"
    aud.mkdir(parents=True)
    _write_json(aud / "generated_invariants.json", {
        "schema": "auditooor.generated_invariants.v1",
        "generated_count": 1,
        "diff": {
            "missing": [{
                "generated_id": "GEN-1",
                "scope_asset": "README",
                "invariant_family": "scope_seeded",
                "statement": "TODO",
            }]
        },
    })
    _write_json(aud / "invariant_acceptance_ledger.json", {
        "schema": "auditooor.invariant_acceptance_ledger.v1",
        "rows": [{
            "generated_id": "GEN-1",
            "review_state": "killed",
            "reason": "not a protocol invariant",
        }],
    })
    _write_json(aud / "impact_miss_offset_benchmark.json", {
        "schema": "auditooor.impact_miss_offset_benchmark.v1",
        "items": [
            {
                "benchmark_id": "crit-custody-1",
                "tier": "Critical",
                "asset_category": "Smart Contract",
                "expected": {"route_family": "asset_custody"},
                "input": {"impact_text": "Critical custody loss via vault route"},
            },
            {
                "benchmark_id": "high-dlt-1",
                "tier": "High",
                "asset_category": "Blockchain/DLT",
                "expected": {"route_family": "node_liveness"},
                "input": {"impact_text": "High node halt via runtime input"},
            },
            {
                "benchmark_id": "medium-ignored",
                "tier": "Medium",
                "asset_category": "Smart Contract",
                "expected": {"route_family": "oracle_integrity"},
                "input": {"impact_text": "Medium stale oracle"},
            },
        ],
    })
    _write_json(aud / "runtime_dlt_execution_evidence_validator.json", {
        "schema": "auditooor.runtime_dlt_execution_evidence_validator.v1",
        "rows": [{
            "route_family": "node_liveness",
            "status": "terminal_runtime_execution_inputs_missing",
        }],
    })
    _write_json(aud / "project_source_root_readiness.json", {
        "schema": "auditooor.project_source_root_readiness.v1",
        "status": "no_declared_roots",
        "ready_count": 0,
    })
    return ws


class InvariantDiscoveryAdoptionTests(unittest.TestCase):
    def test_builds_high_critical_route_family_review_units(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _workspace(Path(td))
            payload = MOD.run(ws, adopt_ledger=False)
            self.assertEqual(payload["status"], "reduced_invariant_discovery_units_ready")
            self.assertEqual(payload["route_family_unit_count"], 2)
            families = {u["route_family"]: u for u in payload["route_family_units"]}
            self.assertIn("asset_custody", families)
            self.assertIn("node_liveness", families)
            self.assertEqual(families["node_liveness"]["required_engine"], "cargo")
            self.assertIn("runtime_family_execution_evidence_missing", families["node_liveness"]["blockers"])
            self.assertEqual(payload["generated_review"]["unreviewed_missing_count"], 0)
            self.assertTrue((ws / ".auditooor" / "invariant_discovery_review_units" / "INV-DISC-ASSET-CUSTODY.json").is_file())

    def test_adopts_blocked_rows_to_canonical_invariant_ledger(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _workspace(Path(td))
            payload = MOD.run(ws, adopt_ledger=True)
            self.assertEqual(payload["status"], "reduced_adopted_blocker_rows")
            self.assertEqual(payload["ledger_rows_added"], 2)
            ledger = json.loads((ws / ".auditooor" / "invariant_ledger.json").read_text())
            rows = {r["id"]: r for r in ledger["rows"]}
            self.assertEqual(rows["INV-DISC-ASSET-CUSTODY"]["status"], "blocked")
            self.assertEqual(rows["INV-DISC-ASSET-CUSTODY"]["severity"], "Critical")
            self.assertIn("blocker:", " ".join(rows["INV-DISC-ASSET-CUSTODY"]["artifacts"]))
            second = MOD.run(ws, adopt_ledger=True)
            self.assertEqual(second["ledger_rows_added"], 0)
            self.assertEqual(second["ledger_rows_updated"], 2)

    def test_unreviewed_generated_invariant_blocks_status(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _workspace(Path(td))
            (ws / ".auditooor" / "invariant_acceptance_ledger.json").unlink()
            payload = MOD.run(ws, adopt_ledger=False)
            self.assertEqual(payload["status"], "blocked_unreviewed_generated_invariants")
            self.assertEqual(payload["generated_review"]["unreviewed_missing_count"], 1)


if __name__ == "__main__":
    unittest.main()
