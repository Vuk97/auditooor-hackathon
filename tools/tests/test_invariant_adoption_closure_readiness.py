from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "invariant-adoption-closure-readiness.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("invariant_adoption_closure_readiness", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["invariant_adoption_closure_readiness"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_current_adoption(ws: Path) -> None:
    _write_json(ws / ".auditooor" / "invariant_discovery_adoption.json", {
        "schema": "auditooor.invariant_discovery_adoption.v1",
        "adopted_to_canonical_invariant_ledger": True,
        "closure_candidate_count": 0,
        "promotion_allowed": False,
        "generated_review": {"unreviewed_missing_count": 0},
        "route_family_units": [
            {"unit_id": "INV-DISC-ASSET-CUSTODY", "review_state": "blocked_no_project_source_roots", "next_commands": ["make project-source-root-readiness WS=<workspace> JSON=1"]},
            {"unit_id": "INV-DISC-NODE-LIVENESS", "review_state": "blocked_runtime_project_evidence_missing", "next_commands": ["make runtime-dlt-execution-evidence WS=<workspace> JSON=1"]},
        ],
    })


class InvariantAdoptionClosureReadinessTests(unittest.TestCase):
    def test_current_adoption_without_fresh_metrics_and_proof_is_exactly_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            _write_current_adoption(ws)
            _write_json(ws / ".auditooor" / "project_source_root_readiness.json", {"ready_count": 0})
            _write_json(ws / ".auditooor" / "execution_manifest_proof_readiness.json", {"rows": []})
            payload = MOD.run(ws)
            self.assertFalse(payload["p0_closure_ready"])
            self.assertIn("fresh_engagement_adoption_metrics_missing_or_below_threshold", payload["blockers"])
            self.assertIn("project_source_roots_missing", payload["blockers"])
            self.assertIn("proved_exploit_impact_execution_manifest_missing", payload["blockers"])
            self.assertTrue((ws / ".auditooor" / "invariant_adoption_closure_readiness.json").is_file())

    def test_hermetic_positive_closes_only_when_fresh_metrics_and_proof_inputs_exist(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            _write_current_adoption(ws)
            _write_json(ws / ".auditooor" / "invariant_adoption_fresh_engagement_metrics.json", {
                "schema": "auditooor.invariant_adoption_fresh_engagement_metrics.v1",
                "rows": [
                    {
                        "engagement_id": f"fresh-{idx}",
                        "adoption_rate": 1.0,
                        "high_critical_route_family_count": 2,
                        "high_critical_route_family_adopted_count": 2,
                        "invariant_ledger_check_passed": True,
                    }
                    for idx in range(3)
                ],
            })
            _write_json(ws / ".auditooor" / "project_source_root_readiness.json", {"ready_count": 1})
            _write_json(ws / ".auditooor" / "impact_binding_source_import_readiness.json", {"line_hit_unit_count": 1})
            _write_json(ws / ".auditooor" / "execution_manifest_proof_readiness.json", {
                "rows": [{"readiness_status": "execution_proof_ready", "proof_ready": True}]
            })
            payload = MOD.run(ws)
            self.assertTrue(payload["p0_closure_ready"])
            self.assertEqual(payload["blockers"], [])
            self.assertEqual(payload["fresh_engagement_metrics"]["valid_fresh_engagement_count"], 3)

    def test_accepts_r134_execution_proof_ready_alias(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            _write_current_adoption(ws)
            _write_json(ws / ".auditooor" / "invariant_adoption_fresh_engagement_metrics.json", {
                "rows": [
                    {
                        "engagement_id": f"fresh-alias-{idx}",
                        "adoption_rate": 1.0,
                        "high_critical_route_family_count": 1,
                        "high_critical_route_family_adopted_count": 1,
                        "invariant_ledger_check_passed": True,
                    }
                    for idx in range(3)
                ],
            })
            _write_json(ws / ".auditooor" / "project_source_root_readiness.json", {"ready_count": 1})
            _write_json(ws / ".auditooor" / "impact_binding_source_import_readiness.json", {"line_hit_unit_count": 1})
            _write_json(ws / ".auditooor" / "execution_manifest_proof_readiness.json", {
                "rows": [{"execution_proof_ready": True}]
            })

            payload = MOD.run(ws)

        self.assertTrue(payload["p0_closure_ready"])
        self.assertEqual(payload["proof_class_evidence"]["proof_ready_execution_manifest_count"], 1)


if __name__ == "__main__":
    unittest.main()
