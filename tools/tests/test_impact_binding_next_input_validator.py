from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-binding-next-input-validator.py"


def _import():
    spec = importlib.util.spec_from_file_location("impact_binding_next_input_validator_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class ImpactBindingNextInputValidatorTests(unittest.TestCase):
    def test_splits_missing_binding_requirements_into_ordered_units(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-access-control-01"
            requirements = ws / ".auditooor" / "impact_contract_binding_requirements.json"
            _write_json(
                requirements,
                {
                    "rows": [
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": "impact-contract-1",
                            "route_family": "access_control",
                            "tier": "Critical",
                            "missing_requirements": [
                                "project_specific_harness_execution",
                                "candidate_bound_project_source_citation",
                                "proved_exploit_impact_execution_manifest",
                            ],
                            "requirement_statuses": [
                                {
                                    "artifact": "candidate_bound_project_source_citation",
                                    "status": "missing",
                                    "review_decision": "terminal_no_candidate_bound_project_source",
                                },
                                {
                                    "artifact": "project_specific_harness_execution",
                                    "status": "missing",
                                    "missing_requirements": ["target_project_binding", "bounded_input_fixture_json"],
                                },
                                {
                                    "artifact": "proved_exploit_impact_execution_manifest",
                                    "status": "missing",
                                    "manifest_paths": [str(ws / "poc_execution" / candidate / "execution_manifest.json")],
                                },
                            ],
                        }
                    ]
                },
            )

            payload = mod.build_payload(ws, input_path=requirements, unit_dir=ws / ".auditooor" / "units")

            self.assertEqual(payload["unit_count"], 3)
            self.assertEqual(payload["summary"]["requirement_counts"]["candidate_bound_project_source_citation"], 1)
            self.assertEqual(payload["summary"]["blocker_class_counts"]["terminal_no_candidate_bound_project_source"], 1)
            self.assertEqual(payload["summary"]["missing_input_counts"]["target_project_binding"], 1)
            self.assertEqual(payload["units"][0]["requirement"], "candidate_bound_project_source_citation")
            self.assertEqual(payload["units"][-1]["requirement"], "proved_exploit_impact_execution_manifest")
            self.assertTrue((ws / ".auditooor" / "units" / "access_control.json").exists())

    def test_classifies_live_production_and_fixture_artifacts_without_promotion(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-high-bridge-finalization-01"
            live_path = ws / ".auditooor" / "live_proof" / f"{candidate}.json"
            fixture_path = ws / "test_fixtures" / candidate / "bounded_input_fixture.json"
            dossier_path = ws / ".auditooor" / "production_path_dossiers" / f"{candidate}.json"
            _write_json(live_path, {"status": "terminal_missing_local_inputs"})
            _write_json(fixture_path, {"status": "neutral_benchmark_fixture"})
            _write_json(dossier_path, {"status": "blocked_missing_project_source"})
            requirements = ws / ".auditooor" / "impact_contract_binding_requirements.json"
            _write_json(
                requirements,
                {
                    "rows": [
                        {
                            "candidate_id": candidate,
                            "route_family": "bridge_finalization",
                            "tier": "High",
                            "missing_requirements": [
                                "production_path_dossier",
                                "paired_live_or_fork_proof",
                                "bounded_project_input_fixture",
                            ],
                            "requirement_statuses": [
                                {"artifact": "production_path_dossier", "status": "missing", "path": str(dossier_path), "dossier_status": "blocked_missing_project_source"},
                                {"artifact": "paired_live_or_fork_proof", "status": "missing", "path": str(live_path), "proof_status": "terminal_missing_local_inputs"},
                                {"artifact": "bounded_project_input_fixture", "status": "missing", "path": str(fixture_path), "fixture_status": "neutral_benchmark_fixture"},
                            ],
                        }
                    ]
                },
            )

            payload = mod.build_payload(ws, input_path=requirements, unit_dir=ws / ".auditooor" / "units")

        classes = {unit["requirement"]: unit["blocker_class"] for unit in payload["units"]}
        self.assertEqual(classes["production_path_dossier"], "terminal_production_path_blocked_missing_project_source")
        self.assertEqual(classes["paired_live_or_fork_proof"], "terminal_live_or_fork_terminal_missing_local_inputs")
        self.assertEqual(classes["bounded_project_input_fixture"], "terminal_bounded_fixture_neutral_benchmark_fixture")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["closure_candidate_count"], 0)

    def test_ready_present_units_are_counted_but_not_promoted(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            requirements = ws / ".auditooor" / "impact_contract_binding_requirements.json"
            _write_json(
                requirements,
                {
                    "rows": [
                        {
                            "candidate_id": "imo-low-resource-consumption-01",
                            "route_family": "resource_consumption",
                            "missing_requirements": ["bounded_project_input_fixture"],
                            "requirement_statuses": [
                                {"artifact": "bounded_project_input_fixture", "status": "present", "fixture_status": "project_bound"}
                            ],
                        }
                    ]
                },
            )

            payload = mod.build_payload(ws, input_path=requirements, unit_dir=ws / ".auditooor" / "units")

        self.assertEqual(payload["ready_unit_count"], 1)
        self.assertEqual(payload["actionable_unit_count"], 0)
        self.assertEqual(payload["units"][0]["blocker_class"], "ready_present")
        self.assertFalse(payload["units"][0]["promotion_allowed"])


if __name__ == "__main__":
    unittest.main()
