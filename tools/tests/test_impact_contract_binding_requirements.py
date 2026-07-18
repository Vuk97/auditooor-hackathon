from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-contract-binding-requirements.py"


def _import():
    spec = importlib.util.spec_from_file_location("impact_contract_binding_requirements_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class ImpactContractBindingRequirementsTests(unittest.TestCase):
    def test_terminalizes_missing_source_harness_execution_and_live_requirements(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-access-control-01"
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "contracts": [
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": "impact-contract-1",
                            "route_family": "access_control",
                            "tier": "Critical",
                            "listed_impact_proven": False,
                            "required_artifacts": ["source_proof", "negative_authorization_fixture"],
                            "exact_proof_requirements": [
                                "candidate_bound_project_source_citation",
                                "project_specific_harness_execution",
                                "proved_exploit_impact_execution_manifest",
                                "paired_live_or_fork_proof",
                            ],
                        }
                    ]
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_proof_source_review_plan.json",
                {"rows": [{"candidate_id": candidate, "decision": "terminal_no_candidate_bound_project_source"}]},
            )
            _write_json(
                ws / ".auditooor" / "execution_manifest_project_replay_bridge_access_control.json",
                {
                    "schema": "auditooor.execution_manifest_project_replay_bridge.v1",
                    "rows": [
                        {
                            "candidate_id": candidate,
                            "bridge_status": "terminal_missing_project_source_and_setup",
                            "missing_requirements": ["target_project_binding"],
                        }
                    ],
                },
            )
            _write_json(
                ws / "poc_execution" / candidate / "execution_manifest.json",
                {
                    "candidate_id": candidate,
                    "final_result": "blocked_path",
                    "impact_assertion": "not_demonstrated",
                    "evidence_class": "executed_with_manifest",
                },
            )
            payload = mod.build_payload(ws, bundle_dir=ws / ".auditooor" / "bundles")

        self.assertEqual(payload["contract_count"], 1)
        self.assertEqual(payload["closure_candidate_count"], 0)
        row = payload["rows"][0]
        self.assertEqual(row["status"], "terminal_missing_binding_inputs")
        self.assertIn("candidate_bound_project_source_citation", row["missing_requirements"])
        self.assertIn("project_specific_harness_execution", row["missing_requirements"])
        self.assertIn("proved_exploit_impact_execution_manifest", row["missing_requirements"])
        self.assertIn("paired_live_or_fork_proof", row["missing_requirements"])
        self.assertFalse(row["promotion_allowed"])

    def test_closure_candidate_requires_listed_impact_and_proved_execution(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-high-resource-consumption-01"
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "contracts": [
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": "impact-contract-2",
                            "route_family": "resource_consumption",
                            "tier": "High",
                            "listed_impact_proven": True,
                            "exact_proof_requirements": [
                                "candidate_bound_project_source_citation",
                                "project_specific_harness_execution",
                                "proved_exploit_impact_execution_manifest",
                                "bounded_project_input_fixture",
                            ],
                        }
                    ]
                },
            )
            _write_json(
                ws / ".auditooor" / "impact_proof_source_review_plan.json",
                {
                    "rows": [
                        {
                            "candidate_id": candidate,
                            "decision": "candidate_bound_project_source_found",
                            "review_candidates": [{"path": "src/Vault.sol", "line": 7, "project_source": True}],
                        }
                    ]
                },
            )
            _write_json(
                ws / ".auditooor" / "execution_manifest_project_replay_bridge_resource_consumption.json",
                {
                    "schema": "auditooor.execution_manifest_project_replay_bridge.v1",
                    "rows": [
                        {
                            "candidate_id": candidate,
                            "bridge_status": "project_binding_possible_requires_harness_execution",
                            "missing_requirements": [],
                        }
                    ],
                },
            )
            _write_json(
                ws / "poc_execution" / candidate / "execution_manifest.json",
                {
                    "candidate_id": candidate,
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": "0"}],
                },
            )
            _write_json(
                ws / "test_fixtures" / candidate / "bounded_input_fixture.json",
                {"status": "project_bound"},
            )
            payload = mod.build_payload(ws, bundle_dir=ws / ".auditooor" / "bundles")

        row = payload["rows"][0]
        self.assertTrue(row["closure_candidate"])
        self.assertEqual(row["status"], "closure_candidate_ready")
        self.assertEqual(row["missing_requirements"], [])
        self.assertEqual(payload["closure_candidate_count"], 1)

    def test_rejects_proved_manifest_without_strict_execution_evidence(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-high-resource-consumption-02"
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "contracts": [
                        {
                            "candidate_id": candidate,
                            "impact_contract_id": "impact-contract-3",
                            "route_family": "resource_consumption",
                            "tier": "High",
                            "listed_impact_proven": True,
                            "exact_proof_requirements": ["proved_exploit_impact_execution_manifest"],
                        }
                    ]
                },
            )
            cases = [
                (
                    "missing-evidence-class",
                    {
                        "candidate_id": candidate,
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                    },
                ),
                (
                    "unstructured-command",
                    {
                        "candidate_id": candidate,
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                        "commands_attempted": ["forge test --match-test testExploitImpact"],
                    },
                ),
                (
                    "non-passing-command",
                    {
                        "candidate_id": candidate,
                        "final_result": "proved",
                        "impact_assertion": "exploit_impact",
                        "evidence_class": "executed_with_manifest",
                        "commands_attempted": [{"command": "forge test", "status": "fail", "exit_code": 1}],
                    },
                ),
            ]

            for label, manifest in cases:
                with self.subTest(label=label):
                    _write_json(ws / "poc_execution" / candidate / "execution_manifest.json", manifest)
                    payload = mod.build_payload(ws, bundle_dir=ws / ".auditooor" / "bundles")
                    row = payload["rows"][0]
                    self.assertFalse(row["closure_candidate"])
                    self.assertIn("proved_exploit_impact_execution_manifest", row["missing_requirements"])

    def test_writes_family_bundles(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            bundle_dir = ws / ".auditooor" / "family_bundles"
            _write_json(
                ws / ".auditooor" / "impact_contracts.json",
                {
                    "contracts": [
                        {
                            "candidate_id": "imo-medium-oracle-settlement-01",
                            "route_family": "oracle_settlement",
                            "tier": "Medium",
                            "exact_proof_requirements": ["candidate_bound_project_source_citation"],
                        }
                    ]
                },
            )
            payload = mod.build_payload(ws, bundle_dir=bundle_dir)

            self.assertEqual(payload["summary"]["route_family_counts"], {"oracle_settlement": 1})
            self.assertTrue((bundle_dir / "oracle_settlement.json").exists())


if __name__ == "__main__":
    unittest.main()
