from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO / "tools" / "readme_runbook_steps.json"
VALIDATOR_PATH = REPO / "tools" / "pipeline-manifest-validate.py"
SPEC = importlib.util.spec_from_file_location("readme_runbook_manifest_validator", VALIDATOR_PATH)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class ReadmeRunbookManifestV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.steps = cls.manifest["steps"]
        cls.by_id = {step["step_id"]: step for step in cls.steps}

    def test_production_manifest_is_fully_valid(self) -> None:
        result = VALIDATOR.validate_manifest_file(MANIFEST_PATH)
        self.assertTrue(result["valid"], json.dumps(result, indent=2))
        self.assertEqual(result["error_count"], 0, json.dumps(result, indent=2))

    def test_schema_count_and_load_bearing_rows(self) -> None:
        self.assertEqual(self.manifest["schema"], "auditooor.pipeline_manifest.v2")
        self.assertEqual(self.manifest["expected_step_count"], 69)
        self.assertEqual(len(self.steps), 69)
        self.assertTrue(all(step["required"] is True for step in self.steps))
        self.assertEqual(sorted(step["order_index"] for step in self.steps), list(range(69)))
        self.assertEqual(sorted(step["run_sequence"] for step in self.steps), list(range(69)))

    def test_semantic_phase_order_uses_canonical_sequence(self) -> None:
        for step in self.steps:
            self.assertEqual(step["run_sequence"], step["order_index"], step["step_id"])
        self.assertLess(self.by_id["step-0g"]["run_sequence"], self.by_id["step-1"]["run_sequence"])
        self.assertEqual(
            self.by_id["step-0g"]["execution_target"],
            ["make", "pipeline-intake-coverage-plane", "WS={workspace}"],
        )

    def test_deep_pipeline_is_split_around_reasoning(self) -> None:
        expected = {
            "step-2": "audit-deep-engine-substrates",
            "step-2c": "audit-deep-drive",
            "step-4": "audit-deep-depth-probe",
        }
        for step_id, make_target in expected.items():
            self.assertEqual(self.by_id[step_id]["execution_target"][:2], ["make", make_target])
        self.assertFalse(
            any(step["execution_target"][:2] == ["make", "audit-deep"] for step in self.steps)
        )

    def test_probes_are_explicit_and_language_na_is_deterministic(self) -> None:
        probes = {row["id"]: row for row in self.manifest["applicability_probes"]}
        self.assertNotIn("never", {row["kind"] for row in probes.values()})
        self.assertNotIn("advisory", {row["kind"] for row in probes.values()})
        for step in self.steps:
            self.assertIn(step["applicability_probe"], probes)
            if step.get("language_filter"):
                self.assertEqual(probes[step["applicability_probe"]]["kind"], "language_any")

    def test_targets_and_environment_are_explicit(self) -> None:
        registry = {row["step_id"]: row["argv"] for row in self.manifest["execution_target_registry"]}
        self.assertEqual(set(registry), set(self.by_id))
        for step in self.steps:
            self.assertEqual(step["execution_target"], registry[step["step_id"]])
            self.assertTrue(step["execution_target"])
            self.assertFalse(any("<ws>" in arg for arg in step["execution_target"]))
        environment = self.manifest["environment_passthrough"]
        self.assertEqual(environment, sorted(set(environment)))
        self.assertFalse(any(token in name for name in environment for token in ("API_KEY", "PASSWORD", "SECRET", "TOKEN")))

    def test_artifact_registry_matches_all_step_edges(self) -> None:
        contracts = {row["id"]: row for row in self.manifest["artifact_contracts"]}
        produced = {artifact for step in self.steps for artifact in step["produces"]}
        consumed = {artifact for step in self.steps for artifact in step["consumes"]}
        self.assertEqual(set(contracts), produced | consumed)
        self.assertTrue(any(row["kind"] == "directory" for row in contracts.values()))
        for artifact, row in contracts.items():
            actual_producers = sorted(step["step_id"] for step in self.steps if artifact in step["produces"])
            actual_consumers = sorted(step["step_id"] for step in self.steps if artifact in step["consumes"])
            self.assertEqual(row["producer_step_ids"], actual_producers)
            self.assertEqual(row["consumer_step_ids"], actual_consumers)
            self.assertEqual(row["terminal"], not actual_consumers)

    def test_reasoner_registry_and_routes_are_complete(self) -> None:
        reasoning_ids = {
            step["step_id"]
            for step in self.steps
            if step["phase"] == "reasoning" and step.get("class") != "orchestration"
        }
        registry = {row["step_id"]: row for row in self.manifest["reasoner_registry"]}
        routes = {row["step_id"]: row for row in self.manifest["reasoner_routes"]}
        self.assertEqual(set(registry), reasoning_ids)
        self.assertEqual(set(routes), reasoning_ids)
        required_route_fields = {
            "queue_step_id",
            "question_step_id",
            "proof_step_id",
            "resolution_step_id",
        }
        for step_id in reasoning_ids:
            route = routes[step_id]
            self.assertTrue(required_route_fields.issubset(route))
            self.assertEqual(route["ledger_artifact"], registry[step_id]["ledger_artifact"])
            for field in required_route_fields:
                self.assertIn(route[field], route["consumer_step_ids"])

    def test_legacy_optional_wording_is_not_present_in_steps(self) -> None:
        body = json.dumps(self.steps)
        self.assertNotIn("required=false", body)
        self.assertNotIn("required:false", body)


if __name__ == "__main__":
    unittest.main()
