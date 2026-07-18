from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "execution-manifest-project-replay-bridge.py"


def _import():
    spec = importlib.util.spec_from_file_location("execution_manifest_project_replay_bridge_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _base_bundle(
    ws: Path,
    candidate: str = "imo-critical-resource-consumption-01",
    family: str = "resource_consumption",
) -> None:
    _write_json(
        ws / ".auditooor" / f"execution_manifest_replay_bundle_{family}.json",
        {
            "schema": "auditooor.execution_manifest_replay_bundle.v1",
            "family": family,
            "rows": [
                {
                    "candidate_id": candidate,
                    "accepted_blocked_status": "accepted_blocked_missing_target_project",
                    "replay_command": f"cd {ws} && {ws}/poc-tests/{candidate}/run_harness.sh",
                }
            ],
        },
    )
    run = ws / "poc-tests" / candidate / "run_harness.sh"
    run.parent.mkdir(parents=True)
    run.write_text("#!/usr/bin/env bash\nexit 2\n", encoding="utf-8")
    _write_json(
        ws / "poc-tests" / candidate / "harness_plan.json",
        {"status": "executable_next_step_not_proof"},
    )
    _write_json(
        ws / "test_fixtures" / candidate / "bounded_input_fixture.json",
        {"status": "neutral_fixture_ready_for_project_binding"},
    )


class ExecutionManifestProjectReplayBridgeTests(unittest.TestCase):
    def test_terminalizes_neutral_replay_when_no_project_source_exists(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _base_bundle(ws)
            _write_json(
                ws / ".auditooor" / "impact_proof_source_review_plan.json",
                {
                    "rows": [
                        {
                            "candidate_id": "imo-critical-resource-consumption-01",
                            "decision": "terminal_no_candidate_bound_project_source",
                            "review_candidates": [],
                        }
                    ]
                },
            )
            payload = mod.build_bridge(ws, "resource_consumption")

        self.assertEqual(payload["row_count"], 1)
        self.assertEqual(payload["terminal_missing_project_source_and_setup_count"], 1)
        self.assertEqual(payload["project_binding_possible_count"], 0)
        row = payload["rows"][0]
        self.assertEqual(row["bridge_status"], "terminal_missing_project_source_and_setup")
        self.assertIn("project_source_root", row["missing_requirements"])
        self.assertIn("target_project_binding", row["missing_requirements"])
        self.assertFalse(row["promotion_allowed"])

    def test_marks_binding_possible_only_with_project_source_and_candidate_review(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-resource-consumption-01"
            _base_bundle(ws, candidate)
            source = ws / "src" / "RuntimeLimiter.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract RuntimeLimiter { function check(bytes calldata input) external {} }\n", encoding="utf-8")
            _write_json(
                ws / ".auditooor" / "impact_proof_source_review_plan.json",
                {
                    "rows": [
                        {
                            "candidate_id": candidate,
                            "decision": "candidate_bound_project_source_found",
                            "review_candidates": [
                                {"path": "src/RuntimeLimiter.sol", "line": 1, "project_source": True}
                            ],
                        }
                    ]
                },
            )
            payload = mod.build_bridge(ws, "resource_consumption")

        row = payload["rows"][0]
        self.assertEqual(payload["project_binding_possible_count"], 0)
        self.assertEqual(row["bridge_status"], "terminal_missing_project_source_and_setup")
        self.assertIn("target_project_binding", row["missing_requirements"])
        self.assertIn("proved_execution_manifest", [item["artifact"] for item in row["required_setup_artifacts"]])

    def test_next_commands_are_family_specific_for_non_resource_rows(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            candidate = "imo-critical-availability-dos-01"
            _base_bundle(ws, candidate, family="availability_dos")
            payload = mod.build_bridge(ws, "availability_dos")

        row = payload["rows"][0]
        self.assertEqual(row["family"], "availability_dos")
        self.assertIn("availability|liveness", row["next_local_commands"][0])
        self.assertNotIn("resource|gas|decode", row["next_local_commands"][0])
        descriptions = " ".join(item["description"] for item in row["required_setup_artifacts"])
        self.assertIn("availability/liveness mechanism", descriptions)

    def test_markdown_renders_summary(self) -> None:
        mod = _import()
        payload = {
            "family": "resource_consumption",
            "proof_boundary": "boundary",
            "row_count": 1,
            "terminal_missing_project_source_and_setup_count": 1,
            "project_binding_possible_count": 0,
            "project_source_file_count": 0,
            "promotion_allowed": False,
            "rows": [
                {
                    "candidate_id": "imo-critical-resource-consumption-01",
                    "bridge_status": "terminal_missing_project_source_and_setup",
                    "missing_requirements": ["project_source_root"],
                }
            ],
        }
        md = mod.render_markdown(payload)
        self.assertIn("Project Replay Bridge", md)
        self.assertIn("Terminal missing source/setup", md)
        self.assertIn("project_source_root", md)

    def test_batch_discovers_and_bridges_all_bundle_families(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _base_bundle(ws, "imo-critical-asset-custody-01", family="asset_custody")
            _base_bundle(ws, "imo-critical-signature-replay-01", family="signature_replay")
            families = mod.discover_bundle_families(ws)
            payload = mod.build_batch(ws, families)
            self.assertEqual(families, ["asset_custody", "signature_replay"])
            self.assertEqual(payload["family_count"], 2)
            self.assertEqual(payload["row_count"], 2)
            self.assertEqual(payload["terminal_missing_project_source_and_setup_count"], 2)
            self.assertTrue(
                (ws / ".auditooor" / "execution_manifest_project_replay_bridge_asset_custody.json").exists()
            )


if __name__ == "__main__":
    unittest.main()
