"""Tests for cosmos-production-harness-tasks."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cosmos_production_harness_tasks",
    ROOT / "tools" / "cosmos-production-harness-tasks.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)  # type: ignore[union-attr]

PLAN_SPEC = importlib.util.spec_from_file_location(
    "cosmos_production_harness_plan",
    ROOT / "tools" / "cosmos-production-harness-plan.py",
)
planner = importlib.util.module_from_spec(PLAN_SPEC)
PLAN_SPEC.loader.exec_module(planner)  # type: ignore[union-attr]


def _case(go_body: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="cosmos_harness_tasks_"))
    (root / "poc_test.go").write_text(go_body, encoding="utf-8")
    return root


class CosmosProductionHarnessTasksTests(unittest.TestCase):
    def test_blocking_planner_gaps_become_phase_b_tasks(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestWeakProfile() {
    db := dbm.NewMemDB()
    _ = db
}
"""
        )
        plan = planner.build_plan(poc, claim_text="network-level chain halt")
        payload = mod.build_tasks(plan)

        task_ids = [task["source_requirement"] for task in payload["tasks"]]
        self.assertFalse(payload["runtime_proof_claimed"])
        self.assertEqual(payload["source_plan_verdict"], "needs_work")
        self.assertIn("real_db_backend", task_ids)
        self.assertIn("finalize_block_commit", task_ids)
        self.assertIn("restart_behavior", task_ids)
        self.assertIn("multi_validator_if_claimed", task_ids)
        self.assertEqual(payload["summary"]["blocking_gap_count"], len(payload["tasks"]))
        self.assertEqual(payload["next_runtime_tasks"], [])

    def test_ready_plan_emits_runtime_next_steps_without_overclaiming(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestProductionPath() {
    db, _ := dbm.NewGoLevelDB("app", t.TempDir())
    app.FinalizeBlock(req)
    app.Commit()
    db.Close()
    _, _ = dbm.NewGoLevelDB("app", t.TempDir())
}
"""
        )
        plan = planner.build_plan(poc, claim_text="single-validator state-machine proof")
        payload = mod.build_tasks(plan)

        self.assertEqual(payload["source_plan_verdict"], "ready")
        self.assertFalse(payload["runtime_proof_claimed"])
        self.assertEqual(payload["tasks"], [])
        self.assertEqual(payload["summary"]["blocking_gap_count"], 0)
        self.assertEqual(payload["summary"]["next_runtime_task_count"], 2)
        self.assertTrue(
            any("execution transcript" in task["objective"] for task in payload["next_runtime_tasks"])
        )

    def test_markdown_renderer_carries_advisory_boundary(self):
        payload = mod.build_tasks({"schema": "test", "verdict": "ready", "requirements": []})
        rendered = mod._render_markdown(payload)

        self.assertIn("Runtime proof claimed: `false`", rendered)
        self.assertIn("not runtime proof", rendered)

    def test_artifact_bundle_materializes_task_files_and_marker_contract(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestWeakProfile() {
    db := dbm.NewMemDB()
    _ = db
}
"""
        )
        plan = planner.build_plan(poc, claim_text="network-level chain halt")
        payload = mod.build_tasks(plan)
        out_dir = Path(tempfile.mkdtemp(prefix="cosmos_harness_artifacts_"))

        bundle = mod.write_artifact_bundle(payload, out_dir, candidate_id="lead-aa")

        bundle_path = out_dir / "cosmos_production_harness_task_bundle.json"
        packet_path = out_dir / "COSMOS_PRODUCTION_HARNESS_TASKS.md"
        marker_path = out_dir / "runtime_marker_contract.json"
        outline_path = out_dir / "GO_PRODUCTION_HARNESS_OUTLINE.md"
        self.assertTrue(bundle_path.is_file())
        self.assertTrue(packet_path.is_file())
        self.assertTrue(marker_path.is_file())
        self.assertTrue(outline_path.is_file())
        self.assertEqual(bundle["candidate_id"], "lead-aa")
        self.assertFalse(bundle["runtime_proof_claimed"])
        self.assertEqual(bundle["schema"], mod.ARTIFACT_BUNDLE_SCHEMA)
        self.assertEqual(bundle["production_constraints"]["persistent_db_backends"], ["GoLevelDB", "PebbleDB"])
        self.assertIn(mod.NETWORK_RUNTIME_EVENT, bundle["marker_contract"]["required_events"])

        task_files = sorted((out_dir / "tasks").glob("*.json"))
        self.assertGreaterEqual(len(task_files), 4)
        task_payloads = [json.loads(path.read_text(encoding="utf-8")) for path in task_files]
        multival = next(item for item in task_payloads if item["source_requirement"] == "multi_validator_if_claimed")
        self.assertIn("multi_validator_liveness_prompts", multival)
        self.assertTrue(any("validator_count" in item for item in multival["multi_validator_liveness_prompts"]))
        self.assertIn("GoLevelDB or PebbleDB", outline_path.read_text(encoding="utf-8"))

    def test_ready_plan_artifact_bundle_emits_runtime_task_prompt(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestProductionPath() {
    db, _ := dbm.NewGoLevelDB("app", t.TempDir())
    app.FinalizeBlock(req)
    app.Commit()
    db.Close()
    _, _ = dbm.NewGoLevelDB("app", t.TempDir())
}
"""
        )
        plan = planner.build_plan(poc, claim_text="single-validator state-machine proof")
        payload = mod.build_tasks(plan)
        out_dir = Path(tempfile.mkdtemp(prefix="cosmos_harness_runtime_artifacts_"))

        bundle = mod.write_artifact_bundle(payload, out_dir)

        self.assertEqual(bundle["summary"]["blocking_gap_count"], 0)
        self.assertEqual(bundle["summary"]["runtime_task_artifact_count"], 2)
        runtime_tasks = [task for task in bundle["task_artifacts"] if task["task_phase"] == "runtime_execution"]
        self.assertEqual(len(runtime_tasks), 2)
        outline = (out_dir / "GO_PRODUCTION_HARNESS_OUTLINE.md").read_text(encoding="utf-8")
        self.assertIn("--require-runtime-markers", outline)


if __name__ == "__main__":
    unittest.main()
