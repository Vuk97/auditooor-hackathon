#!/usr/bin/env python3
"""Tests for tools/foundry-v17-normalization-plan.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_TOOL = REPO_ROOT / "tools" / "foundry-v17-normalization-plan.py"
VERSION_TOOL = REPO_ROOT / "tools" / "foundry-version-report.py"
TRIAL_TOOL = REPO_ROOT / "tools" / "foundry-v17-trial-plan.py"


def _generate_fixture_manifests(root: Path) -> None:
    for ws in [
        root / "vault_good",
        root / "vault_bad",
        root / "fuzz_campaign" / "fixed",
        root / "fuzz_campaign" / "vulnerable",
    ]:
        subprocess.run(
            [sys.executable, str(VERSION_TOOL), "--workspace", str(ws)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        subprocess.run(
            [sys.executable, str(TRIAL_TOOL), "--workspace", str(ws)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )


class FoundryV17NormalizationPlanTest(unittest.TestCase):
    def test_consumes_four_fixture_queues_without_applying_patches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            fixture_root = REPO_ROOT / "tools" / "tests" / "fixtures"
            _generate_fixture_manifests(fixture_root)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(PLAN_TOOL),
                    "--root",
                    str(fixture_root),
                    "--out-dir",
                    str(out_dir),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            plan = json.loads(proc.stdout)
            self.assertEqual(plan["schema_version"], "auditooor.foundry_v1_7_normalization_plan.v1")
            self.assertEqual(plan["status"], "planned_not_executed")
            self.assertFalse(plan["upgrade_performed"])
            self.assertFalse(plan["install_or_upgrade_allowed"])
            self.assertEqual(plan["workspace_count"], 4)
            self.assertEqual(plan["input_manifest_count"], 4)
            self.assertEqual(plan["input_queue_count"], 4)
            self.assertEqual(plan["queue_item_count"], 16)
            self.assertEqual(plan["blocking_queue_item_count"], 8)
            self.assertEqual(plan["patch_suggestion_count"], 16)
            self.assertEqual(plan["validation_command_count"], 40)
            self.assertEqual(plan["concrete_planning_item_count"], 56)
            self.assertEqual(plan["exact_remaining_blocker_count"], 12)
            self.assertEqual(plan["progress_accounting"]["patches_applied"], 0)
            self.assertEqual(plan["progress_accounting"]["forge_commands_executed"], 0)
            self.assertEqual(plan["progress_accounting"]["remaining_operator_patch_decisions"], 16)
            self.assertEqual(plan["progress_accounting"]["remaining_exact_blockers"], 12)
            blockers = plan["exact_remaining_blockers"]
            self.assertEqual(len(blockers), 12)
            self.assertEqual(
                sum(1 for blocker in blockers if blocker["source_warning_code"] == "isolated_trial_not_executed"),
                4,
            )
            self.assertIn("fork_default_drift", plan["risk_counts"])
            self.assertIn("nondeterministic_fuzz_evidence", plan["risk_counts"])
            self.assertIn("hardfork_or_network_default_delta", plan["expected_breakage_counts"])
            self.assertIn("random_seed_or_parallelism_delta", plan["expected_breakage_counts"])
            self.assertTrue((out_dir / "foundry_v1_7_normalization_execution_plan.json").is_file())
            self.assertTrue((out_dir / "foundry_v1_7_normalization_execution_plan.md").is_file())

    def test_patch_suggestions_are_suggestions_with_exact_workspace_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            ws = REPO_ROOT / "tools" / "tests" / "fixtures" / "vault_bad"
            _generate_fixture_manifests(REPO_ROOT / "tools" / "tests" / "fixtures")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(PLAN_TOOL),
                    "--root",
                    str(REPO_ROOT),
                    "--workspace",
                    str(ws),
                    "--out-dir",
                    str(out_dir),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            plan = json.loads((out_dir / "foundry_v1_7_normalization_execution_plan.json").read_text(encoding="utf-8"))
            workspace = plan["workspaces"][0]
            self.assertEqual(workspace["workspace"], str(ws.resolve()))
            self.assertFalse(workspace["fixture_config_edits_allowed"])
            self.assertGreaterEqual(len(workspace["exact_remaining_blockers"]), 1)
            self.assertTrue(
                any(blocker["source_warning_code"] == "isolated_trial_not_executed" for blocker in workspace["exact_remaining_blockers"])
            )
            suggestions = workspace["patch_suggestions"]
            self.assertEqual({item["status"] for item in suggestions}, {"suggested_not_applied"})
            self.assertTrue(all(item["operator_decision_required"] for item in suggestions))
            patches = "\n".join(item["suggested_patch"] for item in suggestions)
            self.assertIn('evm_version = "cancun"', patches)
            self.assertIn('network = "local"', patches)
            self.assertIn('seed = "0x56017"', patches)
            self.assertIn("[profile.invariants]", patches)
            commands = {row["id"]: row["command"] for row in workspace["validation_commands"]}
            self.assertEqual(commands["baseline-forge-build"], f"forge --root {ws.resolve()} build")
            self.assertEqual(commands["baseline-forge-test-seeded"], f"forge --root {ws.resolve()} test --fuzz-seed 0x56017")
            self.assertIn("PATH=<isolated-foundry-v1.7.1-bin>:$PATH forge", commands["target-forge-build"])
            self.assertTrue(all(row["status"] == "planned_not_executed" for row in workspace["validation_commands"]))

    def test_missing_workspace_pair_is_named_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                [
                    sys.executable,
                    str(PLAN_TOOL),
                    "--root",
                    str(REPO_ROOT),
                    "--workspace",
                    str(ws),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("missing manifest/queue", proc.stderr)


if __name__ == "__main__":
    unittest.main()
