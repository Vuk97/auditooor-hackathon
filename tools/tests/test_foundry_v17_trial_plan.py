#!/usr/bin/env python3
"""Tests for tools/foundry-v17-trial-plan.py."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERSION_TOOL = REPO_ROOT / "tools" / "foundry-version-report.py"
TRIAL_TOOL = REPO_ROOT / "tools" / "foundry-v17-trial-plan.py"


def _fake_bin(directory: Path, name: str, output: str) -> None:
    path = directory / name
    path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n", encoding="utf-8")
    path.chmod(0o755)


class FoundryV17TrialPlanTest(unittest.TestCase):
    def test_generates_planning_artifacts_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            _fake_bin(bin_dir, "forge", "forge Version: 1.5.1-stable")
            _fake_bin(bin_dir, "cast", "cast Version: 1.5.1-stable")
            _fake_bin(bin_dir, "anvil", "anvil Version: 1.5.1-stable")
            ws = root / "ws"
            ws.mkdir()
            (ws / "foundry.toml").write_text(
                """
[profile.default]
evm_version = "cancun"
network = "base"
seed = "0x1234"

[profile.invariants]
seed = "0x1234"
check_interval = 1
""",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            inv_proc = subprocess.run(
                [sys.executable, str(VERSION_TOOL), "--workspace", str(ws)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(inv_proc.returncode, 0, inv_proc.stderr)
            proc = subprocess.run(
                [sys.executable, str(TRIAL_TOOL), "--workspace", str(ws), "--print-json"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads(proc.stdout)
            self.assertEqual(manifest["schema_version"], "auditooor.foundry_v1_7_trial_plan.v1")
            self.assertEqual(manifest["migration_state"], "planned_not_executed")
            self.assertFalse(manifest["upgrade_performed"])
            self.assertFalse(manifest["install_or_upgrade_allowed"])
            self.assertEqual(manifest["target"]["foundry_version"], "v1.7.1")
            self.assertEqual(manifest["readiness_accounting"]["status"], "ready_for_operator_approved_isolated_trial")
            self.assertTrue(manifest["schema_validation"]["valid"])
            self.assertEqual(manifest["schema_validation"]["errors"], [])
            accounting = manifest["checklist_accounting"]
            self.assertEqual(accounting["status"], "planned_not_executed")
            self.assertEqual(accounting["baseline_command_count"], 5)
            self.assertEqual(accounting["target_command_count"], 7)
            self.assertEqual(accounting["delta_classifier_rule_count"], 8)
            self.assertEqual(accounting["normalization_queue_item_count"], 0)
            self.assertEqual(accounting["required_artifact_count"], 6)
            self.assertEqual(accounting["closeout_check_count"], 5)
            self.assertEqual(accounting["concrete_checklist_item_count"], 31)
            self.assertEqual(accounting["blocking_checklist_item_count"], 0)
            auditooor = ws / ".auditooor"
            expected = [
                "foundry_v1_7_trial_manifest.json",
                "foundry_v1_7_trial_manifest.md",
                "foundry_v1_7_comparison_report_template.md",
                "foundry_v1_7_delta_classifier.json",
                "foundry_v1_7_delta_classifier.md",
                "foundry_v1_7_validation_commands.md",
                "foundry_v1_7_config_normalization_queue.json",
                "foundry_v1_7_config_normalization_queue.md",
                "foundry_v1_7_readiness_accounting.json",
                "foundry_v1_7_readiness_accounting.md",
            ]
            for name in expected:
                self.assertTrue((auditooor / name).is_file(), name)
            commands_md = (auditooor / "foundry_v1_7_validation_commands.md").read_text(encoding="utf-8")
            self.assertIn("PATH=<isolated-foundry-v1.7.1-bin>:$PATH forge build", commands_md)
            self.assertIn("exploratory_only_not_submission_proof", commands_md)

    def test_queue_and_readiness_block_on_unpinned_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "foundry.toml").write_text(
                """
[profile.default]
src = "src"

[profile.invariants_fast]
check_interval = 16
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TRIAL_TOOL), "--workspace", str(ws), "--print-json"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads(proc.stdout)
            self.assertEqual(manifest["readiness_accounting"]["status"], "planned_not_ready")
            queue_path = ws / ".auditooor" / "foundry_v1_7_config_normalization_queue.json"
            queue = json.loads(queue_path.read_text(encoding="utf-8"))
            codes = {item["source_warning_code"] for item in queue["items"]}
            self.assertIn("missing_explicit_hardfork", codes)
            self.assertIn("missing_fuzz_seed", codes)
            self.assertIn("check_interval_exploratory_only", codes)
            self.assertGreaterEqual(queue["blocking_item_count"], 3)
            self.assertGreaterEqual(queue["warning_counts"]["missing_explicit_hardfork"], 1)
            self.assertGreaterEqual(queue["blocking_warning_counts"]["missing_fuzz_seed"], 1)
            blocking = [item for item in queue["items"] if item["blocks_final_proof"]]
            self.assertGreaterEqual(len(blocking), 3)
            accounting = manifest["checklist_accounting"]
            self.assertEqual(accounting["normalization_queue_item_count"], queue["item_count"])
            self.assertEqual(accounting["blocking_checklist_item_count"], queue["blocking_item_count"])
            blocker_details = manifest["readiness_accounting"]["blocker_details"]
            self.assertEqual(len(blocker_details), queue["blocking_item_count"])
            self.assertTrue(all(item["id"].startswith("FN17-BLOCKER-") for item in blocker_details))

    def test_no_foundry_toml_gets_named_blocker_item(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                [sys.executable, str(TRIAL_TOOL), "--workspace", str(ws), "--print-json"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            queue = json.loads((ws / ".auditooor" / "foundry_v1_7_config_normalization_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(queue["items"][0]["source_warning_code"], "no_foundry_toml_detected")
            self.assertEqual(queue["items"][0]["status"], "blocked")

    def test_delta_classifier_contains_required_classes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            (ws / "foundry.toml").write_text(
                """
[profile.default]
evm_version = "cancun"
network = "base"
seed = "0x1"
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TRIAL_TOOL), "--workspace", str(ws)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            classifier = json.loads((ws / ".auditooor" / "foundry_v1_7_delta_classifier.json").read_text(encoding="utf-8"))
            classes = {rule["class"] for rule in classifier["rules"]}
            self.assertIn("hardfork_or_network_default_delta", classes)
            self.assertIn("random_seed_or_parallelism_delta", classes)
            self.assertIn("unknown_needs_manual_triage", classes)
            self.assertTrue(all(rule["submission_posture"] != "submission_proof" for rule in classifier["rules"]))


if __name__ == "__main__":
    unittest.main()
