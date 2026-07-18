#!/usr/bin/env python3
"""Tests for tools/foundry-v17-blocker-closure.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CLOSURE_TOOL = REPO_ROOT / "tools" / "foundry-v17-blocker-closure.py"


def _fake_tool(path: Path) -> None:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)


class FoundryV17BlockerClosureTest(unittest.TestCase):
    def _packet_path(self, root: Path) -> Path:
        packet = {
            "schema_version": "auditooor.foundry_v1_7_trial_executor_dry_run.v1",
            "status": "blocked",
            "mode": "dry_run",
            "workspace_count": 1,
            "check_count": 4,
            "blocking_check_count": 2,
            "execution_step_count": 2,
            "forge_commands_executed": 0,
            "target_trials_executed": 0,
            "target_bin": None,
            "workspaces": [
                {
                    "workspace": str(root / "ws"),
                    "manifest_path": "ws/.auditooor/foundry_v1_7_trial_manifest.json",
                    "status": "blocked",
                    "readiness_status": "planned_not_ready",
                    "blocking_check_count": 2,
                    "checks": [
                        {
                            "id": "baseline:baseline-targeted-poc:placeholder-free-if-required",
                            "status": "fail",
                            "severity": "P0",
                            "detail": "Required commands must not contain unresolved placeholders.",
                        },
                        {
                            "id": "target:target-forge-test:seeded-proof-command",
                            "status": "fail",
                            "severity": "P0",
                            "detail": "Required fuzz/test proof commands must be deterministic.",
                        },
                    ],
                    "execution_steps": [
                        {"id": "baseline-targeted-poc", "command": "forge test --match-contract <C>", "required": True},
                        {"id": "target-invariant-fast-exploratory", "command": "forge test", "required": False},
                    ],
                }
            ],
        }
        path = root / "preflight.json"
        path.write_text(json.dumps(packet), encoding="utf-8")
        return path

    def test_classifies_ce_preflight_blockers_without_running_forge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            preflight = self._packet_path(root)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(CLOSURE_TOOL),
                    "--preflight-json",
                    str(preflight),
                    "--out-dir",
                    str(root / "out"),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            json_start = proc.stdout.index("{")
            closure = json.loads(proc.stdout[json_start:])
            self.assertEqual(closure["schema_version"], "auditooor.foundry_v1_7_blocker_closure.v1")
            self.assertEqual(closure["status"], "blocked_operator_actions_required")
            self.assertEqual(closure["blocker_class_counts"]["required_command_placeholder"], 1)
            self.assertEqual(closure["blocker_class_counts"]["missing_deterministic_fuzz_seed"], 1)
            self.assertEqual(closure["ce_packet_summary"]["forge_commands_executed"], 0)
            self.assertEqual(closure["ce_packet_summary"]["target_trials_executed"], 0)
            self.assertEqual(len(closure["completed_items"]), 50)
            self.assertIn("do not run forge build/test", closure["target_bin_readiness"]["operator_decision"])
            self.assertTrue((root / "out" / "foundry_v1_7_blocker_closure.json").is_file())
            self.assertTrue((root / "out" / "foundry_v1_7_blocker_closure.md").is_file())

    def test_target_bin_validation_is_path_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            preflight = self._packet_path(root)
            target_bin = root / "target-bin"
            target_bin.mkdir()
            for tool in ("forge", "cast", "anvil"):
                _fake_tool(target_bin / tool)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(CLOSURE_TOOL),
                    "--preflight-json",
                    str(preflight),
                    "--target-bin",
                    str(target_bin),
                    "--out-dir",
                    str(root / "out"),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            json_start = proc.stdout.index("{")
            closure = json.loads(proc.stdout[json_start:])
            readiness = closure["target_bin_readiness"]
            self.assertEqual(readiness["status"], "path_validated_ready_for_dry_run_preflight")
            self.assertTrue(all(readiness["tool_presence"].values()))
            self.assertEqual(closure["ce_packet_summary"]["target_trials_executed"], 0)
            self.assertIn("Rerun the dry-run executor with this TARGET_BIN", readiness["next_action"])

    def test_target_bin_blocker_names_missing_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            preflight = self._packet_path(root)
            target_bin = root / "target-bin"
            target_bin.mkdir()
            _fake_tool(target_bin / "forge")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(CLOSURE_TOOL),
                    "--preflight-json",
                    str(preflight),
                    "--target-bin",
                    str(target_bin),
                    "--out-dir",
                    str(root / "out"),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            json_start = proc.stdout.index("{")
            closure = json.loads(proc.stdout[json_start:])
            readiness = closure["target_bin_readiness"]
            self.assertEqual(readiness["status"], "blocked_missing_target_tools")
            self.assertEqual(readiness["missing_tools"], ["cast", "anvil"])
            self.assertIn("do not invoke foundryup", readiness["next_action"])


if __name__ == "__main__":
    unittest.main()
