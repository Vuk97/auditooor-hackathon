#!/usr/bin/env python3
"""Tests for tools/foundry-v17-trial-executor.py."""
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
EXECUTOR_TOOL = REPO_ROOT / "tools" / "foundry-v17-trial-executor.py"


def _fake_bin(directory: Path, name: str, output: str) -> None:
    path = directory / name
    path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n", encoding="utf-8")
    path.chmod(0o755)


def _ready_foundry_toml() -> str:
    return """
[profile.default]
evm_version = "cancun"
network = "base"
seed = "0x1234"

[profile.invariants]
seed = "0x1234"
check_interval = 1
"""


class FoundryV17TrialExecutorTest(unittest.TestCase):
    def _generate_manifest(self, tmp: str) -> tuple[Path, dict[str, str]]:
        root = Path(tmp)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        _fake_bin(bin_dir, "forge", "forge Version: 1.5.1-stable")
        _fake_bin(bin_dir, "cast", "cast Version: 1.5.1-stable")
        _fake_bin(bin_dir, "anvil", "anvil Version: 1.5.1-stable")
        ws = root / "ws"
        ws.mkdir()
        (ws / "foundry.toml").write_text(_ready_foundry_toml(), encoding="utf-8")
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
        plan_proc = subprocess.run(
            [sys.executable, str(TRIAL_TOOL), "--workspace", str(ws)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        self.assertEqual(plan_proc.returncode, 0, plan_proc.stderr)
        return ws, env

    def test_dry_run_blocks_required_placeholder_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws, env = self._generate_manifest(tmp)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(EXECUTOR_TOOL),
                    "--workspace",
                    str(ws),
                    "--out-dir",
                    str(Path(tmp) / "out"),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            packet = json.loads(proc.stdout)
            self.assertEqual(packet["schema_version"], "auditooor.foundry_v1_7_trial_executor_dry_run.v1")
            self.assertEqual(packet["mode"], "dry_run")
            self.assertEqual(packet["status"], "blocked")
            self.assertEqual(packet["forge_commands_executed"], 0)
            self.assertEqual(packet["target_trials_executed"], 0)
            self.assertGreaterEqual(packet["check_count"], 50)
            failed = {
                check["id"]
                for workspace in packet["workspaces"]
                for check in workspace["checks"]
                if check["status"] == "fail"
            }
            self.assertIn("baseline:baseline-targeted-poc:placeholder-free-if-required", failed)
            self.assertIn("target:target-targeted-poc:placeholder-free-if-required", failed)
            out_json = Path(tmp) / "out" / "foundry_v1_7_trial_executor_dry_run.json"
            out_md = Path(tmp) / "out" / "foundry_v1_7_trial_executor_dry_run.md"
            self.assertTrue(out_json.is_file())
            self.assertTrue(out_md.is_file())
            self.assertIn("Dry-run preflight only", packet["proof_boundary"])

    def test_strict_exit_fails_when_preflight_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws, env = self._generate_manifest(tmp)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(EXECUTOR_TOOL),
                    "--workspace",
                    str(ws),
                    "--out-dir",
                    str(Path(tmp) / "out"),
                    "--strict-exit",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_passes_after_operator_resolves_required_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws, env = self._generate_manifest(tmp)
            manifest_path = ws / ".auditooor" / "foundry_v1_7_trial_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            target_bin = Path(tmp) / "target-bin"
            target_bin.mkdir()
            for tool in ("forge", "cast", "anvil"):
                _fake_bin(target_bin, tool, f"{tool} Version: 1.7.1-stable")
            for section in ("baseline", "target"):
                for command in manifest[section]["commands"]:
                    command["command"] = command["command"].replace("<ws>", str(ws))
                    command["command"] = command["command"].replace("<isolated-foundry-v1.7.1-bin>", str(target_bin))
                    if command["id"] in {"baseline-forge-test", "target-forge-test"}:
                        command["command"] = command["command"].replace("forge test", "forge test --fuzz-seed 0x1234")
                    if "targeted-poc" in command["id"]:
                        command["command"] = command["command"].replace(
                            "<PoCOrRegressionContract>",
                            "RepresentativePoC",
                        ).replace("<seed>", "0x1234")
                    if "InvariantContract" in command["command"]:
                        command["command"] = command["command"].replace("<InvariantContract>", "RepresentativeInvariant")
                    if "brief.md" in command["command"]:
                        command["command"] = command["command"].replace("<brief.md>", str(ws / "brief.md"))
                    if "'<target forge command>'" in command["command"]:
                        command["command"] = command["command"].replace(
                            "'<target forge command>'",
                            "'PATH=/isolated/bin:$PATH forge --root " + str(ws) + " test --fuzz-seed 0x1234'",
                        )
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(EXECUTOR_TOOL),
                    "--workspace",
                    str(ws),
                    "--target-bin",
                    str(target_bin),
                    "--out-dir",
                    str(Path(tmp) / "out"),
                    "--strict-exit",
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            packet = json.loads(proc.stdout)
            self.assertEqual(packet["status"], "pass")
            self.assertEqual(packet["blocking_check_count"], 0)
            self.assertEqual(packet["target_bin"], str(target_bin.resolve()))
            check_ids = {
                check["id"]
                for workspace in packet["workspaces"]
                for check in workspace["checks"]
            }
            self.assertIn("target-bin:forge:present", check_ids)
            self.assertIn("pair:forge-build", check_ids)


if __name__ == "__main__":
    unittest.main()
