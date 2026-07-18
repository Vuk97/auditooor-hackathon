#!/usr/bin/env python3
"""Tests for tools/foundry-version-report.py."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "foundry-version-report.py"


def _fake_bin(directory: Path, name: str, output: str) -> None:
    path = directory / name
    path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n", encoding="utf-8")
    path.chmod(0o755)


class FoundryVersionReportTest(unittest.TestCase):
    def test_prints_and_persists_offline_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            _fake_bin(bin_dir, "forge", "forge Version: 1.5.1-stable\nCommit SHA: b0a9dd9")
            _fake_bin(bin_dir, "cast", "cast Version: 1.5.1-stable")
            _fake_bin(bin_dir, "anvil", "anvil Version: 1.5.1-stable")
            ws = root / "ws"
            ws.mkdir()
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema_version"], "auditooor.foundry_version_inventory.v1")
            self.assertEqual(payload["planned_target"]["foundry_version"], "v1.7.1")
            self.assertFalse(payload["planned_target"]["upgrade_performed"])
            self.assertEqual(payload["current"]["forge"]["version"], "1.5.1-stable")
            self.assertEqual(payload["current"]["forge"]["commit_sha"], "b0a9dd9")
            self.assertFalse(payload["current_matches_planned_target"])
            self.assertIn("forge build", payload["validation_commands"])
            self.assertTrue((ws / ".auditooor" / "foundry_version_inventory.json").is_file())
            md_path = ws / ".auditooor" / "foundry_version_inventory.md"
            self.assertTrue(md_path.is_file())
            self.assertIn("Current matches planned target: `no`", md_path.read_text(encoding="utf-8"))

    def test_missing_tools_are_reported_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            ws.mkdir()
            empty_bin = root / "empty-bin"
            empty_bin.mkdir()
            env = os.environ.copy()
            env["PATH"] = str(empty_bin)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["current"]["forge"]["present"])
            self.assertEqual(payload["current"]["forge"]["error"], "not found on PATH")
            self.assertIsNone(payload["current_matches_planned_target"])
            self.assertEqual(payload["current_version_summary"], {})
            blocker_details = payload["readiness_accounting"]["blocker_details"]
            self.assertTrue(any("Expose the existing `forge` binary on PATH" in row["next_action"] for row in blocker_details))
            md = (ws / ".auditooor" / "foundry_version_inventory.md").read_text(encoding="utf-8")
            self.assertIn("## Workflow Blockers", md)
            self.assertIn("Expose the existing `forge` binary on PATH", md)

    def test_reports_when_current_tools_match_planned_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            _fake_bin(bin_dir, "forge", "forge Version: 1.7.1-stable")
            _fake_bin(bin_dir, "cast", "cast Version: v1.7.1")
            _fake_bin(bin_dir, "anvil", "anvil Version: 1.7.1")
            ws = root / "ws"
            ws.mkdir()
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["current_matches_planned_target"])
            md = (ws / ".auditooor" / "foundry_version_inventory.md").read_text(encoding="utf-8")
            self.assertIn("Status: planned_not_executed; no install or upgrade was performed.", md)
            self.assertIn("Current matches planned target: `yes`", md)

    def test_normalizes_modern_foundry_release_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            _fake_bin(
                bin_dir,
                "forge",
                "forge Version: 1.3.4-v1.3.4\nCommit SHA: fd677c899b643cf3f3abd2c7905a6e0ca2598c0c\nBuild Timestamp: 2025-09-03T11:39:53.680729000Z",
            )
            _fake_bin(bin_dir, "cast", "cast Version: v1.3.4")
            _fake_bin(bin_dir, "anvil", "anvil 1.3.4 (fd677c8 2025-09-03T11:39:53Z)")
            ws = root / "ws"
            ws.mkdir()
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["current"]["forge"]["version"], "1.3.4-v1.3.4")
            self.assertEqual(payload["current"]["forge"]["normalized_version"], "1.3.4")
            self.assertEqual(payload["current"]["forge"]["version_family"], "v1.3.4")
            self.assertEqual(payload["current"]["forge"]["release_channel"], "release")
            self.assertEqual(payload["current"]["anvil"]["normalized_version"], "1.3.4")

    def test_config_scan_surfaces_seed_and_hardfork_warnings(self) -> None:
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
src = "src"

[profile.invariants_fast]
check_interval = 10
""",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            scan = payload["config_scan"]
            self.assertEqual(scan["foundry_toml_count"], 1)
            codes = {warning["code"] for warning in scan["warnings"]}
            self.assertIn("missing_explicit_hardfork", codes)
            self.assertIn("missing_fuzz_seed", codes)
            self.assertIn("check_interval_exploratory_only", codes)
            self.assertEqual(payload["readiness_accounting"]["status"], "needs_migration_review")

    def test_config_scan_accepts_pinned_repro_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"
            ws.mkdir()
            (ws / "foundry.toml").write_text(
                """
[profile.default]
evm_version = "cancun"

[profile.fuzz_repro]
seed = "0x1234"
network = "base"

[profile.invariants]
seed = "0x1234"
check_interval = 1
""",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            configs = payload["config_scan"]["configs"]
            self.assertEqual(len(configs), 1)
            self.assertTrue(configs[0]["has_explicit_evm_version"])
            self.assertTrue(configs[0]["has_fuzz_seed"])
            self.assertTrue(configs[0]["has_fuzz_repro_profile"])


if __name__ == "__main__":
    unittest.main()
