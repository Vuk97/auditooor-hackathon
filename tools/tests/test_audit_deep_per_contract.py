#!/usr/bin/env python3
"""Tests for per-contract audit-deep orchestration planning."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "audit-deep-per-contract.py"


class TestAuditDeepPerContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("python3"):
            raise unittest.SkipTest("python3 not on PATH")
        if not shutil.which("make"):
            raise unittest.SkipTest("make not on PATH")
        if not TOOL.is_file():
            raise unittest.SkipTest(f"{TOOL} not found")

    def setUp(self) -> None:
        self.sandbox = Path(tempfile.mkdtemp(prefix="audit_deep_per_contract_"))
        self.ws = self.sandbox / "audits" / "demo"
        (self.ws / "src").mkdir(parents=True, exist_ok=True)
        (self.ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
        (self.ws / "src" / "Token.sol").write_text("contract Token {}\n", encoding="utf-8")
        (self.ws / "node_modules" / "ignored").mkdir(parents=True, exist_ok=True)
        (self.ws / "node_modules" / "ignored" / "Ignore.sol").write_text(
            "contract Ignore {}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.sandbox, ignore_errors=True)

    def _run(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        merged["HOME"] = str(self.sandbox)
        merged.update(env or {})
        return subprocess.run(
            ["python3", str(TOOL), *args],
            cwd=REPO,
            env=merged,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_discovers_contracts_and_plans_dry_run_by_default(self) -> None:
        proc = self._run("--workspace", str(self.ws), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.audit_deep_per_contract_plan.v1")
        self.assertTrue(payload["dry_run_default"])
        self.assertFalse(payload["live_enabled"])
        self.assertEqual(payload["contracts"], ["src/Token.sol", "src/Vault.sol"])
        self.assertEqual(payload["contracts_discovered"], 2)
        for row in payload["commands"]:
            self.assertTrue(row["dry_run"])
            self.assertFalse(row["live"])
            self.assertIn("make --no-print-directory audit-deep-solidity", row["command"])
            self.assertNotIn("LIVE=1", row["command"])

    def test_live_flag_and_env_flip_plan_to_live(self) -> None:
        proc = self._run("--workspace", str(self.ws), "--json", "--live")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["live_enabled"])
        self.assertTrue(all(row["live"] for row in payload["commands"]))
        self.assertTrue(all("LIVE=1" in row["command"] for row in payload["commands"]))

        env_proc = self._run("--workspace", str(self.ws), "--json", env={"AUDIT_DEEP_LIVE": "1"})
        self.assertEqual(env_proc.returncode, 0, env_proc.stderr)
        env_payload = json.loads(env_proc.stdout)
        self.assertTrue(env_payload["live_enabled"])

    def test_make_target_writes_default_manifest(self) -> None:
        proc = subprocess.run(
            ["make", "audit-deep-per-contract", f"WS={self.ws}"],
            cwd=REPO,
            env={**os.environ, "HOME": str(self.sandbox)},
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        out = self.ws / ".auditooor" / "per_contract_audit_deep_plan.json"
        self.assertTrue(out.is_file())
        payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["contracts_discovered"], 2)


    # --- NEW GUARDING TESTS ---

    def test_excluded_dirs_filter_test_and_certora(self) -> None:
        """Files under test/, certora/, and mocks/ must NOT appear in the plan."""
        # test/ directory at workspace root
        (self.ws / "test").mkdir(parents=True, exist_ok=True)
        (self.ws / "test" / "MockToken.sol").write_text("contract MockToken {}\n", encoding="utf-8")
        # nested certora/ under src/
        (self.ws / "src" / "certora").mkdir(parents=True, exist_ok=True)
        (self.ws / "src" / "certora" / "Harness.sol").write_text("contract Harness {}\n", encoding="utf-8")
        # mocks/ at workspace root
        (self.ws / "mocks").mkdir(parents=True, exist_ok=True)
        (self.ws / "mocks" / "FakeOracle.sol").write_text("contract FakeOracle {}\n", encoding="utf-8")

        proc = self._run("--workspace", str(self.ws), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)

        # Only the two src/ protocol contracts should appear
        self.assertEqual(payload["contracts_discovered"], 2, payload["contracts"])
        contracts = payload["contracts"]
        self.assertIn("src/Token.sol", contracts)
        self.assertIn("src/Vault.sol", contracts)
        self.assertNotIn("test/MockToken.sol", contracts)
        self.assertNotIn("src/certora/Harness.sol", contracts)
        self.assertNotIn("mocks/FakeOracle.sol", contracts)

    def test_contract_name_uses_declaration_not_stem(self) -> None:
        """CONTRACT= in generated command must match the declared name, not the filename stem."""
        # File named differently from the contract declaration inside it
        (self.ws / "src" / "VaultV2Impl.sol").write_text(
            "// SPDX-License-Identifier: MIT\ncontract VaultV2 {}\n",
            encoding="utf-8",
        )
        proc = self._run("--workspace", str(self.ws), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)

        # Find the command for VaultV2Impl.sol
        matching = [row for row in payload["commands"] if row["contract_file"] == "src/VaultV2Impl.sol"]
        self.assertEqual(len(matching), 1, "Expected one command for VaultV2Impl.sol")
        row = matching[0]
        # contract name must be parsed from declaration, not the filename stem
        self.assertEqual(row["contract"], "VaultV2", f"Got stem-based name: {row['contract']}")
        self.assertIn("CONTRACT=VaultV2 ", row["command"])
        # stem should NOT appear as the CONTRACT= value
        self.assertNotIn("CONTRACT=VaultV2Impl ", row["command"])


if __name__ == "__main__":
    unittest.main()
