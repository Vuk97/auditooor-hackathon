#!/usr/bin/env python3
"""Tests for automatic composition fixture discovery."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "gen-composition-fixtures.py"


class TestGenCompositionFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="composition_fixtures_"))
        self.ws = self.tmp / "ws"
        (self.ws / "src").mkdir(parents=True)
        (self.ws / "src" / "Vault.sol").write_text(
            "contract Vault { function deposit(uint256 amount) external {} function withdraw(uint256 shares) public {} }\n",
            encoding="utf-8",
        )
        (self.ws / "src" / "Router.sol").write_text(
            "contract Router { function multicall(bytes[] calldata data) external {} }\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_discovers_pair_and_generates_harness(self) -> None:
        proc = subprocess.run(
            ["python3", str(TOOL), "--workspace", str(self.ws), "--max-pairs", "1", "--json"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.composition_fixtures.v1")
        self.assertEqual(payload["contracts_discovered"], 2)
        self.assertEqual(payload["contracts_eligible"], 2)
        self.assertEqual(payload["pairs_generated"], 1)
        pair = payload["pairs"][0]
        self.assertEqual(pair["status"], "generated")
        self.assertTrue(Path(pair["contract_list"]).is_file())
        harness = Path(pair["harness"])
        self.assertTrue(harness.is_file())
        text = harness.read_text(encoding="utf-8")
        self.assertIn("CompositionFuzz_", text)
        self.assertIn("act_Router_multicall", text)
        self.assertTrue(all(contract["eligible_for_pairing"] for contract in payload["contracts"]))

    def test_skips_zero_action_contracts_when_selecting_pairs(self) -> None:
        (self.ws / "src" / "Observer.sol").write_text(
            "contract Observer { uint256 public lastSeen; }\n",
            encoding="utf-8",
        )
        proc = subprocess.run(
            ["python3", str(TOOL), "--workspace", str(self.ws), "--max-pairs", "5", "--plan-only", "--json"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["contracts_discovered"], 3)
        self.assertEqual(payload["contracts_eligible"], 2)
        self.assertEqual(len(payload["pairs"]), 1)
        self.assertEqual(payload["pairs"][0]["contracts"], ["Router", "Vault"])
        observer = next(contract for contract in payload["contracts"] if contract["name"] == "Observer")
        self.assertFalse(observer["eligible_for_pairing"])
        self.assertEqual(observer["functions"], [])


if __name__ == "__main__":
    unittest.main()
