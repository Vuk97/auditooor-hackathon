#!/usr/bin/env python3
"""Tests for economic invariant fuzzer scaffold generation."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "econ-fuzzer-scaffold.py"


class TestEconFuzzerScaffold(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="econ_fuzzer_"))
        self.ws = self.tmp / "ws"
        self.ws.mkdir(parents=True)
        (self.ws / "economic_hypotheses.md").write_text(
            """# Economic Hypotheses

## Oracle price cycle

- Repeated price update and redemption cycle may break solvency.

## Fee spread loop

- Repeated fee accounting loop may leak value.
""",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_emits_harness_manifest_and_medusa_config(self) -> None:
        proc = subprocess.run(
            ["python3", str(TOOL), "--workspace", str(self.ws), "--json"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.econ_fuzzer_scaffold.v1")
        self.assertGreaterEqual(payload["invariants_count"], 2)
        harness = Path(payload["harness"])
        medusa = Path(payload["medusa_config"])
        manifest = self.ws / ".auditooor" / "econ_fuzzer_scaffold.json"
        self.assertTrue(harness.is_file())
        self.assertTrue(medusa.is_file())
        self.assertTrue(manifest.is_file())
        text = harness.read_text(encoding="utf-8")
        self.assertIn("contract EconomicInvariantFuzz", text)
        self.assertIn("function invariant_econ_oracle_price_cycle", text)
        self.assertIn("address internal targetProtocol;", text)
        self.assertIn("function _action_updateOracle", text)
        self.assertIn("function _action_redeemAgainstOracle", text)
        self.assertIn("function _action_accrueFees", text)
        self.assertIn("Acceptance focus:", text)
        cfg = json.loads(medusa.read_text(encoding="utf-8"))
        self.assertEqual(cfg["targetContracts"], ["EconomicInvariantFuzz"])
        self.assertIn("updateOracle", payload["suggested_handler_actions"])
        self.assertIn("claimFees", payload["suggested_handler_actions"])
        self.assertIn(
            "treat this output as a runnable scaffold, not exploit proof, until target-specific assertions pass",
            payload["acceptance_checklist"],
        )
        oracle_invariant = next(item for item in payload["invariants"] if item["id"] == "econ_oracle_price_cycle")
        self.assertEqual(
            oracle_invariant["suggested_actions"],
            ["updateOracle", "pushPriceShock", "redeemAgainstOracle", "roundTrip", "repeatAction"],
        )
        self.assertIn("assert price-sensitive solvency or redemption bounds", oracle_invariant["acceptance_focus"])


if __name__ == "__main__":
    unittest.main()
