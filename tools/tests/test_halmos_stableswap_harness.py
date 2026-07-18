#!/usr/bin/env python3
"""Regression smoke tests for the hermetic Halmos StableSwap fixture."""
from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tools" / "tests" / "fixtures" / "halmos_stableswap_pure"
HARNESS = FIXTURE / "test" / "HalmosStableSwapPureHarness.t.sol"


class HalmosStableSwapHarnessTest(unittest.TestCase):
    def test_harness_avoids_foundry_cheatcodes(self) -> None:
        text = HARNESS.read_text(encoding="utf-8")
        self.assertNotIn("vm.", text)
        self.assertNotIn("copyStorage", text)
        self.assertNotIn("forge-std", text)

    def test_foundry_concrete_smoke_executes(self) -> None:
        if shutil.which("forge") is None:
            self.skipTest("forge is not installed")

        proc = subprocess.run(
            ["forge", "test", "--root", str(FIXTURE), "-vv"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("test_concreteStableSwapPureChecks", proc.stdout)

    def test_halmos_symbolic_checks_execute(self) -> None:
        if shutil.which("halmos") is None:
            self.skipTest("halmos is not installed")

        proc = subprocess.run(
            [
                "halmos",
                "--root",
                str(FIXTURE),
                "--contract",
                "HalmosStableSwapPureHarness",
                "--function",
                "check_",
                "--solver-timeout-assertion",
                "5s",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Symbolic test result: 3 passed", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
