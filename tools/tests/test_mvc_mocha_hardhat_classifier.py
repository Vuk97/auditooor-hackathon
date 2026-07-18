#!/usr/bin/env python3
# r36-rebuttal: bugfix-inventory-claude-20260712 agent_pathspec.json
"""Regression tests for the Mocha / Hardhat idiom in mutation-verify-coverage.py::_classify.

BUG (serving-join gap, 2026-07-12 axelar-sc):
  _classify()'s runner-idiom recognizers knew forge / cargo / medusa / echidna /
  go-test pass/fail idioms but NOT Mocha / Hardhat (`npx hardhat test` / mocha).
  Mocha prints a plain summary block ("N passing" / "M failing") that matches NONE
  of the existing tokens, so a passing Hardhat invariant harness classified
  `no-execution` (silent skip) and a genuine mutant-kill (Mocha "1 failing") was
  misread as a vacuous pass. A Hardhat-only SC lane (axelar-sc ships 3 Hardhat
  repos, no foundry.toml) had to hand-write a run-invariant.sh shim to re-emit
  forge tokens. The fix teaches _classify the Mocha idiom natively.

CASES:
  1. Mocha "4 passing" (NO failing line)            -> ("pass", True)
  2. Mocha "3 passing\n1 failing"                   -> ("fail", False)  (kill)
  3. Hardhat compile error ("Compilation failed")   -> ("error", False) (NOT a false kill)
"""
import importlib.util
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "mutation-verify-coverage.py"
_spec = importlib.util.spec_from_file_location("mutation_verify_coverage_mocha", str(_TOOL))
mvc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mvc)


class TestMochaHardhatClassifier(unittest.TestCase):
    def test_mocha_all_passing_is_pass(self):
        # A real Mocha green run: `npx hardhat test` prints only a "N passing" line.
        out = (
            "\n"
            "  ItsIntegration invariant\n"
            "    OK U-1 balance conservation\n"
            "\n"
            "  4 passing (1s)\n"
        )
        status, passed = mvc._classify(0, out)
        self.assertEqual(status, "pass")
        self.assertTrue(passed)

    def test_mocha_failing_is_fail_kill(self):
        # A mutant flips the invariant: Mocha prints "N passing" then "M failing".
        out = (
            "\n"
            "  ItsIntegration invariant\n"
            "    OK U-1 setup\n"
            "    FAIL U-2 balance conservation\n"
            "\n"
            "  3 passing (1s)\n"
            "  1 failing\n"
            "\n"
            "  1) ItsIntegration invariant U-2 balance conservation:\n"
            "     AssertionError: expected 5 to equal 6\n"
        )
        # rc from `npx hardhat test` is non-zero on failure; the TEXT must decide
        # regardless, so we pass rc=1 (real) - the Mocha FAIL line still wins.
        status, passed = mvc._classify(1, out)
        self.assertEqual(status, "fail")
        self.assertFalse(passed)

    def test_hardhat_compile_error_is_error_not_kill(self):
        # A compile-broken mutant: Hardhat aborts before any test runs. NO Mocha
        # "passing"/"failing" line is printed -> must be `error`, never a false kill.
        out = (
            "Compiling 42 files with 0.8.21\n"
            "\n"
            "Error HH600: Compilation failed\n"
            "solc exited with an error\n"
            "  Error: Compilation failed\n"
        )
        status, passed = mvc._classify(1, out)
        self.assertEqual(status, "error")
        self.assertFalse(passed)


if __name__ == "__main__":
    unittest.main()
