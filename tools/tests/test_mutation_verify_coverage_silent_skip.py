#!/usr/bin/env python3
# r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
"""Tests for the silent-skip handling in tools/mutation-verify-coverage.py.

ORIGINAL BUG (false-pass, fixed by an earlier patch):
  _classify() returned ("pass", True) on any rc==0 with no _FAIL_TOKENS - even
  on completely empty output (no _PASS_TOKENS).  A stub that exits 0 silently
  was credited as a valid coverage oracle.

OVER-CORRECTION (the funnel bug this file now pins against):
  The earlier patch made verify() return verdict="error" for ANY silent
  exit-0 baseline.  But a REAL Halmos / property harness that found no
  counterexample ALSO exits 0 with no per-test PASS/FAIL line.  So every such
  genuine harness collapsed to "error", mutation_verified_genuine dropped to
  0, and genuinely-covered workspaces (beanstalk / mezo / morpho-midnight)
  were falsely flagged DEEP_AUDIT_HOLLOW.

CORRECT BEHAVIOUR (current):
  _classify still returns ("no-execution", False) for silent exit-0 (and now
  hard "error" for a non-zero exit OR a compile-error token even on exit 0).
  verify() NO LONGER short-circuits a silent baseline to "error"; it carries
  silent_baseline=True into the mutation loop and lets a kill decide:
    - a mutant flips the harness to a failure  => verdict="non-vacuous"
      (the clean silent exit-0 was a real no-counterexample PASS);
    - no mutant ever flips it                  => verdict="no-property-discovered"
      (a TYPED SKIP - not credited as coverage, but NOT an engine error);
    - a non-zero exit or compile-error token   => verdict="no-baseline"
      (a genuine engine/build failure - never enters the loop, never credited).

TESTS:
  1. test_silent_exit0_yields_typed_skip_not_error:
       Silent stub that never flips => verdict="no-property-discovered"
       (NOT "error", NOT a credit).
  2. test_silent_exit0_not_vacuous_or_nonvacuous:
       Same stub - the verdict must NOT be "vacuous" or "non-vacuous".
  3. test_silent_exit0_reason_mentions_output:
       Typed-skip reason mentions "no recognizable" output.
  4. test_control_pass_token_accepted:
       Control: stub prints "[PASS]" and exits 0 => baseline "pass".
  5. test_classify_no_execution_directly:
       Unit-test _classify(): rc=0 + empty output => "no-execution".
  6. test_classify_pass_token_direct:
       Unit-test _classify(): rc=0 + "[PASS]" => "pass".
  7. test_cli_silent_exit0_returns_exit2:
       CLI path: silent-exit-0 runner => main() returns 2 (not 0 or 1).

  The NEW guard cases (silent-baseline-that-kills => non-vacuous; compile-fail
  stays error; genuine pass stays pass) live in the companion file
  test_mutation_verify_silent_skip_vs_engine_error.py.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "mutation-verify-coverage.py"

# Load the module under test the same way the sibling test file does, so
# Python 3.14 dataclass-import edge-cases are avoided (no bare `import`).
_spec = importlib.util.spec_from_file_location("mutation_verify_coverage_ss", str(_TOOL))
mvc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mvc)


# Minimal Solidity source with one arithmetic mutation point.
_SOL_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
contract Calc {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}
"""


class TestSilentSkipFix(unittest.TestCase):
    """Hermetic tests that do NOT require forge / halmos / cargo / go."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mvc_ss_test_"))
        self.src = self.tmp / "src" / "Calc.sol"
        self.src.parent.mkdir(parents=True)
        self.src.write_text(_SOL_SRC, encoding="utf-8")
        self.stub = self.tmp / "stub.sh"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_stub_silent(self):
        """Stub: exits 0, prints NOTHING - the bug scenario."""
        self.stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.stub.chmod(0o755)

    def _write_stub_pass_token(self):
        """Control stub: prints a recognised pass token then exits 0."""
        self.stub.write_text(
            "#!/bin/sh\necho '[PASS] test result: ok'\nexit 0\n",
            encoding="utf-8",
        )
        self.stub.chmod(0o755)

    def _harness_cmd(self) -> str:
        return str(self.stub)

    # ------------------------------------------------------------------
    # 1. Silent exit-0 must produce verdict="error" (not "vacuous" etc.)
    # ------------------------------------------------------------------
    def test_silent_exit0_yields_typed_skip_not_error(self):
        """A silent-exit-0 stub that never flips on any mutant must produce a
        TYPED SKIP (no-property-discovered), NOT a hard engine error.

        The earlier fix mislabeled this as verdict="error", which collapsed
        every real Halmos no-counterexample run (also exit-0, no per-test line)
        to error, drove mutation_verified_genuine to 0, and falsely flagged
        genuinely-covered workspaces DEEP_AUDIT_HOLLOW. The honest verdict is a
        typed skip: not credited as coverage, but not an engine error either."""
        self._write_stub_silent()
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            runner_cmd=[str(self.stub)],
            harness=None,
            runner_cwd=self.tmp,
            classes=["arithmetic"],
            max_mutants=2,
            timeout=15,
        )
        self.assertEqual(
            rec["verdict"], "no-property-discovered",
            f"Expected verdict='no-property-discovered' for a silent-exit-0 stub "
            f"that never flips, got {rec['verdict']!r}. reason={rec.get('reason')!r}",
        )
        # It must NOT be credited as coverage (the load-bearing safety property).
        self.assertNotIn(rec["verdict"], ("non-vacuous", "killed", "pass"))

    # ------------------------------------------------------------------
    # 2. Verdict must NOT be "vacuous" or "non-vacuous" (old false-pass).
    # ------------------------------------------------------------------
    def test_silent_exit0_not_vacuous_or_nonvacuous(self):
        self._write_stub_silent()
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            runner_cmd=[str(self.stub)],
            harness=None,
            runner_cwd=self.tmp,
            classes=["arithmetic"],
            max_mutants=2,
            timeout=15,
        )
        self.assertNotIn(
            rec["verdict"], ("vacuous", "non-vacuous"),
            f"Silent-exit-0 must not produce vacuous/non-vacuous; got {rec['verdict']!r}",
        )

    # ------------------------------------------------------------------
    # 3. Typed-skip reason must mention recognizable output (the fix's message).
    # ------------------------------------------------------------------
    def test_silent_exit0_reason_mentions_output(self):
        self._write_stub_silent()
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            runner_cmd=[str(self.stub)],
            harness=None,
            runner_cwd=self.tmp,
            classes=["arithmetic"],
            max_mutants=2,
            timeout=15,
        )
        reason = rec.get("reason", "")
        self.assertIn(
            "no recognizable",
            reason,
            f"Expected reason to mention 'no recognizable'; got: {reason!r}",
        )

    # ------------------------------------------------------------------
    # 4. Control: pass-token stub is accepted as a valid baseline oracle.
    #    verify() must proceed past the baseline check (verdict is NOT "error").
    # ------------------------------------------------------------------
    def test_control_pass_token_accepted(self):
        """A stub that prints [PASS] must pass the baseline gate."""
        self._write_stub_pass_token()
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            runner_cmd=[str(self.stub)],
            harness=None,
            runner_cwd=self.tmp,
            classes=["arithmetic"],
            max_mutants=2,
            timeout=15,
        )
        # The stub always exits 0 with [PASS], so baseline passes and mutant
        # runs happen; since the stub never inspects the source it will survive
        # every mutant => vacuous.  What matters: verdict is NOT "error".
        self.assertNotEqual(
            rec["verdict"], "error",
            f"Pass-token stub should not yield 'error'; got {rec['verdict']!r}. "
            f"reason={rec.get('reason')!r}",
        )

    # ------------------------------------------------------------------
    # 5. Unit-test _classify directly: rc=0, no output => "no-execution".
    # ------------------------------------------------------------------
    def test_classify_no_execution_directly(self):
        status, passed = mvc._classify(0, "")
        self.assertEqual(status, "no-execution")
        self.assertFalse(passed)

    def test_classify_no_execution_whitespace_only(self):
        """Whitespace-only output (just newlines) is also silent."""
        status, passed = mvc._classify(0, "\n\n  \n")
        self.assertEqual(status, "no-execution")
        self.assertFalse(passed)

    # ------------------------------------------------------------------
    # 6. Unit-test _classify: rc=0 WITH a pass token => "pass", True.
    # ------------------------------------------------------------------
    def test_classify_pass_token_direct(self):
        for token in mvc._PASS_TOKENS:
            with self.subTest(token=token):
                status, passed = mvc._classify(0, f"some output\n{token}\nmore")
                self.assertEqual(status, "pass", f"token={token!r} should give 'pass'")
                self.assertTrue(passed)

    # ------------------------------------------------------------------
    # 7. _classify: fail token on rc=0 still wins (regression guard).
    # ------------------------------------------------------------------
    def test_classify_fail_token_wins_on_rc0(self):
        for token in mvc._FAIL_TOKENS:
            with self.subTest(token=token):
                status, passed = mvc._classify(0, f"output\n{token}")
                self.assertEqual(status, "fail")
                self.assertFalse(passed)

    # ------------------------------------------------------------------
    # 8. CLI path: silent-exit-0 runner => main() returns exit code 2.
    # ------------------------------------------------------------------
    def test_cli_silent_exit0_returns_exit2(self):
        self._write_stub_silent()
        # Drive via main() directly (avoids subprocess overhead).
        rc = mvc.main([
            "--workspace", str(self.tmp),
            "--source", str(self.src),
            "--function", "add",
            "--harness", self._harness_cmd(),
            "--classes", "arithmetic",
            "--max", "2",
            "--timeout", "15",
        ])
        self.assertEqual(
            rc, 2,
            f"Silent-exit-0 should produce CLI exit code 2 (error), got {rc}",
        )


if __name__ == "__main__":
    unittest.main()
