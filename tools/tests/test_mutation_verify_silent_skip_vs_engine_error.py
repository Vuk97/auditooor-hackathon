#!/usr/bin/env python3
"""Guard test for the SILENT-SKIP vs ENGINE-ERROR disambiguation in
tools/mutation-verify-coverage.py.

THE FUNNEL BUG (critical) this file pins against
------------------------------------------------
The genuine-coverage / mutation-verify harness runner classified ANY harness
that exited 0 without a recognizable per-test PASS/FAIL line as
verdict="error" ("harness exited 0 but produced no recognizable pass/fail
output").  That shape is EXACTLY what a real Halmos / property harness emits
when it ran successfully and found NO counterexample (silent skip).  So every
such genuine harness collapsed to error -> mutation_verified_genuine=0 ->
DEEP_AUDIT_HOLLOW on beanstalk / mezo / morpho-midnight, even when the
harnesses were real.

THE HONEST FIX (what this test enforces)
----------------------------------------
A silent exit-0 baseline is AMBIGUOUS and must be resolved by the mutation
loop, NOT short-circuited to error:

  A. silent baseline that KILLS a mutant  -> "non-vacuous"
     (the clean exit-0 was a genuine no-counterexample PASS; the kill proves
      the harness is function-sensitive = real coverage).
  B. silent baseline that NEVER flips     -> "no-property-discovered"
     (a TYPED SKIP: the harness discovered no property over the function;
      NOT credited as coverage, but NOT an engine error either).
  C. non-zero exit                         -> "no-baseline" (engine error).
  D. exit 0 WITH a compile-error token     -> "no-baseline" (build failure;
     a harness that never compiled can NEVER be credited).
  E. genuine [PASS] baseline that flips    -> "non-vacuous" (unchanged).
  F. genuine [PASS] baseline that survives -> "vacuous"     (unchanged).

CRITICAL no-false-green property (asserted directly below): the ONLY way this
tool ever emits a credited verdict ("non-vacuous") is a real mutant KILL - the
harness output literally FLIPS from non-failing to failing when a bug is
injected.  A silent skip, a build failure, and a hollow always-pass harness
can NEVER reach "non-vacuous".  So the fix turns a LYING tool (real coverage
mislabeled error) honest; it cannot manufacture credit that was not earned.
"""
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "mutation-verify-coverage.py"

_spec = importlib.util.spec_from_file_location("mvc_silent_vs_error", str(_TOOL))
mvc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mvc)


# A minimal Solidity source with a mutable arithmetic operator in `add`.
_SOL_SRC = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
contract Calc {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}
"""


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mvc_ssve_"))
        self.src = self.tmp / "src" / "Calc.sol"
        self.src.parent.mkdir(parents=True)
        self.src.write_text(_SOL_SRC, encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        # Belt-and-braces: the tool restores the source itself, but assert it.
        # (The dir is already gone; this is a no-op safety note.)

    def _write_runner(self, body: str) -> Path:
        p = self.tmp / "run.sh"
        p.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        p.chmod(0o755)
        return p

    def _verify(self, runner: Path) -> dict:
        return mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            runner_cmd=[str(runner)],
            harness=None,
            runner_cwd=self.tmp,
            classes=["arithmetic"],
            max_mutants=3,
            timeout=20,
        )


class TestSilentSkipVsEngineError(_Base):

    # ------------------------------------------------------------------
    # CASE A (the bug): a REAL harness whose clean-code run is a silent
    # halmos-no-counterexample (exit 0, no per-test line) but which FLIPS to a
    # counterexample when a mutant is injected. Must be credited: "non-vacuous".
    # ------------------------------------------------------------------
    def test_silent_baseline_that_kills_is_non_vacuous(self):
        # On clean code (`a + b` present) emit nothing and exit 0 (silent
        # no-counterexample). On a mutant (the `+` operator changed) print a
        # counterexample and exit 0 - exactly the halmos shape.
        runner = self._write_runner(
            f'SRC="{self.src}"\n'
            'if grep -q "a + b" "$SRC"; then\n'
            '  exit 0\n'
            'else\n'
            '  echo "Counterexample:"\n'
            '  exit 0\n'
            'fi\n'
        )
        rec = self._verify(runner)
        self.assertEqual(
            rec["verdict"], "non-vacuous",
            f"A real silent-baseline harness that kills a mutant must be "
            f"credited non-vacuous; got {rec['verdict']!r} reason={rec.get('reason')!r}",
        )
        self.assertTrue(rec.get("silent_baseline") is True)
        self.assertGreaterEqual(int(rec.get("killed_count") or 0), 1)

    # ------------------------------------------------------------------
    # CASE B (negative): a silent stub that exits 0 and NEVER flips on any
    # mutant. This is NOT a real oracle - but it is NOT an engine error either.
    # Must be a TYPED SKIP "no-property-discovered", never a credit.
    # ------------------------------------------------------------------
    def test_silent_stub_that_never_flips_is_typed_skip(self):
        runner = self._write_runner("exit 0\n")
        rec = self._verify(runner)
        self.assertEqual(
            rec["verdict"], "no-property-discovered",
            f"A silent stub that never flips must be a typed skip; got "
            f"{rec['verdict']!r} reason={rec.get('reason')!r}",
        )
        # NEVER credited as coverage.
        self.assertNotIn(rec["verdict"], ("non-vacuous", "killed", "pass", "vacuous"))
        self.assertEqual(int(rec.get("killed_count") or 0), 0)

    # ------------------------------------------------------------------
    # CASE C (negative): a non-zero exit on the baseline is a genuine engine
    # error and must STAY no-baseline (never enters the mutation loop, never
    # credited). It must NOT become "no-property-discovered" (a skip would let
    # a crashing engine masquerade as "ran but found nothing").
    # ------------------------------------------------------------------
    def test_nonzero_exit_baseline_stays_no_baseline(self):
        runner = self._write_runner('echo "engine blew up"\nexit 3\n')
        rec = self._verify(runner)
        self.assertEqual(
            rec["verdict"], "no-baseline",
            f"A non-zero baseline exit must stay no-baseline; got "
            f"{rec['verdict']!r} reason={rec.get('reason')!r}",
        )
        self.assertEqual(rec["baseline"]["status"], "error")
        # mutation loop must NOT have run.
        self.assertNotIn("killed_count", rec)

    # ------------------------------------------------------------------
    # CASE D (negative, the critical "never credit code that did not build"):
    # a harness that exits 0 but whose output carries a COMPILE-ERROR token
    # (crytic-compile / out/build-info missing) is a build failure, not a real
    # no-counterexample run. Must STAY no-baseline (never enters the loop).
    # ------------------------------------------------------------------
    def test_compile_error_on_exit0_stays_no_baseline(self):
        for token_line in (
            'echo "crytic-compile: compilation failed: out/build-info not found"',
            'echo "error[E0277]: the trait bound is not satisfied"',
            'echo "Error: ParserError: Expected pragma, import or contract"',
            'echo "could not compile \\`harness\\` due to previous error"',
        ):
            with self.subTest(token_line=token_line):
                runner = self._write_runner(token_line + "\nexit 0\n")
                rec = self._verify(runner)
                self.assertEqual(
                    rec["verdict"], "no-baseline",
                    f"A compile-error baseline (even on exit 0) must stay "
                    f"no-baseline; got {rec['verdict']!r} for {token_line!r}",
                )
                self.assertEqual(rec["baseline"]["status"], "error")
                self.assertNotIn("killed_count", rec)

    # ------------------------------------------------------------------
    # CASE E (control): a genuine [PASS] baseline that flips on a mutant stays
    # "non-vacuous" (regression guard for the pre-existing happy path).
    # ------------------------------------------------------------------
    def test_pass_token_baseline_that_kills_is_non_vacuous(self):
        runner = self._write_runner(
            f'SRC="{self.src}"\n'
            'if grep -q "a + b" "$SRC"; then\n'
            '  echo "[PASS] test result: ok"\n'
            '  exit 0\n'
            'else\n'
            '  echo "[FAIL] assertion failed"\n'
            '  exit 1\n'
            'fi\n'
        )
        rec = self._verify(runner)
        self.assertEqual(rec["verdict"], "non-vacuous", rec.get("reason"))
        self.assertFalse(rec.get("silent_baseline"))
        self.assertGreaterEqual(int(rec.get("killed_count") or 0), 1)

    # ------------------------------------------------------------------
    # CASE F (control): a genuine [PASS] baseline that SURVIVES every mutant
    # (a hollow always-pass harness) stays "vacuous" - it ran but checks
    # nothing. Must NOT be a typed skip (it is a proven-hollow executed run).
    # ------------------------------------------------------------------
    def test_pass_token_baseline_that_survives_is_vacuous(self):
        runner = self._write_runner('echo "[PASS] test result: ok"\nexit 0\n')
        rec = self._verify(runner)
        self.assertEqual(
            rec["verdict"], "vacuous",
            f"A [PASS] baseline surviving all mutants is vacuous, not a skip; "
            f"got {rec['verdict']!r} reason={rec.get('reason')!r}",
        )
        self.assertNotIn(rec["verdict"], ("non-vacuous", "killed", "no-property-discovered"))

    # ------------------------------------------------------------------
    # NO-FALSE-GREEN invariant (the load-bearing safety property): across every
    # runner shape, "non-vacuous" (the ONLY credited verdict) is returned IFF a
    # real mutant kill happened. A silent skip, a build failure, and a hollow
    # always-pass harness can never reach it.
    # ------------------------------------------------------------------
    def test_non_vacuous_implies_a_real_kill(self):
        shapes = {
            "silent_kill": (
                f'SRC="{self.src}"\n'
                'if grep -q "a + b" "$SRC"; then exit 0; '
                'else echo "Counterexample:"; exit 0; fi\n'
            ),
            "silent_stub": "exit 0\n",
            "nonzero": 'echo x\nexit 3\n',
            "compile_fail": 'echo "crytic-compile: compilation failed"\nexit 0\n',
            "pass_survive": 'echo "[PASS] test result: ok"\nexit 0\n',
        }
        for name, body in shapes.items():
            with self.subTest(shape=name):
                runner = self._write_runner(body)
                rec = self._verify(runner)
                if rec["verdict"] == "non-vacuous":
                    self.assertGreaterEqual(
                        int(rec.get("killed_count") or 0), 1,
                        f"shape {name!r} reached non-vacuous WITHOUT a real kill "
                        f"- that is a false green. reason={rec.get('reason')!r}",
                    )

    # ------------------------------------------------------------------
    # The fix must NOT touch the byte content of the source after a run
    # (restoration guard regression check, on the kill path).
    # ------------------------------------------------------------------
    def test_source_is_restored_after_run(self):
        before = self.src.read_text(encoding="utf-8")
        runner = self._write_runner(
            f'SRC="{self.src}"\n'
            'if grep -q "a + b" "$SRC"; then exit 0; '
            'else echo "Counterexample:"; exit 0; fi\n'
        )
        self._verify(runner)
        after = self.src.read_text(encoding="utf-8")
        self.assertEqual(before, after, "source file was not restored after run")


if __name__ == "__main__":
    unittest.main()
