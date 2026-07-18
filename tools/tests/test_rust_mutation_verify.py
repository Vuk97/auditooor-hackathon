#!/usr/bin/env python3
"""Guard tests for tools/rust-mutation-verify.py (Rust CUT-mutant kill oracle).

HERMETIC DESIGN
---------------
These tests do NOT require a real Rust/cargo installation. Instead they mock
the cargo binary by setting AUDITOOOR_RUST_CARGO_BIN to a tiny Python stub
that reads the (possibly mutated) Rust source file and decides PASS/FAIL:

  mode='invariant'  - stub checks that the fn body contains the original '+';
                      fails (exit 3) when the arithmetic operator is mutated
                      => kills arithmetic mutants => verdict 'killed'

  mode='vacuous'    - stub always exits 0 with "test result: ok. 1 passed"
                      regardless of source content
                      => survives every mutant => verdict 'survived'

  mode='nobaseline' - stub always fails (exit 3) on clean code
                      => no-baseline verdict

GUARD TESTS (the fail-before / pass-after criterion)
-----------------------------------------------------
BEFORE this tool existed, tools/mutation-verify-coverage.py's Rust arm used
a bare "cargo test --quiet" and had NO per-function targeted kill oracle.
As a result per_function_verified stayed at 0 for Rust workspaces.  The tests
below verify the NEW capability:

  1. test_killed_verdict_when_invariant_stub_catches_mutation
       The invariant stub FAILS when the arithmetic op is mutated.
       => verify() must return verdict='killed' and killed_count>=1.
       FAILS before this tool exists (no targeted runner, verdict would be
       'error' or 'no-baseline' because cargo is not available).

  2. test_survived_verdict_when_vacuous_stub_ignores_mutation
       The vacuous stub always passes regardless of source.
       => verify() must return verdict='survived' and killed_count==0.

  3. test_no_baseline_when_stub_always_fails
       Stub fails on clean code => no_baseline verdict.

  4. test_source_is_restored_after_killed_run
       After a killed run the source file is byte-identical to the original.

  5. test_source_is_restored_after_survived_run
       After a survived run the source file is byte-identical to the original.

  6. test_source_is_restored_when_stub_crashes
       Even when the stub returns a non-zero exit code on baseline, the source
       is untouched.

  7. test_no_mutants_inconclusive
       A fn body with no mutable operators yields verdict='no_mutants'.

  8. test_per_function_entry_shape_for_audit_honesty_gate
       A 'killed' result carries mutation_verified=True, oracle_verdict='non-vacuous',
       killed=True on the first mutant_result entry that was killed; this is
       the shape that _corroborated_genuine_count() in audit-honesty-check.py
       reads to credit per_function_verified.

  9. test_classify_rust_output_patterns
       Unit-test the internal _classify() function directly against real cargo
       output patterns (pass / fail / compiler-error / silent).

 10. test_cli_exit_code_killed
       CLI main() returns 0 for a killed (non-vacuous) result.

 11. test_cli_exit_code_survived
       CLI main() returns 1 for a survived (vacuous) result.

RELATIONSHIP TO EXISTING TESTS
-------------------------------
tools/tests/test_mutation_verify_coverage.py already tests the generic
mutation-verify-coverage.py using Solidity stubs.  THIS file tests the NEW
rust-mutation-verify.py module directly and verifies that mutation-verify-
coverage.py correctly delegates to it for language=rust.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOLS = _HERE.parent

# ---------------------------------------------------------------------------
# Load the module under test.
# ---------------------------------------------------------------------------
def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_RMV = _load_module("rust_mutation_verify", _TOOLS / "rust-mutation-verify.py")
_MVC = _load_module("mutation_verify_coverage", _TOOLS / "mutation-verify-coverage.py")

# ---------------------------------------------------------------------------
# Minimal Rust source with one arithmetic mutation point.
# The function 'add' uses '+' which the arithmetic operator class will flip to '-'.
# ---------------------------------------------------------------------------
_RUST_SRC = """\
// Minimal test fixture for rust-mutation-verify tests.
pub fn add(a: u64, b: u64) -> u64 {
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
    }
}
"""

# A function body with no mutable operators (just a return of a constant).
_RUST_NOMUT_SRC = """\
pub fn answer() -> u64 {
    42
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_answer() {
        assert_eq!(answer(), 42);
    }
}
"""

# ---------------------------------------------------------------------------
# Stub cargo binary helpers.
# ---------------------------------------------------------------------------
def _write_cargo_stub(path: Path, *, mode: str) -> None:
    """Write a tiny fake cargo binary (Python script).

    The stub is invoked as:
        <stub> test --quiet [filter] [-- --exact]

    It receives all cargo arguments but inspects only the source file
    (whose path is passed via the RUST_MUT_SOURCE env var set by the test).

    mode='invariant'  : reads the source file; FAILs if '+' is not in the
                        function body (i.e. mutation applied).
    mode='vacuous'    : always passes regardless of source.
    mode='nobaseline' : always fails.
    """
    bodies = {
        "invariant": (
            "import sys, os, pathlib\n"
            "src_path = os.environ.get('RUST_MUT_SOURCE', '')\n"
            "if not src_path:\n"
            "    print('test result: failed. no source path in RUST_MUT_SOURCE')\n"
            "    sys.exit(1)\n"
            "src = pathlib.Path(src_path).read_text()\n"
            "# Check that the 'add' fn body still has '+' (not mutated to '-').\n"
            "import re\n"
            "m = re.search(r'pub fn add.*?\\{(.*?)\\}', src, re.DOTALL)\n"
            "body = m.group(1).strip() if m else ''\n"
            "ok = ' + ' in body or '+\\n' in body\n"
            "if ok:\n"
            "    print('running 1 test')\n"
            "    print('test tests::test_add ... ok')\n"
            "    print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured')\n"
            "    sys.exit(0)\n"
            "else:\n"
            "    print('running 1 test')\n"
            "    print('test tests::test_add ... FAILED')\n"
            "    print('failures:')\n"
            "    print('  tests::test_add')\n"
            "    print('test result: failed. 0 passed; 1 failed; 0 ignored; 0 measured')\n"
            "    sys.exit(101)\n"
        ),
        "vacuous": (
            "import sys\n"
            "print('running 1 test')\n"
            "print('test tests::test_answer ... ok')\n"
            "print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured')\n"
            "sys.exit(0)\n"
        ),
        "nobaseline": (
            "import sys\n"
            "print('test result: failed. 0 passed; 1 failed; 0 ignored; 0 measured')\n"
            "sys.exit(101)\n"
        ),
    }
    path.write_text(
        f"#!/usr/bin/env python3\n{bodies[mode]}",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _write_stub_wrapper(wrapper_path: Path, stub_path: Path) -> None:
    """Write a thin shell wrapper that invokes the Python stub.

    We need this because AUDITOOOR_RUST_CARGO_BIN expects an executable, and
    some environments may not run plain .py directly without the shebang path.
    The wrapper ensures the stub is found on all platforms.
    """
    wrapper_path.write_text(
        f"#!/bin/sh\n{sys.executable} {stub_path} \"$@\"\n",
        encoding="utf-8",
    )
    wrapper_path.chmod(0o755)


# ---------------------------------------------------------------------------
# Test suite.
# ---------------------------------------------------------------------------
class TestRustMutationVerify(unittest.TestCase):
    """Hermetic guard tests for rust-mutation-verify.py."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rmu_test_"))
        # Rust source file.
        self.src = self.tmp / "src" / "lib.rs"
        self.src.parent.mkdir(parents=True, exist_ok=True)
        self.src.write_text(_RUST_SRC, encoding="utf-8")
        self._orig = _RUST_SRC
        # Cargo stub.
        self.stub_py = self.tmp / "fake_cargo.py"
        self.wrapper = self.tmp / "fake_cargo"
        # Saved env so we can restore after each test.
        self._orig_env_cargo = os.environ.get("AUDITOOOR_RUST_CARGO_BIN")
        self._orig_env_src = os.environ.get("RUST_MUT_SOURCE")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        # Restore env.
        if self._orig_env_cargo is None:
            os.environ.pop("AUDITOOOR_RUST_CARGO_BIN", None)
        else:
            os.environ["AUDITOOOR_RUST_CARGO_BIN"] = self._orig_env_cargo
        if self._orig_env_src is None:
            os.environ.pop("RUST_MUT_SOURCE", None)
        else:
            os.environ["RUST_MUT_SOURCE"] = self._orig_env_src

    def _setup_stub(self, mode: str) -> None:
        _write_cargo_stub(self.stub_py, mode=mode)
        _write_stub_wrapper(self.wrapper, self.stub_py)
        os.environ["AUDITOOOR_RUST_CARGO_BIN"] = str(self.wrapper)
        # The invariant stub needs to know which file to read.
        os.environ["RUST_MUT_SOURCE"] = str(self.src)

    # ------------------------------------------------------------------
    # 1. killed verdict when the invariant stub catches the mutation.
    # ------------------------------------------------------------------
    def test_killed_verdict_when_invariant_stub_catches_mutation(self):
        """KEY guard: run_for_mvc() must return verdict='killed' when the
        test harness fails on an arithmetic mutation.  This is the capability
        that did NOT exist before rust-mutation-verify.py was built."""
        self._setup_stub("invariant")
        rec = _RMV.run_for_mvc(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            test_filter=None,
            classes=["arithmetic"],
            max_mutants=2,
            timeout=30,
        )
        self.assertEqual(
            rec.get("verdict"), "killed",
            f"Expected verdict='killed', got {rec.get('verdict')!r}. "
            f"reason={rec.get('reason')!r} baseline={rec.get('baseline')}",
        )
        self.assertGreaterEqual(rec.get("killed_count", 0), 1)
        # Source must be restored.
        self.assertEqual(self.src.read_text(encoding="utf-8"), self._orig)

    # ------------------------------------------------------------------
    # 2. survived verdict when the vacuous stub ignores the mutation.
    # ------------------------------------------------------------------
    def test_survived_verdict_when_vacuous_stub_ignores_mutation(self):
        """A stub that always passes regardless of source yields 'survived'."""
        self._setup_stub("vacuous")
        rec = _RMV.run_for_mvc(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            test_filter=None,
            classes=["arithmetic"],
            max_mutants=2,
            timeout=30,
        )
        self.assertEqual(
            rec.get("verdict"), "survived",
            f"Expected verdict='survived', got {rec.get('verdict')!r}. "
            f"reason={rec.get('reason')!r}",
        )
        self.assertEqual(rec.get("killed_count", -1), 0)
        self.assertEqual(self.src.read_text(encoding="utf-8"), self._orig)

    # ------------------------------------------------------------------
    # 3. no_baseline when the stub always fails on clean code.
    # ------------------------------------------------------------------
    def test_no_baseline_when_stub_always_fails(self):
        """Stub that fails on clean code -> no_baseline (not a valid oracle)."""
        self._setup_stub("nobaseline")
        rec = _RMV.run_for_mvc(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            test_filter=None,
            classes=["arithmetic"],
            timeout=30,
        )
        self.assertEqual(rec.get("verdict"), "no_baseline", rec.get("reason"))
        self.assertEqual(self.src.read_text(encoding="utf-8"), self._orig)

    # ------------------------------------------------------------------
    # 4. Source is restored byte-identically after a killed run.
    # ------------------------------------------------------------------
    def test_source_is_restored_after_killed_run(self):
        self._setup_stub("invariant")
        _RMV.run_for_mvc(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            test_filter=None,
            classes=["arithmetic"],
            max_mutants=1,
            timeout=30,
        )
        self.assertEqual(self.src.read_text(encoding="utf-8"), self._orig,
                         "Source file must be byte-identical to original after run.")

    # ------------------------------------------------------------------
    # 5. Source is restored after a survived run.
    # ------------------------------------------------------------------
    def test_source_is_restored_after_survived_run(self):
        self._setup_stub("vacuous")
        _RMV.run_for_mvc(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            test_filter=None,
            classes=["arithmetic"],
            max_mutants=1,
            timeout=30,
        )
        self.assertEqual(self.src.read_text(encoding="utf-8"), self._orig)

    # ------------------------------------------------------------------
    # 6. Source is restored even when the stub crashes (no_baseline path).
    # ------------------------------------------------------------------
    def test_source_is_restored_when_stub_crashes(self):
        self._setup_stub("nobaseline")
        _RMV.run_for_mvc(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            test_filter=None,
            classes=["arithmetic"],
            timeout=10,
        )
        self.assertEqual(self.src.read_text(encoding="utf-8"), self._orig)

    # ------------------------------------------------------------------
    # 7. no_mutants for a function body with nothing mutable.
    # ------------------------------------------------------------------
    def test_no_mutants_inconclusive(self):
        nomut = self.tmp / "src" / "nomut.rs"
        nomut.write_text(_RUST_NOMUT_SRC, encoding="utf-8")
        self._setup_stub("vacuous")
        os.environ["RUST_MUT_SOURCE"] = str(nomut)
        rec = _RMV.run_for_mvc(
            workspace=self.tmp,
            source_file=nomut,
            function="answer",
            test_filter=None,
            classes=["arithmetic"],
            timeout=30,
        )
        self.assertEqual(rec.get("verdict"), "no_mutants",
                         f"Expected no_mutants, got {rec.get('verdict')!r}")
        self.assertIn("mutant_results", rec)
        self.assertEqual(rec["mutant_results"], [])

    # ------------------------------------------------------------------
    # 8. 'killed' result carries the shape audit-honesty-check.py reads.
    # ------------------------------------------------------------------
    def test_per_function_entry_shape_for_audit_honesty_gate(self):
        """_corroborated_genuine_count() in audit-honesty-check.py reads:
          mutation_verified==True AND oracle_verdict=='non-vacuous' AND killed==True
        on per_function list entries.  The 'killed' verdict must carry these keys."""
        self._setup_stub("invariant")
        rec = _RMV.run_for_mvc(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            test_filter=None,
            classes=["arithmetic"],
            max_mutants=2,
            timeout=30,
        )
        # Top-level result carries these for audit-honesty-check compatibility.
        self.assertTrue(rec.get("mutation_verified"), "mutation_verified must be True")
        self.assertEqual(rec.get("oracle_verdict"), "non-vacuous")
        # At least one mutant_result entry must be killed=True.
        killed_entries = [m for m in rec.get("mutant_results", []) if m.get("killed")]
        self.assertGreaterEqual(
            len(killed_entries), 1,
            "At least one mutant_result must have killed=True",
        )

    # ------------------------------------------------------------------
    # 9. Unit-test _classify() against real cargo output patterns.
    # ------------------------------------------------------------------
    def test_classify_rust_output_patterns(self):
        cases = [
            # (rc, snippet, expected_status, expected_passed)
            (0,   "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured", "pass", True),
            (101, "test result: failed. 0 passed; 1 failed; 0 ignored; 0 measured", "fail", False),
            (1,   "error: could not compile `mylib` due to previous error", "fail", False),
            (0,   "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored", "no-execution", False),
            (0,   "",  "no-execution", False),
            (101, "thread 'tests::test_add' panicked at 'assertion failed'", "fail", False),
        ]
        for rc, out, exp_status, exp_passed in cases:
            with self.subTest(rc=rc, snippet=out[:40]):
                status, passed = _RMV._classify(rc, out)
                self.assertEqual(status, exp_status,
                                 f"rc={rc} output={out!r}: expected {exp_status!r}")
                self.assertEqual(passed, exp_passed)

    # ------------------------------------------------------------------
    # 10. CLI main() returns exit code 0 for killed (non-vacuous) result.
    # ------------------------------------------------------------------
    def test_cli_exit_code_killed(self):
        self._setup_stub("invariant")
        rc = _RMV.main([
            "--workspace", str(self.tmp),
            "--source", str(self.src),
            "--function", "add",
            "--classes", "arithmetic",
            "--max", "2",
            "--timeout", "30",
        ])
        self.assertEqual(rc, 0, "CLI should return 0 for killed (non-vacuous)")

    # ------------------------------------------------------------------
    # 11. CLI main() returns exit code 1 for survived (vacuous) result.
    # ------------------------------------------------------------------
    def test_cli_exit_code_survived(self):
        self._setup_stub("vacuous")
        rc = _RMV.main([
            "--workspace", str(self.tmp),
            "--source", str(self.src),
            "--function", "add",
            "--classes", "arithmetic",
            "--max", "2",
            "--timeout", "30",
        ])
        self.assertEqual(rc, 1, "CLI should return 1 for survived (vacuous)")


# ---------------------------------------------------------------------------
# Integration test: mutation-verify-coverage.py delegates to rust-mutation-verify.py
# for language=rust when AUDITOOOR_MVC_RUNNER_RUST is NOT set.
# ---------------------------------------------------------------------------
class TestMVCRustDelegation(unittest.TestCase):
    """Verify that mutation-verify-coverage.py's verify() delegates to
    rust-mutation-verify.py for Rust source files."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mvc_rust_test_"))
        self.src = self.tmp / "src" / "lib.rs"
        self.src.parent.mkdir(parents=True, exist_ok=True)
        self.src.write_text(_RUST_SRC, encoding="utf-8")
        self._orig = _RUST_SRC
        self.stub_py = self.tmp / "fake_cargo.py"
        self.wrapper = self.tmp / "fake_cargo"
        # Save env.
        self._saved_cargo = os.environ.get("AUDITOOOR_RUST_CARGO_BIN")
        self._saved_src = os.environ.get("RUST_MUT_SOURCE")
        self._saved_mvc_runner = os.environ.get("AUDITOOOR_MVC_RUNNER_RUST")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        for key, saved in [
            ("AUDITOOOR_RUST_CARGO_BIN", self._saved_cargo),
            ("RUST_MUT_SOURCE", self._saved_src),
            ("AUDITOOOR_MVC_RUNNER_RUST", self._saved_mvc_runner),
        ]:
            if saved is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved

    def _setup_stub(self, mode: str) -> None:
        _write_cargo_stub(self.stub_py, mode=mode)
        _write_stub_wrapper(self.wrapper, self.stub_py)
        os.environ["AUDITOOOR_RUST_CARGO_BIN"] = str(self.wrapper)
        os.environ["RUST_MUT_SOURCE"] = str(self.src)
        os.environ.pop("AUDITOOOR_MVC_RUNNER_RUST", None)

    def test_mvc_delegates_to_rmu_for_rust(self):
        """mutation-verify-coverage.verify() must delegate to run_for_mvc()
        for language=rust, producing a 'killed' verdict when the invariant
        stub is in place.  This is the integration guard: before the wiring
        was added, mvc.verify() would fall through to the generic coarse
        cargo runner and return 'no-baseline' or 'error' (no real cargo)."""
        self._setup_stub("invariant")
        rec = _MVC.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            harness=None,
            language="rust",
            classes=["arithmetic"],
            max_mutants=2,
            timeout=30,
        )
        # The wired result comes from rust-mutation-verify.py.
        # Verdict must be 'killed' (rmu) NOT the generic mvc verdicts.
        self.assertEqual(
            rec.get("verdict"), "killed",
            f"mvc.verify() for rust must delegate to rmu and return 'killed'; "
            f"got {rec.get('verdict')!r}. reason={rec.get('reason')!r}",
        )
        # Schema must be rust-mutation-verify's own schema.
        self.assertEqual(
            rec.get("schema"), "auditooor.rust_mutation_verify.v1",
            f"Delegated result must carry rmu schema; got {rec.get('schema')!r}",
        )
        self.assertEqual(self.src.read_text(encoding="utf-8"), self._orig)


if __name__ == "__main__":
    unittest.main()
