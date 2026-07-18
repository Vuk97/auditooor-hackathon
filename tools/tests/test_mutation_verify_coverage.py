#!/usr/bin/env python3
"""Tests for tools/mutation-verify-coverage.py (R80/R81 oracle half).

These tests are hermetic: they do NOT require forge / halmos / cargo / go.
Instead they drive the verifier with a literal `--harness` shell command that
is a tiny Python stub. The stub reads the (possibly mutated) source file and
decides PASS/FAIL by a rule we control, so we can deterministically construct
both the VACUOUS (stub ignores the function) and NON-VACUOUS (stub asserts the
function's invariant) scenarios, plus no-baseline and no-mutants.

morpho appears ONLY as an optional integration smoke that is SKIPPED unless
halmos + the morpho-midnight workspace are both present (so the suite stays
green offline / in CI).
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
_spec = importlib.util.spec_from_file_location("mutation_verify_coverage", str(_TOOL))
mvc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mvc)


# A Solidity source whose function `add` has a mutable arithmetic operator.
_SOL_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
contract Calc {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}
"""


def _write_stub(path: Path, *, mode: str) -> None:
    """Write a tiny harness stub.

    mode='invariant' : the stub re-implements add(2,3)==5 by READING the source
                       line and FAILS (exit 3) if the arithmetic op is not '+'.
                       => kills the arithmetic mutant => NON-VACUOUS.
    mode='vacuous'   : the stub ignores the source entirely and always passes.
                       => survives every mutant => VACUOUS.
    mode='nobaseline': the stub always fails (exit 3) => no-baseline.
    """
    body = {
        "invariant": (
            "import sys, re, pathlib\n"
            "src = pathlib.Path(sys.argv[1]).read_text()\n"
            "# crude oracle: the 'add' body must compute a '+'\n"
            "m = re.search(r'return a (.) b;', src)\n"
            "ok = bool(m) and m.group(1) == '+'\n"
            "print('[PASS]' if ok else '[FAIL] counterexample add(2,3) != 5')\n"
            "sys.exit(0 if ok else 3)\n"
        ),
        "vacuous": (
            "import sys\n"
            "print('Symbolic test result: 1 passed; 0 failed')\n"
            "sys.exit(0)\n"
        ),
        "nobaseline": (
            "import sys\n"
            "print('[FAIL] always fails')\n"
            "sys.exit(3)\n"
        ),
    }[mode]
    path.write_text(body, encoding="utf-8")


class TestMutationVerifyCoverage(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mvc_test_"))
        self.src = self.tmp / "src" / "Calc.sol"
        self.src.parent.mkdir(parents=True, exist_ok=True)
        self.src.write_text(_SOL_SRC, encoding="utf-8")
        self.stub = self.tmp / "stub.py"
        self._orig = _SOL_SRC

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _harness_cmd(self) -> str:
        # The stub is passed the source path so it can inspect the mutated body.
        return f"{sys.executable} {self.stub} {self.src}"

    # -- NON-VACUOUS: the invariant stub kills the arithmetic mutant. --------
    def test_non_vacuous_kills_mutant(self):
        _write_stub(self.stub, mode="invariant")
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            harness=self._harness_cmd(),
            classes=["arithmetic"],
            max_mutants=2,
            timeout=30,
        )
        self.assertEqual(rec["verdict"], "non-vacuous", rec.get("reason"))
        self.assertGreaterEqual(rec["killed_count"], 1)
        # source restored byte-identical
        self.assertEqual(self.src.read_text(), self._orig)

    def test_shell_operator_harness_runs_via_shell(self):
        # SSV loop fix 2026-06-23: a literal harness command with SHELL OPERATORS
        # (the canonical genuine-coverage form `cd <root> && forge test ..`) must
        # run through a shell. shlex.split would tokenize it and subprocess (no
        # shell) would exec only `cd` -> exit 0, empty output -> no-execution ->
        # 0/N genuine on every workspace. Wrap the working stub in `cd <tmp> &&
        # <stub>`: it MUST still kill a mutant, proving the full command executed.
        _write_stub(self.stub, mode="invariant")
        shell_cmd = f"cd {self.tmp} && {self._harness_cmd()}"
        rec = mvc.verify(
            workspace=self.tmp, source_file=self.src, function="add",
            harness=shell_cmd, classes=["arithmetic"], max_mutants=2, timeout=30,
        )
        self.assertEqual(rec["verdict"], "non-vacuous", rec.get("reason"))
        self.assertNotEqual(rec.get("baseline", {}).get("status"), "no-execution",
                            "shell-operator harness must execute, not silently cd")

    # -- VACUOUS: the always-pass stub survives every mutant. ----------------
    def test_vacuous_survives_all_mutants(self):
        _write_stub(self.stub, mode="vacuous")
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            harness=self._harness_cmd(),
            classes=["arithmetic"],
            max_mutants=2,
            timeout=30,
        )
        self.assertEqual(rec["verdict"], "vacuous", rec.get("reason"))
        self.assertEqual(rec["killed_count"], 0)
        self.assertEqual(self.src.read_text(), self._orig)

    # -- NO-BASELINE: stub fails clean -> cannot be a coverage oracle. -------
    def test_no_baseline_when_clean_fails(self):
        _write_stub(self.stub, mode="nobaseline")
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            harness=self._harness_cmd(),
            classes=["arithmetic"],
            timeout=30,
        )
        self.assertEqual(rec["verdict"], "no-baseline", rec.get("reason"))
        # no mutant runs happened, source untouched
        self.assertEqual(self.src.read_text(), self._orig)

    # -- NO-MUTANTS: a function with no mutable operators is inconclusive. ----
    def test_no_mutants_is_inconclusive(self):
        # A function body with nothing the chosen class can mutate.
        nomut = self.tmp / "src" / "Empty.sol"
        nomut.write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.13;\n"
            "contract E {\n"
            "    function noop() public pure {\n"
            "        // nothing arithmetic here\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        _write_stub(self.stub, mode="vacuous")  # passes clean
        cmd = f"{sys.executable} {self.stub} {nomut}"
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=nomut,
            function="noop",
            harness=cmd,
            classes=["arithmetic"],
            timeout=30,
        )
        self.assertEqual(rec["verdict"], "no-mutants", rec.get("reason"))

    # -- ERROR: missing source file. ----------------------------------------
    def test_error_missing_source(self):
        _write_stub(self.stub, mode="vacuous")
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.tmp / "src" / "DoesNotExist.sol",
            function="add",
            harness=self._harness_cmd(),
            timeout=30,
        )
        self.assertEqual(rec["verdict"], "error")

    # -- RESTORE ON EXCEPTION: source is restored even if a run raises. -------
    def test_restore_even_on_runner_crash(self):
        # Harness command points at a non-existent interpreter path so _run
        # returns a non-zero/error rather than raising; baseline becomes error
        # -> no-baseline, and source must be untouched.
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            harness="/nonexistent/interp --x",
            classes=["arithmetic"],
            timeout=10,
        )
        self.assertIn(rec["verdict"], ("no-baseline", "error"))
        self.assertEqual(self.src.read_text(), self._orig)

    # -- JSON record is well-formed and seeds an R80 *mutation*.json. --------
    def test_record_is_json_serializable_with_expected_keys(self):
        _write_stub(self.stub, mode="invariant")
        rec = mvc.verify(
            workspace=self.tmp,
            source_file=self.src,
            function="add",
            harness=self._harness_cmd(),
            classes=["arithmetic"],
            max_mutants=1,
            timeout=30,
        )
        s = json.dumps(rec)  # must not raise
        d = json.loads(s)
        for k in ("schema", "verdict", "function", "mutant_count", "baseline"):
            self.assertIn(k, d)
        self.assertEqual(d["schema"], "auditooor.mutation_verify_coverage.v1")

    # -- Case-insensitive _classify guard tests. --------------------------------
    def test_classify_lowercase_failed_is_fail(self):
        """Lowercase 'failed' in harness output must be classified as fail."""
        status, passed = mvc._classify(0, "some output: failed\n")
        self.assertEqual(status, "fail")
        self.assertFalse(passed)

    def test_classify_lowercase_assertion_failed_is_fail(self):
        """Lowercase 'assertion failed' must be classified as fail."""
        status, passed = mvc._classify(0, "assertion failed at line 42\n")
        self.assertEqual(status, "fail")
        self.assertFalse(passed)

    def test_classify_lowercase_bracket_fail_is_fail(self):
        """Lowercase '[fail]' must be classified as fail."""
        status, passed = mvc._classify(0, "[fail] test_foo\n")
        self.assertEqual(status, "fail")
        self.assertFalse(passed)

    def test_classify_uppercase_FAILED_is_fail(self):
        """Uppercase 'FAILED' still classified as fail after lowercasing tokens."""
        status, passed = mvc._classify(0, "FAILED: counterexample found\n")
        self.assertEqual(status, "fail")
        self.assertFalse(passed)

    def test_classify_pass_token_not_misread_as_fail(self):
        """A clean [PASS]/ok output must be classified as pass, not fail."""
        status, passed = mvc._classify(0, "[PASS] all tests passed;\n")
        self.assertEqual(status, "pass")
        self.assertTrue(passed)

    def test_classify_empty_output_is_no_execution(self):
        """Empty output on rc==0 must be classified as no-execution, not fail."""
        status, passed = mvc._classify(0, "")
        self.assertEqual(status, "no-execution")
        self.assertFalse(passed)

    def test_classify_compile_error_is_error(self):
        """Non-zero rc with no recognized fail token is an error, not a kill."""
        status, passed = mvc._classify(1, "build error: missing semicolon\n")
        self.assertEqual(status, "error")
        self.assertFalse(passed)

    # -- CLI exit codes: 0 non-vacuous / 1 vacuous / 2 otherwise. -----------
    def test_cli_exit_codes(self):
        _write_stub(self.stub, mode="vacuous")
        rc = mvc.main([
            "--workspace", str(self.tmp),
            "--source", str(self.src),
            "--function", "add",
            "--harness", self._harness_cmd(),
            "--classes", "arithmetic",
            "--max", "1",
            "--timeout", "30",
        ])
        self.assertEqual(rc, 1)  # vacuous -> exit 1


@unittest.skipUnless(
    shutil.which("halmos")
    and Path("/Users/wolf/audits/morpho-midnight/src/src/Midnight.sol").is_file(),
    "halmos + morpho-midnight required for integration smoke",
)
class TestMorphoVacuousSmoke(unittest.TestCase):
    """OPTIONAL integration smoke: the real morpho `Halmos_IMidnight_multicall`
    `assert(true)` harness is proven VACUOUS against mutants of the real
    Midnight.multicall. Skipped unless halmos + the workspace are present."""

    def test_morpho_multicall_harness_is_vacuous(self):
        mm = Path("/Users/wolf/audits/morpho-midnight")
        work = Path(tempfile.mkdtemp(prefix="mvc_morpho_"))
        try:
            shutil.copytree(mm / "src" / "src", work / "src")
            (work / "test").mkdir()
            harness_src = (mm / "poc-tests" / "per_function_invariants"
                           / "Halmos_IMidnight_multicall.t.sol").read_text()
            harness_src = harness_src.replace(
                "../../src/src/interfaces/IMidnight.sol",
                "../src/interfaces/IMidnight.sol")
            (work / "test" / "Halmos_IMidnight_multicall.t.sol").write_text(harness_src)
            (work / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\ntest = \"test\"\nvia_ir = true\n")
            rec = mvc.verify(
                workspace=work,
                source_file=work / "src" / "Midnight.sol",
                function="multicall",
                harness=str(work / "test" / "Halmos_IMidnight_multicall.t.sol"),
                max_mutants=2,
                timeout=240,
            )
            self.assertEqual(rec["verdict"], "vacuous", rec.get("reason"))
            self.assertEqual(rec["killed_count"], 0)
        finally:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class MedusaOracleTest(unittest.TestCase):
    """medusa exits 0 even on a failing property and its summary
    'N test(s) failed' matches no generic token; the classifier must still read
    it as FAIL (else every medusa mutant-kill is misread as a vacuous pass and
    no medusa invariant can be credited). Real strings from the optimism
    OptimismPortal2 no-double-spend clean + mutant runs."""

    def test_medusa_clean_summary_is_pass(self):
        out = "Test summary: 8 test(s) passed, 0 test(s) failed"
        self.assertEqual(mvc._classify(0, out), ("pass", True))

    def test_medusa_failing_summary_is_fail_despite_exit0(self):
        out = "Test summary: 6 test(s) passed, 1 test(s) failed"
        self.assertEqual(mvc._classify(0, out), ("fail", False))

    def test_medusa_pass_summary_wins_over_stray_failed_substring(self):
        # a benign "failed to ..." substring in verbose medusa logs must NOT
        # override a 10/10-pass summary (the summary is authoritative).
        out = ("INFO: worker failed to dial peer, retrying\n"
               "Test summary: 10 test(s) passed, 0 test(s) failed")
        self.assertEqual(mvc._classify(0, out), ("pass", True))

    def test_medusa_real_failure_wins_over_stray_pass_text(self):
        out = ("some passed; note\nTest summary: 9 test(s) passed, 1 test(s) failed")
        self.assertEqual(mvc._classify(0, out), ("fail", False))

    def test_medusa_pass_with_crytic_compile_noise_is_pass(self):
        # medusa shells out to crytic-compile (in _COMPILE_ERROR_TOKENS) on EVERY
        # run; a successful run's test summary must win over that noise.
        out = "running crytic-compile ...\nTest summary: 8 test(s) passed, 0 test(s) failed"
        self.assertEqual(mvc._classify(0, out), ("pass", True))

    def test_medusa_zero_failed_not_false_fail(self):
        # a bare "0 test(s) failed" must NOT be read as a failure
        status, passed = mvc._classify(0, "ran; 0 test(s) failed")
        self.assertNotEqual(status, "fail")

    # -- echidna per-property oracle (selfdestruct/SafeSend-path contracts) -----
    def test_echidna_passing_property_is_pass(self):
        # echidna's clean verdict line for a held property.
        out = "property_no_double_finalize: passing 🎉\nUnique instructions: 1234"
        self.assertEqual(mvc._classify(0, out), ("pass", True))

    def test_echidna_failed_property_is_fail(self):
        # the mutant-kill shape: echidna falsifies the property.
        out = ("property_no_double_finalize: failed!💥\n"
               "  Call sequence:\n    unlockETH(1)\n")
        self.assertEqual(mvc._classify(1, out), ("fail", False))

    def test_echidna_falsified_legacy_is_fail(self):
        out = "echidna_balance_conservation: falsified after 5000 tests"
        self.assertEqual(mvc._classify(0, out), ("fail", False))

    def test_echidna_mixed_run_with_one_fail_is_fail(self):
        # a fail among passes wins (>=1 falsified property = run fail).
        out = ("property_a: passing 🎉\n"
               "property_b: failed!💥\n")
        self.assertEqual(mvc._classify(0, out), ("fail", False))


class PremadeMutantHarnessTest(unittest.TestCase):
    """Harness-level (pre-made mutant) verification: baseline PASS + mutant FAIL =>
    non-vacuous, WITHOUT mutating the audit-tree source. Uses echo'd medusa-style
    summaries so the test is engine-free + fast."""

    def _run(self, baseline_out, mutant_out):
        ws = Path(tempfile.mkdtemp())
        src = ws / "src" / "Portal.sol"; src.parent.mkdir(parents=True)
        src.write_text("contract P {}\n")
        return mvc.verify_premade_mutant(
            workspace=ws, source_file=src, function="finalize",
            baseline_harness=f"bash -lc 'echo \"{baseline_out}\"'",
            mutant_harness=f"bash -lc 'echo \"{mutant_out}\"'", timeout=30)

    def test_baseline_pass_mutant_fail_is_non_vacuous(self):
        r = self._run("Test summary: 8 test(s) passed, 0 test(s) failed",
                      "Test summary: 6 test(s) passed, 1 test(s) failed")
        self.assertEqual(r["verdict"], "non-vacuous")
        self.assertTrue(r["mutation_verified"])

    def test_mutant_also_passes_is_vacuous(self):
        r = self._run("8 test(s) passed, 0 test(s) failed",
                      "8 test(s) passed, 0 test(s) failed")
        self.assertEqual(r["verdict"], "vacuous")
        self.assertFalse(r["mutation_verified"])

    def test_baseline_fail_is_no_baseline(self):
        r = self._run("2 test(s) passed, 3 test(s) failed",
                      "1 test(s) passed, 1 test(s) failed")
        self.assertEqual(r["verdict"], "no-baseline")


class TestKillKindClassification(unittest.TestCase):
    """P1-a (modes 9, 16): each kill is tagged kill_kind; only a non-panic
    behaviour-changing kill counts toward verdict=non-vacuous. A panic-only
    equivalent-mutant yields verdict=equivalent-mutant-only (not credited)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="killkind_"))
        self.src = self.tmp / "src" / "Calc.sol"
        self.src.parent.mkdir(parents=True, exist_ok=True)
        self.src.write_text(_SOL_SRC, encoding="utf-8")
        self.stub = self.tmp / "stub.py"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cmd(self):
        return f"{sys.executable} {self.stub} {self.src}"

    def test_panic_only_kill_is_equivalent_mutant_only(self):
        # The stub FAILs with a bare EVM Panic(0x11) (no invariant_/property_ frame)
        # iff the '+' op is mutated -> every kill is panic-only -> equivalent-mutant.
        self.stub.write_text(
            "import sys, re, pathlib\n"
            "src = pathlib.Path(sys.argv[1]).read_text()\n"
            "m = re.search(r'return a (.) b;', src)\n"
            "ok = bool(m) and m.group(1) == '+'\n"
            "print('[PASS] ok' if ok else '[FAIL] Panic(uint256) 0x11 arithmetic underflow')\n"
            "sys.exit(0 if ok else 3)\n", encoding="utf-8")
        rec = mvc.verify(
            workspace=self.tmp, source_file=self.src, function="add",
            harness=self._cmd(), classes=["arithmetic"], max_mutants=2, timeout=30)
        self.assertEqual(rec["verdict"], "equivalent-mutant-only", rec.get("reason"))
        self.assertEqual(rec["killed_count"], 0)
        self.assertGreaterEqual(rec["panic_only_kill_count"], 1)
        self.assertTrue(all(m["kill_kind"] != "behavior-changing"
                            for m in rec["mutant_results"]))

    def test_behavior_changing_kill_is_non_vacuous_with_attribution(self):
        # A guard/relational assertion failure naming an invariant_ frame -> the
        # genuine behaviour-changing kill, recorded with per-invariant attribution.
        self.stub.write_text(
            "import sys, re, pathlib\n"
            "src = pathlib.Path(sys.argv[1]).read_text()\n"
            "m = re.search(r'return a (.) b;', src)\n"
            "ok = bool(m) and m.group(1) == '+'\n"
            "print('[PASS] ok' if ok else "
            "'[FAIL] invariant_sum() (runs: 9) assertion violated')\n"
            "sys.exit(0 if ok else 3)\n", encoding="utf-8")
        rec = mvc.verify(
            workspace=self.tmp, source_file=self.src, function="add",
            harness=self._cmd(), classes=["arithmetic"], max_mutants=2, timeout=30)
        self.assertEqual(rec["verdict"], "non-vacuous", rec.get("reason"))
        self.assertGreaterEqual(rec["behavior_changing_kill_count"], 1)
        self.assertIn("invariant_sum", rec["invariant_mutant_attribution"])


class TestManualMvcRegistration(unittest.TestCase):
    """P1-c (mode 11 residual): register_manual_mvc writes a conforming
    .auditooor/mvc_sidecar/*.json for a hand-authored mutant harness."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="manualmvc_"))
        self.harness = self.tmp / "test" / "OmniBridge_MutantVacuity.t.sol"
        self.harness.parent.mkdir(parents=True, exist_ok=True)
        self.harness.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.20;\n"
            "contract OmniBridge_MutantVacuity {\n"
            "    function invariant_no_replay() public {}\n"
            "    function property_conservation() public {}\n}\n",
            encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_register_writes_conforming_sidecar(self):
        rec = mvc.register_manual_mvc(workspace=self.tmp, harness_path=self.harness)
        self.assertEqual(rec["schema"], "auditooor.mutation_verify_coverage.v1")
        self.assertEqual(rec["verdict"], "non-vacuous")
        self.assertTrue(rec["mutation_verified"])
        self.assertTrue(rec["manual_registration"])
        self.assertIn("invariant_no_replay", rec["invariants"])
        # persist + assert the sidecar landed in the dir the gates read.
        written = mvc._persist_durable_sidecar(self.tmp, rec)
        self.assertIsNotNone(written)
        sc = self.tmp / ".auditooor" / "mvc_sidecar"
        self.assertTrue(any(sc.glob("*.json")))
        d = json.loads(next(sc.glob("*.json")).read_text())
        self.assertEqual(d["verdict"], "non-vacuous")
        self.assertIn("harness_source_sha256", d)  # P1-b: hash recorded

    def test_register_missing_harness_is_error(self):
        rec = mvc.register_manual_mvc(
            workspace=self.tmp, harness_path=self.tmp / "nope.t.sol")
        self.assertEqual(rec["verdict"], "error")

    def test_cli_register_manual_mvc(self):
        rc = mvc.main([
            "--workspace", str(self.tmp),
            "--register-manual-mvc", str(self.harness),
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(any((self.tmp / ".auditooor" / "mvc_sidecar").glob("*.json")))


class TestSidecarSourceHashDrift(unittest.TestCase):
    """P1-b (mode 13): a sidecar records harness_source_sha256; a consumer detects
    drift when the on-disk harness was clobbered after the sidecar was banked."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="drift_"))
        self.harness = self.tmp / "H.t.sol"
        self.harness.write_text("contract H { function invariant_x() public {} }\n",
                                encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_fresh_sidecar_not_drifted(self):
        rec = {"verdict": "non-vacuous", "harness_path": str(self.harness),
               "function": "x", "source_file": "src/H.sol"}
        mvc._persist_durable_sidecar(self.tmp, rec)
        banked = json.loads(next((self.tmp / ".auditooor" / "mvc_sidecar")
                                 .glob("*.json")).read_text())
        self.assertIn("harness_source_sha256", banked)
        self.assertFalse(mvc.sidecar_harness_drifted(banked, self.tmp))

    def test_clobbered_harness_is_drifted(self):
        rec = {"verdict": "non-vacuous", "harness_path": str(self.harness),
               "function": "x", "source_file": "src/H.sol"}
        mvc._persist_durable_sidecar(self.tmp, rec)
        banked = json.loads(next((self.tmp / ".auditooor" / "mvc_sidecar")
                                 .glob("*.json")).read_text())
        # clobber the harness by hand (mode 13: regenerated as an assert(true) stub)
        self.harness.write_text("contract H { function x() public { assert(true); } }\n",
                                encoding="utf-8")
        self.assertTrue(mvc.sidecar_harness_drifted(banked, self.tmp))

    def test_no_recorded_hash_is_not_drifted(self):
        # a pre-P1-b sidecar (no hash) is not retroactively rejected.
        self.assertFalse(mvc.sidecar_harness_drifted(
            {"harness_path": str(self.harness)}, self.tmp))


class TestSiblingBuildResilience(unittest.TestCase):
    """SSV loop fix 2026-06-23: forge/solc compile the WHOLE project, so one broken
    SIBLING test file fails EVERY harness's baseline. _baseline_blocked_by_sibling
    distinguishes 'a sibling poisoned the shared build' from 'MY harness is broken'
    so good harnesses are not falsely no-baseline'd (the parallel-authoring collision).
    """
    _H = "cd /w/src && forge test --match-contract Halmos_SSVClusters_liquidate"
    _SRC = "/w/src/contracts/modules/SSVClusters.sol"

    def _call(self, out):
        return mvc._baseline_blocked_by_sibling(
            out, harness=self._H, harness_path=None, source_file=self._SRC)

    def test_sibling_compile_break_is_flagged(self):
        out = ("Error (6275): Source not found.\n"
               "  --> test/Halmos_SSVClusters_bulkRegisterValidator.t.sol:64:5\n"
               "Error: Compilation failed")
        self.assertEqual(self._call(out),
                         "test/Halmos_SSVClusters_bulkRegisterValidator.t.sol")

    def test_own_harness_break_is_not_sibling(self):
        out = ("ParserError: x\n  --> test/Halmos_SSVClusters_liquidate.t.sol:10:1\n"
               "Error: Compilation failed")
        self.assertIsNone(self._call(out))

    def test_cut_source_break_is_not_sibling(self):
        out = ("Error (1234): y\n  --> contracts/modules/SSVClusters.sol:206:1\n"
               "Error: Compilation failed")
        self.assertIsNone(self._call(out))

    def test_no_compile_error_is_not_sibling(self):
        self.assertIsNone(self._call("Ran 1 test ... [PASS] ... 1 passed"))

    def test_mixed_own_and_sibling_is_not_sibling(self):
        # if our own file is ALSO among the culprits, it is (also) our problem
        out = ("Error: Compilation failed\n"
               "  --> test/Halmos_SSVClusters_bulkRegisterValidator.t.sol:64:5\n"
               "  --> test/Halmos_SSVClusters_liquidate.t.sol:9:1")
        self.assertIsNone(self._call(out))


class TestMonorepoSlugCollision(unittest.TestCase):
    """LANE L1 (found by the morpho MV-floor workflow): in a monorepo, two CUTs
    that share a basename but live in DIFFERENT sub-projects
    (src/vault-v2/src/VaultV2.sol vs src/vault-v2-marketadapter/src/VaultV2.sol)
    must get DISTINCT durable-sidecar slugs. A basename-only slug clobbered one
    on disk, silently dropping a genuine per-fn mutation credit (a serving-join /
    collision). The fix adds a sub-project discriminant. CONSERVATIVE: a plain
    single-project layout keeps its existing slug (no churn)."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="mono_")).resolve()

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _rec(self, source_file):
        return {"schema": "x", "verdict": "non-vacuous",
                "mutation_verified": True, "function": "deposit",
                "source_file": source_file}

    def test_same_basename_diff_subproject_produce_two_sidecars(self):
        # THE non-vacuous core test: two same-basename CUTs in different
        # sub-projects must produce TWO distinct sidecar files, not 1 clobbered.
        p1 = mvc._persist_durable_sidecar(
            self.ws, self._rec("src/vault-v2/src/VaultV2.sol"))
        p2 = mvc._persist_durable_sidecar(
            self.ws, self._rec("src/vault-v2-marketadapter/src/VaultV2.sol"))
        self.assertIsNotNone(p1)
        self.assertIsNotNone(p2)
        self.assertNotEqual(p1, p2, "monorepo slug collision: one CUT clobbered the other")
        sidecars = sorted((self.ws / ".auditooor" / "mvc_sidecar").glob("mvc-*.json"))
        self.assertEqual(len(sidecars), 2,
                         "expected 2 distinct sidecars; a collision dropped one credit")
        # both credits survived and carry their own (distinct) source_file.
        srcs = {json.loads(p.read_text())["source_file"] for p in sidecars}
        self.assertEqual(srcs, {
            "src/vault-v2/src/VaultV2.sol",
            "src/vault-v2-marketadapter/src/VaultV2.sol"})
        # the discriminant appears in the filename so the two are tellable apart.
        names = {p.name for p in sidecars}
        self.assertTrue(any("vault-v2-marketadapter" in n for n in names))
        self.assertTrue(any("vault-v2-" in n and "marketadapter" not in n for n in names))

    def test_single_project_slug_unchanged_no_churn(self):
        # a plain single-project layout must keep its bare <srcbase>-<fn> slug.
        p = mvc._persist_durable_sidecar(self.ws, self._rec("src/H.sol"))
        self.assertEqual(Path(p).name, "mvc-h-deposit.json")

    def test_discriminant_helper(self):
        d = mvc._subproject_discriminant
        # monorepo double-build-dir shape -> enclosing sub-project segment.
        self.assertEqual(d("src/vault-v2/src/VaultV2.sol"), "vault-v2")
        self.assertEqual(d("src/vault-v2-marketadapter/src/VaultV2.sol"),
                         "vault-v2-marketadapter")
        self.assertEqual(d("src/pos-contracts/contracts/x/StakeManager.sol"),
                         "pos-contracts")
        # plain layouts -> no discriminant (no churn).
        self.assertEqual(d("src/H.sol"), "")
        self.assertEqual(d("src/contracts/Foo.sol"), "")
        self.assertEqual(d("Foo.sol"), "")
        self.assertEqual(d(None), "")
        # strips ::line suffix before computing.
        self.assertEqual(d("src/vault-v2/src/VaultV2.sol::deposit"), "vault-v2")
