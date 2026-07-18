#!/usr/bin/env python3
"""P0-d (mode 12): setUp-crash false-kill is NOT a genuine kill.

A mutation that breaks the harness's OWN setUp()/seed path makes setUp() revert; a
producer keying on exit-code/status=="fail" records a mutant "kill" even though the
invariant property NEVER executed (near-intents finTransfer 6/6 were all
`[FAIL] setUp() (gas: 0)`). The promoted shared predicate in tools/lib/mutation_kill.py
reclassifies such a tail as harness-broken-by-mutant; a tail naming an
invariant_/property_ assertion frame is a genuine kill (killed==True).

These tests are hermetic (no forge/halmos/cargo): they drive the verifier with a
tiny Python stub whose PASS/FAIL is controlled by inspecting the (mutated) source,
and they unit-test the shared predicate directly.
"""
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOLS = _HERE.parent


def _load(name: str, fname: str):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fname))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # py3.14: register BEFORE exec_module
    spec.loader.exec_module(mod)
    return mod


mk = _load("mutation_kill", "lib/mutation_kill.py")
mvc = _load("mutation_verify_coverage", "mutation-verify-coverage.py")


_SOL_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
contract Calc {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}
"""


class TestSharedPredicate(unittest.TestCase):
    """Unit tests for tools/lib/mutation_kill.py (the promoted predicate)."""

    def test_setup_only_fail_tail_is_not_genuine(self):
        tail = "[FAIL: arithmetic underflow] setUp() (gas: 0)"
        self.assertFalse(mk._is_genuine_invariant_kill(tail))
        self.assertEqual(mk.classify_kill_kind(tail), "harness-broken-by-mutant")

    def test_invariant_frame_fail_tail_is_genuine(self):
        tail = "[FAIL] invariant_cap() (runs: 256, calls: 5000) assertion failed"
        self.assertTrue(mk._is_genuine_invariant_kill(tail))
        self.assertEqual(mk.classify_kill_kind(tail), "behavior-changing")

    def test_panic_only_no_assertion_is_equivalent_mutant(self):
        tail = "[FAIL] Panic(uint256) 0x11 arithmetic overflow"
        self.assertEqual(mk.classify_kill_kind(tail), "equivalent-mutant")
        # not a genuine invariant kill either (no assertion frame)
        self.assertFalse(mk._is_genuine_invariant_kill(tail))

    def test_panic_with_invariant_frame_but_no_behavior_change_is_equivalent(self):
        # the assertion frame is named but the only failure signal is the EVM panic
        tail = "invariant_balance(): Panic(uint256) 0x11 arithmetic underflow"
        self.assertEqual(mk.classify_kill_kind(tail), "equivalent-mutant")

    def test_property_assertion_violated_is_behavior_changing(self):
        tail = "property_no_free_shares: failed!  assertion violated"
        self.assertEqual(mk.classify_kill_kind(tail), "behavior-changing")
        self.assertTrue(mk.is_behavior_changing_kill(tail))

    def test_no_failure_marker_is_not_a_kill(self):
        self.assertEqual(mk.classify_kill_kind("[PASS] invariant_x() ok"), "not-a-kill")


def _write_stub(path: Path, *, mode: str) -> None:
    """mode='invariant': FAILs naming an invariant_ frame iff the '+' op is gone.
    mode='setup_crash': always FAILs naming ONLY setUp() (a scaffold-revert kill)
                        when the op is gone; passes on clean '+' source."""
    bodies = {
        "invariant": (
            "import sys, re, pathlib\n"
            "src = pathlib.Path(sys.argv[1]).read_text()\n"
            "m = re.search(r'return a (.) b;', src)\n"
            "ok = bool(m) and m.group(1) == '+'\n"
            "print('[PASS] invariant_add() ok' if ok else "
            "'[FAIL] invariant_add() (runs: 10, calls: 50) assertion failed')\n"
            "sys.exit(0 if ok else 3)\n"
        ),
        "setup_crash": (
            "import sys, re, pathlib\n"
            "src = pathlib.Path(sys.argv[1]).read_text()\n"
            "m = re.search(r'return a (.) b;', src)\n"
            "ok = bool(m) and m.group(1) == '+'\n"
            "print('[PASS] invariant_add() ok' if ok else "
            "'[FAIL] setUp() (gas: 0)')\n"
            "sys.exit(0 if ok else 3)\n"
        ),
    }
    path.write_text(bodies[mode], encoding="utf-8")


class TestProducerSetupCrashFalseKill(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="setupcrash_"))
        self.src = self.tmp / "src" / "Calc.sol"
        self.src.parent.mkdir(parents=True, exist_ok=True)
        self.src.write_text(_SOL_SRC, encoding="utf-8")
        self.stub = self.tmp / "stub.py"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cmd(self) -> str:
        return f"{sys.executable} {self.stub} {self.src}"

    def test_invariant_frame_tail_is_killed(self):
        _write_stub(self.stub, mode="invariant")
        rec = mvc.verify(
            workspace=self.tmp, source_file=self.src, function="add",
            harness=self._cmd(), classes=["arithmetic"], max_mutants=2, timeout=30,
        )
        self.assertEqual(rec["verdict"], "non-vacuous", rec.get("reason"))
        self.assertGreaterEqual(rec["killed_count"], 1)
        self.assertTrue(any(m["killed"] and m["kill_kind"] == "behavior-changing"
                            for m in rec["mutant_results"]))

    def test_setup_crash_tail_is_NOT_killed(self):
        _write_stub(self.stub, mode="setup_crash")
        rec = mvc.verify(
            workspace=self.tmp, source_file=self.src, function="add",
            harness=self._cmd(), classes=["arithmetic"], max_mutants=2, timeout=30,
        )
        # every "fail" is a setUp()-only frame -> harness-broken-by-mutant, NOT killed
        self.assertEqual(rec["killed_count"], 0, rec.get("reason"))
        self.assertNotEqual(rec["verdict"], "non-vacuous")
        self.assertTrue(all(m["kill_kind"] != "behavior-changing"
                            for m in rec["mutant_results"]))
        self.assertTrue(any(m["kill_kind"] == "harness-broken-by-mutant"
                            for m in rec["mutant_results"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
