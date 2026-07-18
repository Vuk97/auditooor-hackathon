#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-CORE-COVERAGE-GATE registered via agent-pathspec-register.py -->
"""Guard: core-coverage-completeness fails-closed on a periphery-only harness set.

The load-bearing case: a workspace flags an in-scope value-moving CORE contract,
a mutation-verified harness exists, BUT the harness's CUT is a PERIPHERY file
(not the core contract). The gate must FAIL (fail-core-coverage-periphery-only).
When the SAME harness instead targets the core contract it must PASS. Also
exercises: no-core (pass-no-core-contracts), no-mutation-evidence
(pass-core-mutation-evidence-absent), and the L37-wiring round-trip (the new
signal is enumerated, fails the whole gate, and an operator core-coverage:
l37-rebuttal walks it back - false-green-safe + honest-walk-back-compatible).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "ccc", str(_TOOLS / "core-coverage-completeness.py"))
ccc = importlib.util.module_from_spec(_spec)
sys.modules["ccc"] = ccc
_spec.loader.exec_module(ccc)

_aspec = importlib.util.spec_from_file_location(
    "acc_for_core_cov", str(_TOOLS / "audit-completeness-check.py"))
acc = importlib.util.module_from_spec(_aspec)
sys.modules["acc_for_core_cov"] = acc
_aspec.loader.exec_module(acc)


def _ws() -> Path:
    return Path(tempfile.mkdtemp())


def _write_vmf(ws: Path, core_file: str):
    """Flag ``core_file`` as an in-scope value-moving CORE contract."""
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "value_moving_functions.json").write_text(json.dumps({
        "workspace": str(ws),
        "function_count": 1,
        "functions": [
            {"file": core_file, "function": "withdraw", "language": "sol",
             "transfer_hit": True, "ledger_write_hit": True},
        ],
    }), encoding="utf-8")


def _write_mutation(ws: Path, cut_file: str, *, kill=True):
    """Record a mutation-verified harness whose CUT is ``cut_file``."""
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "mutation_verify_coverage.json").write_text(json.dumps({
        "results": [
            {"source_file": cut_file, "function": "withdraw",
             "harness": "InvariantTest.t.sol",
             "verdict": "non-vacuous" if kill else "vacuous",
             "mutation_verified": True},
        ],
    }), encoding="utf-8")


def _write_src(ws: Path, rel: str):
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("// SPDX-License-Identifier: MIT\ncontract C { function withdraw() public {} }\n")


class TestCoreCoverageCompleteness(unittest.TestCase):
    # ---- the periphery-only false-green this gate exists to close ----
    def test_periphery_only_harness_FAILS(self):
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        _write_src(ws, "src/Logger.sol")
        _write_vmf(ws, "src/CoreVault.sol")          # CORE = the vault
        _write_mutation(ws, "src/Logger.sol")        # harness CUT = periphery
        r = ccc.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-core-coverage-periphery-only")
        self.assertEqual(r["covered_core_count"], 0)
        self.assertIn("src/CoreVault.sol", r["uncovered_core"])

    def test_core_cut_harness_PASSES(self):
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        _write_vmf(ws, "src/CoreVault.sol")
        _write_mutation(ws, "src/CoreVault.sol")     # harness CUT = the core contract
        r = ccc.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-core-covered")
        self.assertIn("src/CoreVault.sol", r["covered_core"])

    def test_vacuous_core_harness_does_NOT_credit(self):
        # A mutation record that KILLED NOTHING (vacuous) on the core CUT must
        # not satisfy the gate - false-green safety.
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        _write_vmf(ws, "src/CoreVault.sol")
        _write_mutation(ws, "src/CoreVault.sol", kill=False)
        r = ccc.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-core-coverage-periphery-only")

    def test_basename_match_credits(self):
        # Mutation records often store ABSOLUTE source_file paths; the join must
        # still credit the core contract by path-suffix / basename.
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        _write_vmf(ws, "src/CoreVault.sol")
        abs_cut = str((ws / "src" / "CoreVault.sol").resolve())
        _write_mutation(ws, abs_cut)
        r = ccc.evaluate(ws)
        self.assertEqual(r["verdict"], "pass-core-covered")

    # ---- language scope: medusa is Solidity-only; Go/Rust defer ----
    def test_go_rust_core_deferred_not_in_medusa_denominator(self):
        # A Go monitoring "value-mover" CANNOT have a medusa harness; it must be
        # DEFERRED (surfaced), not counted as uncovered medusa-core. The Solidity
        # core requirement must remain intact (still fails-closed when uncovered).
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        (ws / "src" / "mon").mkdir(parents=True, exist_ok=True)
        (ws / "src" / "mon" / "monitor.go").write_text("package mon\nfunc Check() {}\n")
        d = ws / ".auditooor"; d.mkdir(parents=True, exist_ok=True)
        (d / "value_moving_functions.json").write_text(json.dumps({
            "functions": [
                {"file": "src/CoreVault.sol", "function": "withdraw", "language": "sol",
                 "transfer_hit": True, "ledger_write_hit": True},
                {"file": "src/mon/monitor.go", "function": "Check", "language": "go",
                 "transfer_hit": False, "ledger_write_hit": True},
            ]}), encoding="utf-8")
        _write_mutation(ws, "src/Logger.sol")  # periphery harness -> Sol core uncovered
        r = ccc.evaluate(ws)
        # Solidity core still required + still failing (NO weakening):
        self.assertEqual(r["verdict"], "fail-core-coverage-periphery-only")
        self.assertIn("src/CoreVault.sol", r["uncovered_core"])
        # Go file is DEFERRED, not in the medusa core set / uncovered list:
        self.assertEqual(r["core_count"], 1, "Go file leaked into the medusa core denominator")
        self.assertNotIn("src/mon/monitor.go", r.get("uncovered_core", []))
        self.assertIn("src/mon/monitor.go", r.get("deferred_non_medusa_core", []))

    def test_solidity_core_still_required_after_scoping(self):
        # belt-and-suspenders: a Solidity-only workspace with a real core-CUT harness
        # still PASSES (scoping did not break the credit path).
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        _write_vmf(ws, "src/CoreVault.sol")
        _write_mutation(ws, "src/CoreVault.sol")
        self.assertEqual(ccc.evaluate(ws)["verdict"], "pass-core-covered")

    # ---- the no-double-penalty / pass paths ----
    def test_no_core_contracts_PASSES(self):
        ws = _ws()
        _write_src(ws, "src/Foo.sol")
        # empty VMF -> no value-moving core surface
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / ".auditooor" / "value_moving_functions.json").write_text(
            json.dumps({"function_count": 0, "functions": []}), encoding="utf-8")
        self.assertEqual(ccc.evaluate(ws)["verdict"], "pass-no-core-contracts")

    def test_no_mutation_evidence_does_not_double_penalize(self):
        # Core contracts flagged but NO mutation artifact yet: this gate does not
        # own "must fuzz" (invariant-fuzz does) so it must PASS, not FAIL.
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        _write_vmf(ws, "src/CoreVault.sol")
        self.assertEqual(
            ccc.evaluate(ws)["verdict"], "pass-core-mutation-evidence-absent")

    # ---- L37 wiring round-trip: signal enumerated, fails gate, rebuttal walks back ----
    def test_signal_in_order_and_wired(self):
        order_keys = {s for s, _ in acc._SIGNAL_ORDER}
        self.assertIn("core-coverage", order_keys)
        # by_signal index in evaluate() must not KeyError on the new signal.
        self.assertTrue(hasattr(acc, "check_core_coverage"))

    def test_signal_fail_then_l37_rebuttal_walks_back(self):
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        _write_src(ws, "src/Logger.sol")
        _write_vmf(ws, "src/CoreVault.sol")
        _write_mutation(ws, "src/Logger.sol")
        # Raw signal must FAIL.
        sig = acc.check_core_coverage(ws)
        self.assertFalse(sig.ok)
        self.assertEqual(sig.signal, "core-coverage")
        # Operator l37-rebuttal flips it to ok-rebuttal (honest-walk-back). The
        # canonical line form is ``l37-rebuttal: <signal>: <reason>`` - the same
        # path every other signal inherits via evaluate()'s _rebuttal_for.
        (ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: core-coverage: cross-function pair covers the vault; "
            "periphery harness is N/A here\n",
            encoding="utf-8")
        rebuttals = acc._load_rebuttal(ws)
        self.assertEqual(rebuttals.get("core-coverage"),
                         "cross-function pair covers the vault; "
                         "periphery harness is N/A here")
        self.assertIsNotNone(acc._rebuttal_for(rebuttals, "core-coverage"))
        # And the full gate honors it: the signal flips to ok-rebuttal.
        out = acc.evaluate(ws)
        cc = next(s for s in out["signals"] if s["signal"] == "core-coverage")
        self.assertTrue(cc["ok"])
        self.assertEqual(cc["verdict"], "ok-rebuttal")

    def test_full_evaluate_does_not_crash(self):
        # Defensive: the whole gate enumerates every signal incl. core-coverage.
        ws = _ws()
        _write_src(ws, "src/CoreVault.sol")
        _write_vmf(ws, "src/CoreVault.sol")
        _write_mutation(ws, "src/Logger.sol")
        out = acc.evaluate(ws)
        sigs = {s["signal"] for s in out["signals"]}
        self.assertIn("core-coverage", sigs)
        cc = next(s for s in out["signals"] if s["signal"] == "core-coverage")
        self.assertFalse(cc["ok"])
        self.assertEqual(cc["verdict"], "fail-core-coverage-periphery-only")


if __name__ == "__main__":
    unittest.main(verbosity=2)
