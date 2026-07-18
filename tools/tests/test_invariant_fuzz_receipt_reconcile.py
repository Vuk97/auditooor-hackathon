#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-INVARIANT-FUZZ-GATE registered via agent-pathspec-register.py -->
"""E1 regression: fuzz-receipt <-> runner-log RECONCILIATION.

Locks in the fix for a CONFIRMED SSV coverage-theater fabrication: the
fuzz_campaign_receipt.json recorded result.calls=1,000,127 for the
SSVClusterSolvency campaign while the ONLY real echidna run log
(fuzz_logs/solvency.log + _campaign_index.log) showed `Total calls: 500172` at
limit=500000 - the number 1,000,127 exists in NO run log. invariant-fuzz-
completeness previously read result.calls BLINDLY.

Behaviour under test (advisory-first, never-retro-red):
  - a receipt whose claimed calls MATCH a runner-log `Total calls: N` (within a
    small tolerance) reconciles -> no flag (never-false-pass);
  - a receipt whose claimed calls appear in NO log AND exceed the max logged
    count for that harness -> `fuzz-receipt-unreconciled`;
  - a claim SMALLER than the log proves (under-states) reconciles (safe);
  - an aggregate _campaign_index.log is sliced to THIS campaign's block so a
    concatenation of many campaigns cannot cross-credit another's count.

Gate-strict semantics (2026-07-03 graduated to DEFAULT-ON under the L37 umbrella).
The 4-case matrix (env AUDITOOOR_FUZZ_RECEIPT_RECONCILE_STRICT x AUDITOOOR_L37_STRICT):
  1. env unset + L37 set          -> ENFORCED  (new default; fail-fuzz-receipt-unreconciled, exit 1);
  2. env unset + no L37           -> advisory  (verdict unchanged, exit 0 - library/non-strict caller);
  3. env=0 (opt-out) even under L37-> advisory  (escape hatch);
  4. env=1 (opt-in)               -> ENFORCED  (regardless of L37).
NEVER-FALSE-PASS: a reconciled receipt still passes even when the gate is ENFORCED.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "ifc_reconcile", str(_TOOLS / "invariant-fuzz-completeness.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["ifc_reconcile"] = m
spec.loader.exec_module(m)

_STRICT_ENV = "AUDITOOOR_FUZZ_RECEIPT_RECONCILE_STRICT"
_L37_ENV = "AUDITOOOR_L37_STRICT"


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _ws_with_receipt(campaigns, logs=None):
    """Build a bare workspace with a fuzz_campaign_receipt.json + fuzz_logs/.
    `campaigns` is the receipt campaigns[] list; `logs` is {filename: text}."""
    ws = Path(tempfile.mkdtemp())
    au = ws / ".auditooor"
    au.mkdir(parents=True)
    _write(au / "fuzz_campaign_receipt.json", json.dumps({
        "schema": "auditooor.fuzz_campaign_receipt.v1",
        "campaigns": campaigns,
    }))
    for name, text in (logs or {}).items():
        _write(au / "fuzz_logs" / name, text)
    return ws


def _echidna_log(contract, total_calls, limit=500000):
    return (f"Compiling test/echidna/{contract}.sol... Done!\n"
            f"Analyzing contract: {contract}\n"
            f"[status] tests: 0/5, fuzzing: {total_calls}/{limit}, cov: 9995\n"
            f"echidna_solvency: passing\n"
            f"Unique instructions: 9995\n"
            f"Total calls: {total_calls}\n")


class TestReceiptReconcile(unittest.TestCase):
    def setUp(self):
        # Deterministic base: BOTH the gate env and the L37 umbrella cleared, so an
        # "env unset" test is unambiguously the "unset + no L37 -> advisory" case
        # regardless of the ambient shell.
        os.environ.pop(_STRICT_ENV, None)
        os.environ.pop(_L37_ENV, None)

    def tearDown(self):
        os.environ.pop(_STRICT_ENV, None)
        os.environ.pop(_L37_ENV, None)

    # ---- reconciliation predicate ----
    def test_matching_receipt_reconciles(self):
        # receipt claims 500172, log shows Total calls: 500172 -> reconciles.
        ws = _ws_with_receipt(
            [{"name": "Solvency", "engine": "echidna",
              "harness_path": "test/echidna/SolvencyMedusa.sol",
              "result": {"calls": 500172}}],
            {"solvency.log": _echidna_log("SolvencyMedusa", 500172)})
        rc = m._reconcile_fuzz_receipt(ws)
        self.assertTrue(rc["applicable"])
        self.assertEqual(rc["checked"], 1)
        self.assertEqual(rc["unreconciled"], [])

    def test_fabricated_receipt_is_unreconciled(self):
        # THE SSV fabrication: receipt claims 1,000,127, log shows 500,172.
        ws = _ws_with_receipt(
            [{"name": "Solvency", "engine": "echidna",
              "harness_path": "test/echidna/SolvencyMedusa.sol",
              "result": {"calls": 1_000_127}}],
            {"solvency.log": _echidna_log("SolvencyMedusa", 500172)})
        rc = m._reconcile_fuzz_receipt(ws)
        self.assertEqual(len(rc["unreconciled"]), 1)
        u = rc["unreconciled"][0]
        self.assertEqual(u["claimed_calls"], 1_000_127)
        self.assertEqual(u["max_logged_calls"], 500172)

    def test_understated_claim_reconciles(self):
        # a claim SMALLER than the log proves (200225 vs a 500244 log) is safe -
        # under-stating is not a fabrication. Mirrors SSV EBAccounting.
        ws = _ws_with_receipt(
            [{"name": "EB", "engine": "echidna",
              "harness_path": "test/echidna/EBEchidna.sol",
              "result": {"calls": 200225}}],
            {"eb-accounting.log": _echidna_log("EBEchidna", 500244)})
        rc = m._reconcile_fuzz_receipt(ws)
        self.assertEqual(rc["unreconciled"], [])

    def test_no_matching_log_is_advisory_not_flagged(self):
        # a campaign whose harness matches NO log (real run log named differently)
        # is reported no-log, NOT unreconciled - never retro-fail on absence.
        ws = _ws_with_receipt(
            [{"name": "Staking", "engine": "echidna",
              "harness_path": "test/echidna/StakingSymmetry.sol",
              "result": {"calls": 100154}}],
            {"unrelated-other.log": _echidna_log("SomethingElse", 500000)})
        rc = m._reconcile_fuzz_receipt(ws)
        self.assertEqual(rc["unreconciled"], [])
        self.assertIn("Staking", rc["no_log"])

    def test_forge_unit_mutation_campaign_skipped(self):
        # a forge-unit-mutation campaign (no result.calls, no testLimit) is not a
        # coverage-guided fuzz campaign and is skipped (no Total-calls log to match).
        ws = _ws_with_receipt(
            [{"name": "DAO_mut", "engine": "forge-mutation-verify",
              "harness_path": "test/Halmos_DAO.t.sol",
              "config": {"mode": "forge-unit-mutation", "mutants": 6},
              "result": {"properties": 2, "passed": 2, "mutants_killed": 6}}])
        rc = m._reconcile_fuzz_receipt(ws)
        self.assertEqual(rc["checked"], 0)
        self.assertEqual(rc["unreconciled"], [])

    def test_aggregate_index_log_sliced_per_campaign(self):
        # an aggregate _campaign_index.log holding BOTH campaigns must not let one
        # campaign borrow the other's Total-calls. Solvency claims a fabricated
        # 1,000,127; its own block shows 500172 -> still flagged despite a sibling
        # block that shows a higher count.
        index = (
            "=== [17:46:09] campaign solvency (contract=SolvencyMedusa limit=500000) ===\n"
            "Total calls: 500172\n"
            "=== [17:47:33] campaign eb-accounting (contract=EBEchidna limit=500000) ===\n"
            "Total calls: 900500\n"
            "=== [18:08:17] ALL CAMPAIGNS DONE ===\n")
        ws = _ws_with_receipt(
            [{"name": "solvency", "engine": "echidna",
              "harness_path": "test/echidna/SolvencyMedusa.sol",
              "result": {"calls": 1_000_127}}],
            {"_campaign_index.log": index})
        rc = m._reconcile_fuzz_receipt(ws)
        self.assertEqual(len(rc["unreconciled"]), 1)
        # the reconciler read ONLY the solvency block (500172), not the sibling 900500.
        self.assertEqual(rc["unreconciled"][0]["max_logged_calls"], 500172)

    # ---- advisory-first end-to-end verdict wiring ----
    def _ws_full_pass_but_fabricated(self):
        """A workspace where the harness-centric bar passes AND a fabricated
        receipt exists, so the ONLY thing that can flip the verdict is E1."""
        ws = Path(tempfile.mkdtemp())
        au = ws / ".auditooor"
        au.mkdir(parents=True)
        # a genuine harness dir so the harness bar passes
        hd = ws / "chimera_harnesses" / "H"
        hd.mkdir(parents=True)
        _write(hd / "Properties.sol",
               "// SPDX-License-Identifier: MIT\npragma solidity 0.8.34;\ncontract Properties {\n"
               "    function property_a() public view returns (bool) { return true; }\n"
               "    function property_b() public view returns (bool) { return true; }\n"
               "    function test_mutation_breaks_a() public { assertFalse(false); }\n}\n")
        deng = au / "deep-engine-findings"
        deng.mkdir(parents=True)
        _write(deng / "H-invariant-fuzz.md",
               "# H\n" + ("x" * 400) +
               "\n[PASS] invariant_a() (runs: 25000, calls: 1200000, reverts: 0)\n")
        # fabricated receipt + its real (lower) log
        _write(au / "fuzz_campaign_receipt.json", json.dumps({
            "schema": "auditooor.fuzz_campaign_receipt.v1",
            "campaigns": [
                {"name": "Solvency", "engine": "echidna",
                 "harness_path": "test/echidna/SolvencyMedusa.sol",
                 "result": {"calls": 1_000_127}}]}))
        _write(au / "fuzz_logs" / "solvency.log",
               _echidna_log("SolvencyMedusa", 500172))
        return ws

    # ---- 4-case gate-strict matrix ----
    def test_case2_unset_no_l37_is_advisory_exit0(self):
        # CASE 2 (env unset + no L37): a bare non-strict / library caller stays
        # advisory - the reconcile field shows the fabrication but the verdict is
        # NOT the fuzz-receipt fail and exit is 0 (never-retro-red).
        ws = self._ws_full_pass_but_fabricated()
        r = m.evaluate(ws)
        self.assertIn("fuzz_receipt_reconcile", r)
        self.assertEqual(len(r["fuzz_receipt_reconcile"]["unreconciled"]), 1)
        self.assertNotEqual(r["verdict"], "fail-fuzz-receipt-unreconciled")
        self.assertEqual(m.main(["--workspace", str(ws)]), 0)

    def test_case1_unset_under_l37_is_enforced_exit1(self):
        # CASE 1 (env unset + L37 set): the NEW default - the strict audit umbrella
        # enforces the gate WITHOUT the operator naming the per-gate env.
        ws = self._ws_full_pass_but_fabricated()
        os.environ[_L37_ENV] = "1"
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-fuzz-receipt-unreconciled")
        self.assertEqual(m.main(["--workspace", str(ws)]), 1)

    def test_case3_optout_under_l37_is_advisory_exit0(self):
        # CASE 3 (env=0 opt-out, even under L37): the escape hatch keeps the gate
        # advisory despite the L37 umbrella.
        ws = self._ws_full_pass_but_fabricated()
        os.environ[_L37_ENV] = "1"
        os.environ[_STRICT_ENV] = "0"
        r = m.evaluate(ws)
        self.assertNotEqual(r["verdict"], "fail-fuzz-receipt-unreconciled")
        self.assertEqual(m.main(["--workspace", str(ws)]), 0)

    def test_case4_explicit_optin_is_enforced_exit1(self):
        # CASE 4 (env=1 explicit opt-in): enforced regardless of L37 (here L37 unset).
        ws = self._ws_full_pass_but_fabricated()
        os.environ[_STRICT_ENV] = "1"
        r = m.evaluate(ws)
        self.assertEqual(r["verdict"], "fail-fuzz-receipt-unreconciled")
        self.assertEqual(m.main(["--workspace", str(ws)]), 1)

    def test_enforced_passes_when_reconciled(self):
        # NEVER-FALSE-PASS: a genuine (matching) receipt still passes when ENFORCED
        # (exercise both the explicit opt-in AND the L37-default enforcement path).
        for enable in ({_STRICT_ENV: "1"}, {_L37_ENV: "1"}):
            os.environ.pop(_STRICT_ENV, None)
            os.environ.pop(_L37_ENV, None)
            os.environ.update(enable)
            ws = self._ws_full_pass_but_fabricated()
            # rewrite the receipt to claim the TRUE logged count -> reconciles.
            rec = ws / ".auditooor" / "fuzz_campaign_receipt.json"
            d = json.loads(rec.read_text())
            d["campaigns"][0]["result"]["calls"] = 500172
            rec.write_text(json.dumps(d))
            r = m.evaluate(ws)
            self.assertNotEqual(r["verdict"], "fail-fuzz-receipt-unreconciled")
            self.assertEqual(r["fuzz_receipt_reconcile"]["unreconciled"], [])


if __name__ == "__main__":
    unittest.main()
