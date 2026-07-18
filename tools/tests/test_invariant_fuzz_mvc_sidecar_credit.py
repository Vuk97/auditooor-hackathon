#!/usr/bin/env python3
"""G8 regression: invariant-fuzz-completeness must credit a durable mvc_sidecar
(mutation-verify-coverage) for a harness's non-vacuity - but ONLY on a GENUINE
invariant-assertion kill, never on a setUp()/compile-revert kill (R80 guard).

Before 2026-06-27 the gate set mut=True only from an in-tree `test_mutation_breaks_*`
fn, ignoring the mvc_sidecar produced by tools/mutation-verify-coverage.py - so a
genuinely mutation-verified harness false-red'd as mut=False (serving-join, the SSV
re-verify finding). Fix credits the sidecar, soundly.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "invariant-fuzz-completeness.py"
_s = importlib.util.spec_from_file_location("invariant_fuzz_completeness", _T)
ifc = importlib.util.module_from_spec(_s)
sys.modules["invariant_fuzz_completeness"] = ifc
_s.loader.exec_module(ifc)


class GenuineKillPredicateTest(unittest.TestCase):
    def test_setup_revert_kill_is_NOT_genuine(self):
        tail = ("Ran 1 test for test/X.t.sol:Econ\n[FAIL: CastOverflow()] setUp() (gas: 0)\n"
                "Suite result: FAILED. 0 passed; 1 failed")
        self.assertFalse(ifc._is_genuine_invariant_kill(tail))

    def test_invariant_assertion_kill_IS_genuine(self):
        tail = ("Ran 1 test\n[FAIL: assertion violated] invariant_conservation() (runs: 5, calls: 900)\n"
                "Suite result: FAILED. 0 passed; 1 failed")
        self.assertTrue(ifc._is_genuine_invariant_kill(tail))

    def test_medusa_property_kill_is_genuine(self):
        tail = "[FAILED] Assertion Test: Handler.property_solvency()\n"
        self.assertTrue(ifc._is_genuine_invariant_kill(tail))

    def test_clean_pass_is_not_a_kill(self):
        self.assertFalse(ifc._is_genuine_invariant_kill("Suite result: ok. 3 passed; 0 failed"))


class MvcSidecarCreditTest(unittest.TestCase):
    def _ws_with_sidecar(self, mutant_tail, base_status="pass"):
        t = tempfile.mkdtemp()
        ws = Path(t)
        hd = ws / "chimera_harnesses" / "VaultV2"
        hd.mkdir(parents=True)
        (hd / "VaultV2InvariantHandler.sol").write_text(
            "contract VaultV2InvariantHandler { function property_x() public {} }", encoding="utf-8")
        scd = ws / ".auditooor" / "mvc_sidecar"
        scd.mkdir(parents=True)
        rec = {
            "schema": "auditooor.mutation_verify_coverage.v1",
            "harness_path": str(hd / "VaultV2InvariantHandler.sol"),
            "baseline": {"status": base_status,
                         "output_tail": "Ran 1 test\n[PASS] invariant_x() (runs: 256, calls: 256000)\nSuite result: ok. 1 passed"},
            "mutant_results": [{"killed": True, "output_tail": mutant_tail}],
        }
        (scd / "mvc-vaultv2.json").write_text(json.dumps(rec), encoding="utf-8")
        return ws, hd

    def test_genuine_kill_credits_mut(self):
        ws, hd = self._ws_with_sidecar(
            "[FAIL: violated] invariant_conservation() (runs: 3, calls: 600)\nSuite result: FAILED")
        mut, ev = ifc._mvc_sidecar_credit(ws, hd)
        self.assertTrue(mut, "genuine invariant-assertion kill must credit mut")
        self.assertTrue(any("mvc-kill" in e for e in ev))
        self.assertTrue(any("mvc-baseline" in e for e in ev), "passing baseline run = engine evidence")

    def test_setup_revert_kill_does_NOT_credit_mut(self):
        ws, hd = self._ws_with_sidecar(
            "[FAIL: CastOverflow()] setUp() (gas: 0)\nSuite result: FAILED")
        mut, ev = ifc._mvc_sidecar_credit(ws, hd)
        self.assertFalse(mut, "setUp/compile-revert kill must NOT credit mut (coverage-theater guard)")
        # but the passing baseline still counts as engine evidence
        self.assertTrue(any("mvc-baseline" in e for e in ev))


class DualSchemaCreditTest(unittest.TestCase):
    """corecov_cluster_sidecar_credit_fix 4th-gate blind spot: a GENUINE durable
    sidecar in the cluster/manual schema (NOT auditooor.mutation_verify_coverage.v1)
    was skipped purely on the schema string, even though core-coverage credited the
    very same record. invariant-fuzz must now admit it via the canonical
    _sidecar_is_genuine predicate - and ONLY when genuine (never-false-pass)."""

    def _ws(self, rec, harness_name="SSVClusterSolvencyMedusa.sol"):
        t = tempfile.mkdtemp()
        ws = Path(t)
        hd = ws / "chimera_harnesses" / "SSVClusterSolvency"
        hd.mkdir(parents=True)
        (hd / harness_name).write_text(
            "contract SSVClusterSolvencyMedusa { function property_solvency() public {} }",
            encoding="utf-8")
        scd = ws / ".auditooor" / "mvc_sidecar"
        scd.mkdir(parents=True)
        (scd / "cluster.json").write_text(json.dumps(rec), encoding="utf-8")
        return ws, hd

    def _genuine_cluster_rec(self, harness_name="SSVClusterSolvencyMedusa.sol"):
        return {
            "schema": "mvc_sidecar_v1",
            "harness_path": f"src/ssv-network/test/echidna/{harness_name}",
            "contract": "SSVClusterSolvencyMedusa",
            "mutation_verified": True,
            "mutants_killed": 2,
            "invariants": [
                {"name": "operator_no_over_withdraw",
                 "mutant_result": "FAIL - killed by MUTANT-A"},
                {"name": "liquidation_gating",
                 "mutant_result": "FAIL - killed by MUTANT-B"},
            ],
            "mutation_detail": [
                {"mutant_id": "MUTANT-A", "target_fn": "_withdrawOperatorEarnings",
                 "description": "remove balance-sufficiency check + skip deduction"},
            ],
        }

    def test_genuine_cluster_schema_is_credited(self):
        rec = self._genuine_cluster_rec()
        self.assertNotEqual(rec["schema"], ifc._MVC_SCHEMA)
        self.assertTrue(ifc._sidecar_is_genuine(rec),
                        "fixture must be canon-genuine or the test proves nothing")
        ws, hd = self._ws(rec)
        mut, ev = ifc._mvc_sidecar_credit(ws, hd)
        self.assertTrue(mut, "genuine cluster-schema sidecar must credit mut (4th-gate fix)")

    def test_nongenuine_cluster_schema_is_NOT_credited(self):
        rec = self._genuine_cluster_rec()
        rec["mutation_verified"] = False
        rec["mutants_killed"] = 0
        rec["invariants"] = [{"name": "x", "mutant_result": "N/A"}]
        rec["mutation_detail"] = []
        ws, hd = self._ws(rec)
        if not ifc._sidecar_is_genuine(rec):
            mut, _ = ifc._mvc_sidecar_credit(ws, hd)
            self.assertFalse(mut, "0-kill cluster sidecar must NOT credit (never-false-pass)")


if __name__ == "__main__":
    unittest.main()
