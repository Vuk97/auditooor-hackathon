#!/usr/bin/env python3
"""test_A7.py - cross-module reentrancy / callback-into-SIBLING screen (A7).

Exercises tools/cross-module-sibling-reentrancy.py (CMSR), an advisory-first,
NO-AUTO-CREDIT (verdict=needs-fuzz) GENERAL enforcement screen for the private
invariant "a reentrancy lock must span the whole cross-module composition".

Non-vacuity is proven three ways:
  * a planted positive FIRES (vuln.sol: read + write sibling sub-classes),
  * a guarded negative stays SILENT (guarded.sol) and FIRES only once a
    sibling's reentrancy guard is weakened on a temp copy (mutation-verify),
  * neutralising the core callback-window predicate makes the positive test
    FAIL (test_callback_predicate_is_load_bearing); likewise the state-var and
    relation predicates each have a dedicated FP-guard fixture.
"""
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "cross-module-sibling-reentrancy.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "A7"


def _load():
    spec = importlib.util.spec_from_file_location("cmsr_a7", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["cmsr_a7"] = m
    spec.loader.exec_module(m)
    return m


class TestCrossModuleSiblingReentrancy(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, *names, extra=None):
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        for n in names:
            shutil.copy(_FIX / n, d / "src" / n)
        if extra:
            for fname, text in extra.items():
                (d / "src" / fname).write_text(text, encoding="utf-8")
        return d

    def _hits(self, *names, extra=None):
        return self.m.produce_hypotheses(self._ws(*names, extra=extra))

    # ---- planted positive FIRES -----------------------------------------
    def test_positive_fires_both_subclasses(self):
        hits = self._hits("vuln.sol")
        self.assertEqual(len(hits), 2, "vuln must fire exactly the read + write pair")
        subs = {h["sub_class"] for h in hits}
        self.assertEqual(subs, {
            "cross-module-readonly-reentrancy",
            "cross-module-write-reentrancy",
        })
        for h in hits:
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertEqual(h["attack_class"], "cross-module-reentrancy")
            self.assertEqual(h["window_contract"], "Pool")
            self.assertEqual(h["window_function"], "flashLoan")
            self.assertEqual(h["coupled_token"], "totalReserves")
            self.assertNotEqual(h["sibling_contract"], h["window_contract"])
            self.assertFalse(h["dedup_hint_same_contract"])

    # ---- guarded negative stays SILENT ----------------------------------
    def test_guarded_is_silent(self):
        self.assertEqual(self._hits("guarded.sol"), [],
                         "a reentrancy-guarded sibling must suppress the row")

    # ---- MUTATION-VERIFY: weaken the sibling guard -> FIRES --------------
    def test_mutation_weakening_sibling_guard_fires(self):
        # Start from the guarded (silent) fixture; remove nonReentrant from the
        # read sibling only -> the tool must now fire on that sibling.
        src = (_FIX / "guarded.sol").read_text()
        weakened = src.replace(
            "function price() external view nonReentrant returns (uint256)",
            "function price() external view returns (uint256)",
        )
        self.assertNotEqual(src, weakened, "the guard token must be present to weaken")
        hits = self.m.produce_hypotheses(self._ws(extra={"weak.sol": weakened}))
        self.assertEqual(len(hits), 1,
                         "removing the sibling's guard must expose exactly the read pair")
        self.assertEqual(hits[0]["sibling_function"], "price")
        self.assertEqual(hits[0]["sub_class"], "cross-module-readonly-reentrancy")

    # ---- FP-guard: local (non-state) coupled name -----------------------
    def test_fp_local_not_state_var_is_silent(self):
        self.assertEqual(self._hits("fp_local.sol"), [],
                         "a coincidental LOCAL name is not a cross-module storage coupling")

    # ---- FP-guard: unrelated contracts in separate files ----------------
    def test_fp_unrelated_contracts_silent(self):
        self.assertEqual(self._hits("unrelated_a.sol", "unrelated_b.sol"), [],
                         "unrelated contracts sharing a field name must not pair")

    # ---- non-vacuity: the callback-window predicate is load-bearing ------
    def test_callback_predicate_is_load_bearing(self):
        saved = list(self.m._SOL_CALLBACK_RES)
        try:
            self.m._SOL_CALLBACK_RES[:] = [re.compile(r"ZZZ_NEVER_MATCHES")]
            self.assertEqual(self._hits("vuln.sol"), [],
                             "neutralising the callback lexicon must silence the positive")
        finally:
            self.m._SOL_CALLBACK_RES[:] = saved
        self.assertEqual(len(self._hits("vuln.sol")), 2, "restored predicate fires again")

    # ---- non-vacuity: the guard predicate is load-bearing ---------------
    def test_guard_predicate_is_load_bearing(self):
        # With the guard lexicon neutralised, the GUARDED fixture must now fire
        # (proving the guard check is what suppresses it).
        saved = list(self.m._SOL_GUARD_RES)
        try:
            self.m._SOL_GUARD_RES[:] = [re.compile(r"ZZZ_NEVER_MATCHES")]
            self.assertEqual(len(self._hits("guarded.sol")), 2,
                             "neutralising the guard lexicon must expose the guarded pair")
        finally:
            self.m._SOL_GUARD_RES[:] = saved

    # ---- non-vacuity: the state-var predicate is load-bearing -----------
    def test_state_var_predicate_is_load_bearing(self):
        saved = self.m._STATE_VAR_RE
        try:
            # Make state-var extraction match nothing -> no coupled token is a
            # real state var -> the positive must go silent.
            self.m._STATE_VAR_RE = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(self._hits("vuln.sol"), [],
                             "with no state vars, no coupling is recognised")
        finally:
            self.m._STATE_VAR_RE = saved

    # ---- advisory-first: OFF by default, no sidecar ---------------------
    def test_advisory_off_by_default(self):
        os.environ.pop(self.m._ADVISORY_ENV, None)
        ws = self._ws("vuln.sol")
        res = self.m.evaluate(ws)
        self.assertIsNone(res.get("cross_module_sibling_reentrancy"),
                          "advisory must be OFF (None) by default")
        self.assertFalse(
            (ws / ".auditooor" / "cross_module_sibling_reentrancy.jsonl").exists(),
            "no sidecar emitted when advisory disabled")

    def test_enabled_emits_needs_fuzz_sidecar(self):
        os.environ[self.m._ADVISORY_ENV] = "1"
        try:
            ws = self._ws("vuln.sol")
            res = self.m.evaluate(ws)
            summ = res.get("cross_module_sibling_reentrancy")
            self.assertIsNotNone(summ)
            self.assertTrue(summ["enabled"])
            self.assertEqual(summ["verdict"], "needs-fuzz")
            self.assertGreaterEqual(summ["count"], 1)
            jl = ws / ".auditooor" / "cross_module_sibling_reentrancy.jsonl"
            self.assertTrue(jl.exists())
            rows = [json.loads(x) for x in jl.read_text().splitlines() if x.strip()]
            self.assertTrue(rows and all(r["verdict"] == "needs-fuzz" for r in rows),
                            "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        finally:
            os.environ.pop(self.m._ADVISORY_ENV, None)

    # ---- run() writes a jsonl even with zero rows (never fail-closed) ----
    def test_run_zero_rows_ok(self):
        ws = self._ws("guarded.sol")
        out = self.m.run(ws)
        self.assertTrue(out.exists())
        self.assertEqual(out.read_text().strip(), "")


if __name__ == "__main__":
    unittest.main()
