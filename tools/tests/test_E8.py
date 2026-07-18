#!/usr/bin/env python3
"""test_E8.py - 11th sub-axis token_behavior (E8).

Extends tools/completeness-matrix-build.py with an advisory-first, NO-AUTO-CREDIT
(verdict='needs-fuzz') detector: per in-scope fn that moves a settings/config
token via safe/transferFrom, an enumerated invariant must be BOTH measured-delta
(balanceOf before/after) AND decimal-normalized; else one hypothesis row.

Non-vacuity: the predicate is load-bearing. The VULN fixture (nominal-amount
credit, config token) FIRES; the CLEAN fixture (measured-delta + decimals) is
silent (mutation-kill); the BENIGN ETH-only fixture is silent (FP-guard).
test_predicate_is_load_bearing MUTATES the covered-control predicate and shows
the CLEAN fixture then starts firing - i.e. the check is not vacuously true.
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "E8"


def _load():
    spec = importlib.util.spec_from_file_location("cmb_e8", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["cmb_e8"] = m
    spec.loader.exec_module(m)
    return m


def _fns(hits):
    return {h["function"] for h in hits}


class TestTokenBehaviorAxis(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _scan(self, name):
        src = (_FIX / name).read_text()
        return self.m.scan_token_behavior(src, name)

    def test_vuln_fires(self):
        hits = self._scan("vuln.sol")
        self.assertIn("receiveStakeAsset", _fns(hits))
        row = next(h for h in hits if h["function"] == "receiveStakeAsset")
        self.assertEqual(row["verdict"], "needs-fuzz")
        self.assertTrue(row["advisory"])
        self.assertEqual(row["sub_axis"], "token_behavior")
        self.assertIn("measured-delta", row["missing_invariant"])
        self.assertIn("decimal-normalized", row["missing_invariant"])

    def test_clean_silent(self):
        # measured-delta + decimals present -> covered control, no row.
        self.assertEqual(self._scan("clean.sol"), [])

    def test_benign_eth_silent(self):
        # ETH-asset path carries no transferFrom -> FP-guard keeps it silent.
        self.assertEqual(self._scan("benign_eth.sol"), [])

    def test_missing_only_decimals_fires(self):
        # A fn that measures the delta but does NOT normalize decimals must still
        # fire - the decimal-normalized axis is the net-new requirement over the
        # existing FOT/deflation detectors (which only cover measured-delta).
        src = (_FIX / "clean.sol").read_text()
        # strip the decimals normalization only
        src2 = re.sub(r"uint scale = .*?;", "", src)
        src2 = src2.replace("stake_asset_amount / scale", "stake_asset_amount")
        hits = self.m.scan_token_behavior(src2, "half.sol")
        self.assertIn("receiveStakeAsset", _fns(hits))
        row = next(h for h in hits if h["function"] == "receiveStakeAsset")
        self.assertEqual(row["missing_invariant"], "decimal-normalized")

    def test_predicate_is_load_bearing(self):
        # MUTATE the covered-control predicate (force has_delta False): the CLEAN
        # fixture must then start firing. Proves the covered-control gate is what
        # keeps it silent - the predicate is not vacuously satisfied.
        orig = self.m._TB_DELTA_RE
        try:
            self.m._TB_DELTA_RE = re.compile(r"__never_matches_anything__")
            hits = self._scan("clean.sol")
            self.assertIn("receiveStakeAsset", _fns(hits))
        finally:
            self.m._TB_DELTA_RE = orig
        # restored: clean is silent again
        self.assertEqual(self._scan("clean.sol"), [])


if __name__ == "__main__":
    unittest.main()
