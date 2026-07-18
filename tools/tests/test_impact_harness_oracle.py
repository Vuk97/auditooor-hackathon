#!/usr/bin/env python3
"""Cross-wire #1: the EVM harness author biases its oracle categories by each
function's IMPACT class (impact-methodology renderer), so the generated harness
asserts the property that catches the hypothesized impact - not only name keywords.
Always-on + fail-open (renderer absent -> empty -> legacy name-only behavior).
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "evm-engine-harness-author.py"
_s = importlib.util.spec_from_file_location("evm_engine_harness_author", _T)
m = importlib.util.module_from_spec(_s)
sys.modules["evm_engine_harness_author"] = m
try:
    _s.loader.exec_module(m)
except SystemExit:
    pass


class ImpactHarnessOracleTest(unittest.TestCase):
    def test_impact_map_targets_real_categories(self):
        cats = set()
        for v in m._IMPACT_TO_CATEGORIES.values():
            cats.update(v)
        self.assertTrue(cats.issubset(set(m._CATEGORY_INVARIANT.keys())),
                        "impact categories must be real oracle categories")
        self.assertEqual(m._IMPACT_TO_CATEGORIES["access-control-bypass"], ("authorization",))

    def test_withdraw_gets_theft_categories(self):
        c = m._impact_categories_for_fn("withdrawOperatorEarnings",
                                        "withdrawOperatorEarnings(uint64,uint256)")
        self.assertIn("conservation", c)
        self.assertIn("custody", c)

    def test_view_function_contributes_nothing(self):
        self.assertEqual(m._impact_categories_for_fn("getBalance",
                         "getBalance() view returns (uint256)"), set())

    def test_fail_open_when_renderer_absent(self):
        saved = m._IMPACT_RENDERER_FN
        m._IMPACT_RENDERER_FN = None  # simulate unavailable renderer
        try:
            self.assertEqual(m._impact_categories_for_fn("withdraw", ""), set())
        finally:
            m._IMPACT_RENDERER_FN = saved

    def test_griefing_dos_not_mapped(self):
        # generic DoS is OOS (R35) -> must not steer the oracle
        self.assertNotIn("griefing-dos", m._IMPACT_TO_CATEGORIES)


if __name__ == "__main__":
    unittest.main()
