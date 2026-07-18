#!/usr/bin/env python3
"""Regression: render_impact_questions must be FUNCTION-SPECIALIZED.

Before this fix the renderer's kind-only UNION arm attached every contract-kind-
matched playbook to EVERY function in a DeFi contract, and emitted the corpus
prose verbatim - so registerValidator (not a custody fn) got the SAME custody-
release questions as withdraw/liquidate, with no function binding (the SSV
finding). The fix: gate the kind-only rescue to functions the shape classifier
genuinely missed, and bind each question to its function.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hacker_question_renderer.py"
_s = importlib.util.spec_from_file_location("hqr_spec", _T)
hqr = importlib.util.module_from_spec(_s)
sys.modules["hqr_spec"] = hqr
_s.loader.exec_module(hqr)

_SCOPE = "SSV DVT staking: clusters, operators, validators, liquidation, earnings withdrawal"


def _ids(fn, sig):
    qs = hqr.render_impact_questions(
        function_name=fn, function_signature=sig, language="solidity",
        scope_text=_SCOPE, file_path="contracts/X.sol", max_questions=6)
    return qs


class RendererSpecializationTest(unittest.TestCase):
    def test_questions_are_function_bound(self):
        qs = _ids("withdrawOperatorEarnings",
                  "withdrawOperatorEarnings(uint64 operatorId,uint256 amount)")
        self.assertTrue(qs, "a withdrawal must attach fund-theft impact questions")
        for q in qs:
            self.assertIn("withdrawOperatorEarnings", q["question"],
                          "every impact question must name its function")

    def test_register_validator_not_sprayed_with_custody(self):
        qs = _ids("registerValidator",
                  "registerValidator(bytes pk,uint64[] ids,bytes s,Cluster c) external payable")
        ids = {q.get("impact_id") for q in qs}
        # registerValidator is NOT a custody-release fn -> must NOT get the
        # direct-theft/custody-release impact (the old spray bug).
        self.assertNotIn("direct-theft-funds", ids,
                         "custody-release impact wrongly sprayed onto registerValidator")

    def test_view_function_gets_nothing(self):
        qs = _ids("getBalance", "getBalance(address o,uint64[] ids) view returns (uint256)")
        self.assertEqual(qs, [], "a pure view function must attach no fund-theft questions")

    def test_distinct_functions_get_distinct_text(self):
        liq = {q["question"] for q in _ids("liquidate",
               "liquidate(address o,uint64[] ids,Cluster c)")}
        wd = {q["question"] for q in _ids("withdrawOperatorEarnings",
              "withdrawOperatorEarnings(uint64 id,uint256 amount)")}
        self.assertTrue(liq and wd)
        self.assertFalse(liq & wd, "two different functions emitted identical question text")

    def test_value_moving_predicate(self):
        self.assertTrue(hqr._function_is_value_moving_ish("withdraw", ""))
        self.assertTrue(hqr._function_is_value_moving_ish("foo", "foo() external payable"))
        self.assertTrue(hqr._function_is_value_moving_ish("foo", "foo(uint256 amount)"))
        self.assertFalse(hqr._function_is_value_moving_ish("getBurnRate", "getBurnRate() view"))

    def test_bind_helper_honors_placeholder(self):
        self.assertEqual(hqr._bind_question_to_fn("check {fn} now", "liquidate"),
                         "check liquidate now")
        self.assertTrue(hqr._bind_question_to_fn("generic q", "liquidate")
                        .startswith("On `liquidate`:"))
        self.assertEqual(hqr._bind_question_to_fn("q", ""), "q")


if __name__ == "__main__":
    unittest.main()
