#!/usr/bin/env python3
"""Batch-2 learning-loop cross-wires into per-fn-question-ranker:
#8  impact_severity_hint -> severity_boost (Critical/High leads outrank low ones).
#13 load_invariant_index also reads the PER-RECORD invariants_extracted*.jsonl so
    tier_score is not dead (the aggregate index often had 0 per-record rows).
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "per-fn-question-ranker.py"
_s = importlib.util.spec_from_file_location("per_fn_question_ranker", _T)
m = importlib.util.module_from_spec(_s)
sys.modules["per_fn_question_ranker"] = m
try:
    _s.loader.exec_module(m)
except SystemExit:
    pass


def _score(hint):
    q = {"question": "q", "function": "withdraw", "file": "x.sol",
         "question_class": "generic", "anchor_invariant": "", "impact_severity_hint": hint}
    return m.score_question(q, [], [], {}, {}, {}, None)


class RankerSeverityBoostTest(unittest.TestCase):
    def test_severity_boost_scale(self):
        self.assertEqual(_score("Critical")["score_breakdown"]["severity_boost"], 2.0)
        self.assertEqual(_score("High")["score_breakdown"]["severity_boost"], 1.0)
        self.assertEqual(_score("Medium")["score_breakdown"]["severity_boost"], 0.3)

    def test_absent_hint_zero_and_legacy_safe(self):
        self.assertEqual(_score("")["score_breakdown"]["severity_boost"], 0.0)
        # a question with no impact_severity_hint key at all is unaffected
        q = {"question": "q", "function": "f", "file": "x.sol",
             "question_class": "generic", "anchor_invariant": ""}
        self.assertEqual(m.score_question(q, [], [], {}, {}, {}, None)
                         ["score_breakdown"]["severity_boost"], 0.0)

    def test_critical_outranks_low(self):
        self.assertGreater(_score("Critical")["score"], _score("")["score"])


class RankerInvTierTest(unittest.TestCase):
    def test_invariant_index_reads_per_record_extracted(self):
        idx = m.load_invariant_index()
        # the per-record extracted file populates many INV ids with real tiers
        self.assertGreater(len(idx), 100,
                           "inv tier index should be populated from invariants_extracted")
        # every value is a recognizable tier string
        self.assertTrue(all(str(t).startswith("tier-") for t in idx.values()))


if __name__ == "__main__":
    unittest.main()
