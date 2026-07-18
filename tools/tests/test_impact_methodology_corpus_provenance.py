#!/usr/bin/env python3
"""Tests for the impact-methodology CORPUS-PROVENANCE gate
(tools/impact-methodology-corpus-provenance-check.py).

Closes the coverage-theater hole where the impact-methodology capability was
present in the dispatch brief + counted as resolved, while the persisted per-fn
corpus carried ZERO impact rows (SSV June-23) and audit-complete still went green.

Proves:
  - FAIL provenance: value-moving functions in scope but 0 impact rows.
  - FAIL specialization: impact rows present but generic (not fn-bound).
  - PASS: impact rows present and fn-bound on a value surface.
  - NA: no corpus, or a pure-view surface (no value-moving function).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "impact-methodology-corpus-provenance-check.py"
_s = importlib.util.spec_from_file_location("impact_corpus_prov", _T)
mod = importlib.util.module_from_spec(_s)
sys.modules["impact_corpus_prov"] = mod
_s.loader.exec_module(mod)


def _ws(rows: list[dict]) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / ".auditooor").mkdir(parents=True)
    (d / ".auditooor" / "per_fn_hacker_questions.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return d


class ImpactCorpusProvenanceTest(unittest.TestCase):
    def test_fail_provenance_value_surface_no_impact(self):
        rows = [
            {"function": "withdraw", "question": "conservation?", "question_class": "generic"},
            {"function": "liquidate", "question": "solvency?", "question_class": "generic"},
        ]
        res = mod.check(_ws(rows))
        self.assertEqual(res["verdict"], mod.VERDICT_FAIL_PROVENANCE)

    def test_fail_specialization_generic_impact_rows(self):
        rows = [
            {"function": "withdraw", "question": "conservation?", "question_class": "generic"},
            # impact rows present but NOT fn-bound (generic prose)
            {"function": "withdraw", "question": "Can a fresh EOA call a custody fn?",
             "question_source": "impact-methodology", "impact_id": "direct-theft-funds"},
            {"function": "withdraw", "question": "Is from caller-supplied?",
             "question_source": "impact-methodology", "impact_id": "direct-theft-funds"},
        ]
        res = mod.check(_ws(rows))
        self.assertEqual(res["verdict"], mod.VERDICT_FAIL_SPECIALIZATION)

    def test_pass_fnbound_impact_on_value_surface(self):
        rows = [
            {"function": "withdraw", "question": "conservation?", "question_class": "generic"},
            {"function": "withdraw", "question": "On `withdraw`: custody release?",
             "question_source": "impact-methodology", "impact_id": "direct-theft-funds"},
            {"function": "withdraw", "question": "On `withdraw`: from caller-supplied?",
             "question_source": "impact-methodology", "impact_id": "direct-theft-funds"},
        ]
        res = mod.check(_ws(rows))
        self.assertEqual(res["verdict"], mod.VERDICT_PASS)

    def test_na_view_only_surface(self):
        rows = [
            {"function": "getBalance", "question": "view?", "question_class": "generic"},
            {"function": "getBurnRate", "question": "view?", "question_class": "generic"},
        ]
        res = mod.check(_ws(rows))
        self.assertEqual(res["verdict"], mod.VERDICT_NA)

    def test_na_no_corpus(self):
        d = Path(tempfile.mkdtemp())
        res = mod.check(d)
        self.assertEqual(res["verdict"], mod.VERDICT_NA)

    def test_rc_nonzero_only_on_fail(self):
        # main() returns rc 0 for PASS/NA, 1 for any FAIL
        rows = [{"function": "withdraw", "question": "x", "question_class": "generic"}]
        ws = _ws(rows)
        self.assertEqual(mod.main([str(ws), "--json"]), 1)
        view = _ws([{"function": "getBalance", "question": "v"}])
        self.assertEqual(mod.main([str(view), "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
