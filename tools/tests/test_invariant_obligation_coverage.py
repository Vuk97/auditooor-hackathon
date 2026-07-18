#!/usr/bin/env python3
"""Regression: per-item invariant-obligation coverage - every value-moving asset's
DERIVED invariant obligation (from value_moving_functions + per_fn question_class)
must be TESTED (mutation-verified enumerated category) or DISPOSITIONED.

Operator 2026-07-07: ties the audit's OWN produced per-item material to an
invariant-coverage requirement so "all invariants held" is falsifiable. Validated
live: strata 10/10 covered; nuva 2 open, morpho 41, beanstalk 67 (real untested
value-moving surface the old gates passed)."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("ioc", _H.parent / "invariant-obligation-coverage.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


class T(unittest.TestCase):
    def _ws(self, vm_funcs, enum=None, disp=None, questions=None):
        ws = Path(tempfile.mkdtemp())
        a = ws / ".auditooor"
        a.mkdir(parents=True)
        (a / "value_moving_functions.json").write_text(json.dumps({"functions": vm_funcs}))
        if enum is not None:
            (a / "completeness_matrix.json").write_text(json.dumps({"asset_rows": enum}))
        if disp is not None:
            (a / "non_economic_dispositions.json").write_text(json.dumps({"dispositions": disp}))
        if questions is not None:
            (a / "per_fn_hacker_questions.jsonl").write_text(
                "\n".join(json.dumps(q) for q in questions))
        return ws

    def test_value_moving_floor_open_when_untested(self):
        ws = self._ws([{"file": "src/Foo.sol", "transfer_hit": True}])
        r = m.check(ws)
        # transfer_hit -> conservation + custody required, none enumerated -> 2 open
        self.assertEqual(r["open_count"], 2)
        cats = {o["required_category"] for o in r["open"]}
        self.assertEqual(cats, {"conservation", "custody"})

    def test_covered_when_enumerated(self):
        ws = self._ws(
            [{"file": "src/Foo.sol", "transfer_hit": True}],
            enum=[{"asset_id": "src/Foo.sol", "invariant_enumeration": {
                "conservation": {"status": "enumerated"}, "custody": {"status": "enumerated"}}}])
        self.assertEqual(m.check(ws)["verdict"], "pass-obligations-covered")

    def test_covered_when_dispositioned(self):
        ws = self._ws([{"file": "src/Foo.sol", "transfer_hit": True}],
                      disp=[{"cut_path": "src/Foo.sol"}])
        self.assertEqual(m.check(ws)["verdict"], "pass-obligations-covered")

    def test_question_class_enriches(self):
        # sum-preserved -> conservation (already floored); unguarded is custody; add a
        # ledger-only asset whose question raises atomicity.
        ws = self._ws(
            [{"file": "src/Bar.sol", "ledger_write_hit": True}],
            questions=[{"file": "src/Bar.sol:10", "question_class": "unguarded-low_level_call"}])
        r = m.check(ws)
        cats = {o["required_category"] for o in r["open"]}
        self.assertIn("conservation", cats)   # from ledger floor
        self.assertIn("atomicity", cats)       # enriched from question_class

    def test_no_value_moving_is_pass(self):
        ws = self._ws([{"file": "src/View.sol"}])  # no hits
        self.assertEqual(m.check(ws)["verdict"], "pass-no-obligations")

    def test_strict_fails_on_open(self):
        ws = self._ws([{"file": "src/Foo.sol", "transfer_hit": True}])
        os.environ["AUDITOOOR_INVARIANT_OBLIGATION_STRICT"] = "1"
        try:
            self.assertEqual(m.check(ws)["verdict"], "fail-invariant-obligation-uncovered")
        finally:
            del os.environ["AUDITOOOR_INVARIANT_OBLIGATION_STRICT"]


if __name__ == "__main__":
    unittest.main()
