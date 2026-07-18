#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-RULE-INVENTORY-PARITY registered in .auditooor/agent_pathspec.json -->
"""Tests for r-rule-inventory-parity-check.py (DELTA-1 closure gate)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "r-rule-inventory-parity-check.py"
_spec = importlib.util.spec_from_file_location("rrule_parity", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

ROOT = Path(__file__).resolve().parent.parent.parent


class TestRuleIdParse(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(mod._rule_id_from_check_name("R76-HALLUCINATION-GUARD"), "R76")

    def test_gap_alnum(self):
        self.assertEqual(mod._rule_id_from_check_name("GAP37B-SALVAGE-NEGATION-VERDICT"), "GAP37B")

    def test_multi_rule_takes_first(self):
        self.assertEqual(mod._rule_id_from_check_name("R18/R19/L32"), "R18")

    def test_non_rule_family_none(self):
        self.assertIsNone(mod._rule_id_from_check_name("FINAL-PASTE-FORM"))
        self.assertIsNone(mod._rule_id_from_check_name("HACKENPROOF-POC"))


class TestEvaluate(unittest.TestCase):
    def _write(self, d, pre_lines, inv_rows):
        p = Path(d) / "pre.sh"
        p.write_text("\n".join(pre_lines))
        iv = Path(d) / "inv.jsonl"
        iv.write_text("\n".join(json.dumps({"rule_id": r}) for r in inv_rows))
        return p, iv

    def test_complete_passes(self):
        with tempfile.TemporaryDirectory() as d:
            p, iv = self._write(d, ["# Check #106: R59-ANTIPATTERN-ATTRIBUTION (Rule 59)"], ["R59"])
            res = mod.evaluate(p, iv)
            self.assertEqual(res["verdict"], "pass-inventory-complete")
            self.assertEqual(res["wired_rule_family_checks"], 1)

    def test_missing_row_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p, iv = self._write(d, ["# Check #125: R76-HALLUCINATION-GUARD (Rule R76)"], ["R59"])
            res = mod.evaluate(p, iv)
            self.assertEqual(res["verdict"], "fail-inventory-missing-rows")
            self.assertEqual(res["missing_from_inventory"][0]["rule_id"], "R76")
            self.assertEqual(res["missing_from_inventory"][0]["check_number"], "125")

    def test_non_rule_headers_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            p, iv = self._write(d, ["# Check #7: FINAL-PASTE-FORM", "# Check #106: R59-X (Rule 59)"], ["R59"])
            res = mod.evaluate(p, iv)
            self.assertEqual(res["verdict"], "pass-inventory-complete")
            self.assertEqual(res["wired_rule_family_checks"], 1)

    def test_missing_input_errors(self):
        with tempfile.TemporaryDirectory() as d:
            res = mod.evaluate(Path(d) / "nope.sh", Path(d) / "nope.jsonl")
            self.assertEqual(res["verdict"], "error")


class TestLiveRepo(unittest.TestCase):
    """The live repo MUST stay at parity (this is the standing CI guard)."""

    def test_live_inventory_is_complete(self):
        pre = ROOT / "tools" / "pre-submit-check.sh"
        inv = ROOT / "reference" / "r_rules_inventory.jsonl"
        if not (pre.is_file() and inv.is_file()):
            self.skipTest("live artifacts not present")
        res = mod.evaluate(pre, inv)
        self.assertEqual(
            res["verdict"], "pass-inventory-complete",
            msg=f"inventory drifted: {res.get('missing_from_inventory')}",
        )


if __name__ == "__main__":
    unittest.main()
