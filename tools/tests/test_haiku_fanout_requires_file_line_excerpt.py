#!/usr/bin/env python3
"""Regression (G10): the haiku-fanout dispatcher template MUST list file_line +
code_excerpt as REQUIRED verdict keys.

Before 2026-06-27 the dispatcher's "verdict typically requires keys" list named
file_path_hint but NOT file_line/code_excerpt. Agents anchored on this outer list
(not the per-task inner spec) and emitted clean rule-outs (applies_to_target='no')
with no file_line/code_excerpt. function-coverage-completeness credits an
applies_to_target='no' rule-out as genuine coverage ONLY with a same-file file_line
cite (R80: bare prose -> hollow), and the R76 guard greps code_excerpt against real
source. So 30 real morpho rule-outs landed UNCREDITED (function stayed hollow) - the
"N hollow despite a real hunt" symptom. The template must require both keys + explain
that omitting them silently wastes the hunt.
"""
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "haiku-fanout-dispatcher.py").read_text(encoding="utf-8")


class HaikuFanoutRequiresFileLineExcerptTest(unittest.TestCase):
    def test_required_keys_include_file_line_and_code_excerpt(self):
        # The required-keys instruction block must name both.
        self.assertIn("file_line", SRC)
        self.assertIn("code_excerpt", SRC)

    def test_mandatory_for_clean_ruleout(self):
        # Must explain they are required even for applies_to_target='no'.
        low = SRC.lower()
        self.assertIn("applies_to_target='no'", SRC)
        self.assertTrue(
            "mandatory for coverage credit" in low or "required on every verdict" in low,
            "template must state file_line/code_excerpt are MANDATORY for coverage credit")

    def test_explains_uncredited_consequence(self):
        low = SRC.lower()
        self.assertTrue(
            "hollow" in low and ("uncredited" in low or "wastes the hunt" in low),
            "template must warn that omitting the cite drops the verdict to hollow")


if __name__ == "__main__":
    unittest.main()
