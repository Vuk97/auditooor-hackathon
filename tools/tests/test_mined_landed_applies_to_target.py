#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-MINED-LANDED-APPLIES registered via agent-pathspec-register.py -->
"""Guard: mined-landed parity recognises the per-function/MIMO hunt schema's
`applies_to_target` field as a determinable verdict.

Regression for the morpho-midnight mined-landed false-red: 9 sidecars with
`applies_to_target: "no"` (adjudicated FP) were scored "no determinable
verdict" -> permanent un-landed LEARNING_DEBT, because _verdict_bucket read
only verdict/disposition/outcome/kill_verdict. "no" -> refuted, "yes" ->
confirmed; an explicit confirmed/refuted marker still wins.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("mlpb", str(_TOOLS / "mined-landed-parity-build.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["mlpb"] = m
spec.loader.exec_module(m)


class TestAppliesToTargetVerdict(unittest.TestCase):
    def test_applies_no_is_refuted(self):
        self.assertEqual(m._verdict_bucket({"applies_to_target": "no", "candidate_finding": "NA"}), "refuted")

    def test_applies_yes_is_confirmed(self):
        self.assertEqual(m._verdict_bucket({"applies_to_target": "yes"}), "confirmed")

    def test_no_applies_field_stays_undetermined(self):
        self.assertIsNone(m._verdict_bucket({"candidate_finding": "maybe a rounding issue"}))

    def test_explicit_confirmed_marker_wins_over_applies_no(self):
        # a sidecar that is applies=no but carries a CONFIRMED verdict must not be buried as refuted
        self.assertEqual(
            m._verdict_bucket({"applies_to_target": "no", "verdict": "confirmed"}), "confirmed")

    def test_explicit_refuted_marker_still_refuted(self):
        self.assertEqual(m._verdict_bucket({"disposition": "false-positive"}), "refuted")


if __name__ == "__main__":
    unittest.main(verbosity=2)
