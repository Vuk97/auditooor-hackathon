"""Regression for hunt-failure-breakdown.py - makes a 0-finding hunt auditable
by categorizing every 'no' verdict (question-inapplicable / unanchored-r76 /
axis-* / genuine-safe). Anchor: zebra's 1700 verdicts were 79% question-
inapplicable (EVM questions on a Zcash node), not target safety.
"""
import importlib.util, sys, unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-failure-breakdown.py"


def _load():
    spec = importlib.util.spec_from_file_location("hfb", _T)
    m = importlib.util.module_from_spec(spec); sys.modules["hfb"] = m
    spec.loader.exec_module(m); return m


H = _load()


class TestBreakdown(unittest.TestCase):
    def c(self, **kw):
        return H.categorize(kw)

    def test_question_inapplicable(self):
        self.assertEqual(self.c(applies_to_target="no",
            notes="Hypothesis is tailored to EVM smart contract bridges; Zebra is Zcash"),
            "question-inapplicable")

    def test_unanchored(self):
        self.assertEqual(self.c(applies_to_target="no", file_path_hint="NA",
            notes="could be an issue"), "unanchored-r76")

    def test_axis_impact(self):
        self.assertEqual(self.c(applies_to_target="no", file_path_hint="x.rs:10",
            notes="this is self-harm / below threshold, attacker hurts own quota"),
            "axis-IMPACT")

    def test_axis_original(self):
        self.assertEqual(self.c(applies_to_target="no", file_path_hint="x.rs:10",
            notes="this is designed as intended, peers untrusted by design"),
            "axis-ORIGINAL")

    def test_genuine_safe(self):
        self.assertEqual(self.c(applies_to_target="no", file_path_hint="x.rs:10",
            notes="the code correctly validates the input, already guarded"),
            "genuine-safe")

    def test_candidate_maybe_surfaced(self):
        self.assertEqual(self.c(applies_to_target="maybe", notes="x"), "candidate-maybe")


if __name__ == "__main__":
    unittest.main()
