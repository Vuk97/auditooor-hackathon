"""The global-rule-admission gate BLOCKS a new global rule not admitted across
>= N workspaces (reverse-evolution enforcement), unless an operator marker."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parents[1]
def _load(n, f):
    s = importlib.util.spec_from_file_location(n, _T / f)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
G = _load("global_rule_admission_gate", "global-rule-admission-gate.py")
RA = _load("review_attribution", "review_attribution.py")


class TestAdmissionGate(unittest.TestCase):
    def setUp(self):
        RA.LEDGER = Path(tempfile.mkdtemp()) / "led.jsonl"
        G._review_attribution = lambda: RA

    def test_new_rule_blocked_when_not_admitted(self):
        lines = ["+- **R99 shiny-new-rule** (Check #200): do the thing"]
        rep = G.scan_added_lines(lines, threshold=3)
        self.assertEqual(rep["verdict"], "fail-unadmitted-global-rule")
        self.assertEqual(rep["violations"][0]["subject"], "rule:R99")

    def test_admitted_after_three_workspaces(self):
        for ws in ("a", "b", "c"):
            RA.record(ws, "rule:R99", "reasoning", ledger=RA.LEDGER)
        rep = G.scan_added_lines(["+- **R99 shiny-new-rule** (Check #200): do it"], threshold=3)
        self.assertEqual(rep["verdict"], "pass-admitted")

    def test_operator_marker_bypasses(self):
        lines = ["+- **R99 shiny** (Check #200): do it <!-- admitted: rule:R99 -->"]
        self.assertEqual(G.scan_added_lines(lines, threshold=3)["verdict"], "pass-admitted")

    def test_no_new_rule_passes(self):
        self.assertEqual(G.scan_added_lines(["+ just a normal code line"], threshold=3)["verdict"], "pass-admitted")

    def test_new_l37_signal_also_gated(self):
        lines = ['+    strict = _l37_gate_strict("BRAND_NEW_SIGNAL")']
        rep = G.scan_added_lines(lines, threshold=3)
        self.assertEqual(rep["verdict"], "fail-unadmitted-global-rule")
        self.assertEqual(rep["violations"][0]["subject"], "signal:BRAND_NEW_SIGNAL")


    def test_prose_mention_of_existing_rule_not_a_new_rule(self):
        """loop-caught 2026-07-01: a code COMMENT that merely mentions an
        existing rule/signal name (e.g. "the L37 signal", "matches R76
        hallucination") must NOT be treated as a new rule definition - only the
        CODIFIED_RULES_INDEX.md bullet shape `- **R99 title**` counts."""
        lines = [
            '+    # yet this verdict was OMITTED from the fail set, so the L37 signal',
            '+    # matches R76 hallucination guard semantics',
            '+    "fail-depth-stale",',
        ]
        rep = G.scan_added_lines(lines, threshold=3)
        self.assertEqual(rep["verdict"], "pass-admitted")
        self.assertEqual(rep["new_rule_subjects"], [])

    def test_real_bullet_still_caught_with_diff_plus_prefix(self):
        """The diff '+' add-marker must be stripped before bullet matching, not
        block it - a genuine new rule bullet inside a real git-diff line still
        fires."""
        lines = ['+- **R99 shiny-new-rule** (Check #200): do the thing']
        rep = G.scan_added_lines(lines, threshold=3)
        self.assertEqual(rep["verdict"], "fail-unadmitted-global-rule")


if __name__ == "__main__":
    unittest.main()
