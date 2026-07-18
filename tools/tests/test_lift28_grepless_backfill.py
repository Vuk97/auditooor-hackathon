"""Guard: A2a - grep-less hacker-Q rows are back-derived a function pattern.

(a) a grep-less row whose question_text/anchor implies a role gains
    target_function_patterns (so corpus-driven-hunt no longer drops it on the
    empty-needle guard);
(b) a structural meta row (codified-rule / postmortem-rule) is flagged
    non_targetable_meta with NO function pattern (routed to a rubric lane, not
    mislabeled);
(c) a row that already has grep_patterns is unchanged (no regression).
"""
import importlib.util
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[1] / "lib" / "per_function_target_patterns.py"


def _load():
    spec = importlib.util.spec_from_file_location("pftp", LIB)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestGreplessBackfill(unittest.TestCase):
    def test_grepless_row_recovers_function_patterns(self):
        m = _load()
        rec = {
            "question_text": "Can withdraw be called to settle and drain before finalize?",
            "attack_class_anchor": "settlement-bypass",
            "grep_patterns": [],
        }
        out = m.enrich_hacker_question_record(rec)
        self.assertTrue(out["target_function_patterns"],
                        "grep-less row with role signal must recover fn patterns")
        self.assertNotIn("non_targetable_meta", out)

    def test_structural_meta_row_flagged_not_targeted(self):
        m = _load()
        rec = {"question_text": "Generic rubric reminder", "attack_class_anchor": "rule-7",
               "source_incident_id": "codified-rule-12", "grep_patterns": []}
        out = m.enrich_hacker_question_record(rec)
        self.assertEqual(out["target_function_patterns"], [])
        self.assertTrue(out.get("non_targetable_meta"))
        self.assertEqual(out["scope_specificity"], m.SCOPE_WORKSPACE)

    def test_payload_row_unchanged(self):
        m = _load()
        rec = {"question_text": "q", "attack_class_anchor": "x", "grep_patterns": ["transferFrom"]}
        out = m.enrich_hacker_question_record(rec)
        self.assertTrue(out["target_function_patterns"])
        self.assertNotIn("non_targetable_meta", out)


if __name__ == "__main__":
    unittest.main()
