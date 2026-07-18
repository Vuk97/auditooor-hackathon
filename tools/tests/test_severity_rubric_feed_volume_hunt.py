"""test_severity_rubric_feed_volume_hunt.py

Guards the wave-4 uplift "severity-rubric-feed-volume-hunt": the program's
PAYABLE SEVERITY.md rows must reach the per-fn VOLUME hunt, instead of the hunt
staying generic on the rubric axis.

Two tools cooperate:

  * tools/per-function-hacker-questions.py  -- parses SEVERITY.md via
    tools/lib/severity_rubric.parse_tier_rows(), emits ONE targeted question per
    payable row per function, and tags every question whose attack_class maps to
    a payable row with payable_match=True + rubric provenance.

  * tools/per-fn-question-ranker.py  -- boosts a payable_match question so it
    ranks above a generic one.

SPEC guard (from the task): given a SEVERITY.md with 2 payable rows, the
generated questions include >=1 question per row, and a row-mapped question
ranks above a generic one.

These tests import the modules directly and feed in-memory fixtures - no network,
no MCP, no LLM. AUDITOOOR_MCP_REQUIRED=0 is set so the import side has no MCP dep.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("AUDITOOOR_MCP_REQUIRED", "0")

TOOLS_DIR = Path(__file__).resolve().parent.parent
GEN_TOOL = TOOLS_DIR / "per-function-hacker-questions.py"
RANK_TOOL = TOOLS_DIR / "per-fn-question-ranker.py"


def _load(name: str, path: Path):
    # Ensure tools/ is importable so the generator's `from lib.severity_rubric`
    # import resolves the SAME way it does when run as a script.
    sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


GEN = _load("pfhq_under_test", GEN_TOOL)
RANK = _load("ranker_under_test", RANK_TOOL)


# A minimal two-payable-row SEVERITY.md in the dydx em-dash heading shape that
# parse_tier_rows() recognises. The two bullets are the two PAYABLE rows.
SEVERITY_MD_TWO_ROWS = """# Severity Classification

### Critical - **USD 100,000 to 1,000,000**
- Incorrectly proven withdrawal allowing theft of bridged user funds

### High - **USD 25,000 to 100,000**
- Unauthorized access to a privileged admin function
"""


def _parse_payable(text: str):
    """Helper: write text to a temp SEVERITY.md and return the parsed payable
    rows via the generator's own loader (exercises the real call path)."""
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "SEVERITY.md"
    p.write_text(text, encoding="utf-8")
    return GEN.load_payable_rubric_rows(p), p


class TestRubricFeedsGeneration(unittest.TestCase):
    """The payable rubric rows must reach question generation."""

    def test_two_payable_rows_parsed(self):
        rows, _ = _parse_payable(SEVERITY_MD_TWO_ROWS)
        # Exactly the two payable bullet rows (one per tier heading here).
        sentences = [r.sentence.lower() for r in rows]
        self.assertTrue(
            any("incorrectly proven withdrawal" in s for s in sentences),
            f"Critical payable row not parsed; got {sentences}",
        )
        self.assertTrue(
            any("unauthorized access" in s for s in sentences),
            f"High payable row not parsed; got {sentences}",
        )
        self.assertGreaterEqual(len(rows), 2)

    def test_at_least_one_question_per_payable_row(self):
        """SPEC: >=1 generated question per payable row on a relevant fn."""
        rows, _ = _parse_payable(SEVERITY_MD_TWO_ROWS)
        fn_record = {
            "function": "proveWithdrawalTransaction",
            "file": "L1/OptimismPortal.sol",
            "language": "solidity",
            "invariant_candidates": ["access-control-missing-1"],
        }
        qs = GEN.gen_questions(fn_record, rows)
        # Every payable row id must appear at least once among the questions.
        row_ids = {GEN._rubric_row_id(r) for r in rows}
        emitted_row_ids = {
            q.get("rubric_row_id")
            for q in qs
            if q.get("question_source") == "rubric-row-targeted"
        }
        missing = row_ids - emitted_row_ids
        self.assertEqual(
            missing, set(),
            f"Every payable row needs >=1 targeted question; missing {missing}",
        )
        # And those targeted questions are tagged payable_match.
        for q in qs:
            if q.get("question_source") == "rubric-row-targeted":
                self.assertTrue(q.get("payable_match"))
                self.assertIn(q.get("rubric_tier"), ("critical", "high"))

    def test_class_mapped_template_question_is_tagged(self):
        """A synth-template question whose class maps to a payable row gets
        payable_match=True + the row provenance (so the ranker can boost it)."""
        rows, _ = _parse_payable(SEVERITY_MD_TWO_ROWS)
        fn_record = {
            "function": "adminSetGuardian",
            "file": "L1/SystemConfig.sol",
            "language": "solidity",
            # access-control-missing maps to the "unauthorized access" payable row
            "invariant_candidates": ["access-control-missing-1"],
        }
        qs = GEN.gen_questions(fn_record, rows)
        tagged_templates = [
            q for q in qs
            if q.get("question_source") == "synth-template"
            and q.get("payable_match")
        ]
        self.assertTrue(
            tagged_templates,
            "An access-control template question should be tagged payable_match "
            "(it maps to the 'unauthorized access' payable row)",
        )
        for q in tagged_templates:
            self.assertEqual(q.get("question_class"), "access-control-missing")
            self.assertTrue(q.get("rubric_row_id"))

    def test_no_severity_md_stays_generic(self):
        """Back-compat: with no payable rows, no payable_match tags and no
        rubric-row-targeted questions are emitted."""
        fn_record = {
            "function": "deposit",
            "file": "Vault.sol",
            "language": "solidity",
            "invariant_candidates": ["reentrancy-1"],
        }
        qs = GEN.gen_questions(fn_record, [])  # no rubric
        self.assertTrue(qs, "should still emit template questions")
        self.assertFalse(
            any(q.get("payable_match") for q in qs),
            "no rubric => no payable_match tags",
        )
        self.assertFalse(
            any(q.get("question_source") == "rubric-row-targeted" for q in qs),
            "no rubric => no rubric-row-targeted questions",
        )


class TestRankerBoostsRubricMapped(unittest.TestCase):
    """A row-mapped question must rank above a generic one."""

    def _score(self, q):
        return RANK.score_question(q, [], [], {}, {}, {})

    def test_rubric_mapped_outranks_generic_even_on_lower_surface(self):
        """SPEC: a row-mapped question ranks above a generic one.

        The rubric question is placed on a LOWER-surface (internal) function so
        the test proves the boost - not the surface score - is what wins.
        """
        generic = {
            "question": "Can deposit be exploited generically?",
            "function": "deposit",
            "file": "Vault.sol",
            "question_class": "generic",
            "anchor_invariant": "",
            "callable_surface": "external",
            "function_visibility": "external",
        }
        rubric = {
            "question": "Payable rubric row crit-1: realize the impact.",
            "function": "_settle",
            "file": "Vault.sol",
            "question_class": "sum-preserved",
            "anchor_invariant": "crit-1",
            "callable_surface": "internal",
            "function_visibility": "internal",
            "payable_match": True,
            "question_source": "rubric-row-targeted",
            "rubric_row_id": "crit-1",
            "rubric_tier": "critical",
        }
        sg = self._score(generic)
        sr = self._score(rubric)
        self.assertEqual(sg["verdict"], "rank-eligible")
        self.assertEqual(sr["verdict"], "rank-eligible")
        self.assertGreater(
            sr["score"], sg["score"],
            f"rubric-mapped ({sr['score']}) must outrank generic ({sg['score']})",
        )
        self.assertGreater(sr["score_breakdown"]["rubric_boost"], 0.0)
        self.assertEqual(sg["score_breakdown"]["rubric_boost"], 0.0)

    def test_no_boost_without_payable_match(self):
        """A question without payable_match gets zero rubric_boost (no false
        boost of unrelated generic questions)."""
        q = {
            "question": "generic",
            "function": "f",
            "file": "a.sol",
            "question_class": "reentrancy",
            "anchor_invariant": "",
            "callable_surface": "external",
            "function_visibility": "external",
        }
        r = self._score(q)
        self.assertEqual(r["score_breakdown"]["rubric_boost"], 0.0)


class TestCapPreservesRubricRows(unittest.TestCase):
    """The per-fn cap must NOT drop rubric-row-targeted questions (every payable
    row keeps its candidate even under a tight budget)."""

    def test_tight_cap_keeps_all_rubric_rows(self):
        rows, _ = _parse_payable(SEVERITY_MD_TWO_ROWS)
        fn_record = {
            "function": "proveWithdrawalTransaction",
            "file": "L1/OptimismPortal.sol",
            "language": "solidity",
            # Several template invariants to fill the budget and try to starve
            # the appended rubric-row questions.
            "invariant_candidates": [
                "reentrancy-1", "access-control-missing-1", "sum-conservation-1",
            ],
        }
        qs = GEN.gen_questions(fn_record, rows)
        capped = GEN._cap_questions(qs, cap=2)  # tighter than #rubric rows
        kept_row_ids = {
            q.get("rubric_row_id")
            for q in capped
            if q.get("question_source") == "rubric-row-targeted"
        }
        all_row_ids = {GEN._rubric_row_id(r) for r in rows}
        self.assertEqual(
            kept_row_ids, all_row_ids,
            "every payable row must survive the cap; "
            f"kept {kept_row_ids} of {all_row_ids}",
        )


if __name__ == "__main__":
    unittest.main()
