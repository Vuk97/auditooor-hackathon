"""Tests for tools/worker-brief-completeness-check.py.

Covers every verdict branch:
  pass-brief-complete
  fail-missing-mcp-recall
  fail-missing-hunt-definition
  fail-missing-skip-set
  fail-missing-brain-prime
  fail-missing-hacker-questions
  ok-rebuttal
  error

Plus: multi-missing ordering, strict-recall context_pack_id value
requirement, rebuttal edge cases (empty / oversized), and main() exit codes.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "worker_brief_completeness_check",
    ROOT / "tools" / "worker-brief-completeness-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

evaluate = mod.evaluate
main = mod.main
SCHEMA = mod.SCHEMA
SECTION_ORDER = mod.SECTION_ORDER


# A complete brief carrying all five sections.
COMPLETE_BRIEF = """\
## MCP-FIRST RECALL (your first action)
Run vault_resume_context and vault_known_dead_ends.
context_pack_id: auditooor.resume.v1:abc123def456

## TASK / HUNT-DEFINITION
Hunt the cooperative-exit path for chain-watcher validation gaps.

## SKIP-SET
Consult hunt_skip_set.json and vault_known_dead_ends; skip already-filed.

## BRAIN-PRIME
vault_brain_prime_context seeds the attack-class mindset hints.

## HACKER QUESTIONS
Traverse the top hacker-questions (vault_hacker_questions) against the target.
"""


def _brief_missing(section: str) -> str:
    """Build a brief that has every section EXCEPT the named one."""
    blocks = {
        "mcp-recall": "context_pack_id: auditooor.resume.v1:abc123",
        "hunt-definition": "## TASK\nHunt the exit path.",
        "skip-set": "Consult the skip-set / known-dead-ends before hunting.",
        "brain-prime": "## BRAIN-PRIME\nmindset-prime hints seeded here.",
        "hacker-questions": "Traverse the hacker-questions library.",
    }
    blocks.pop(section)
    return "\n\n".join(blocks.values())


class TestWorkerBriefCompleteness(unittest.TestCase):
    def test_complete_brief_passes(self):
        result = evaluate(COMPLETE_BRIEF)
        self.assertEqual(result["verdict"], "pass-brief-complete")
        self.assertTrue(result["passed"])
        self.assertEqual(result["missing_sections"], [])
        self.assertEqual(result["schema"], SCHEMA)
        self.assertTrue(all(result["sections_present"].values()))

    def test_missing_mcp_recall(self):
        result = evaluate(_brief_missing("mcp-recall"))
        self.assertEqual(result["verdict"], "fail-missing-mcp-recall")
        self.assertFalse(result["passed"])
        self.assertIn("mcp-recall", result["missing_sections"])

    def test_missing_hunt_definition(self):
        result = evaluate(_brief_missing("hunt-definition"))
        self.assertEqual(result["verdict"], "fail-missing-hunt-definition")
        self.assertFalse(result["passed"])

    def test_missing_skip_set(self):
        result = evaluate(_brief_missing("skip-set"))
        self.assertEqual(result["verdict"], "fail-missing-skip-set")
        self.assertFalse(result["passed"])

    def test_missing_brain_prime(self):
        result = evaluate(_brief_missing("brain-prime"))
        self.assertEqual(result["verdict"], "fail-missing-brain-prime")
        self.assertFalse(result["passed"])

    def test_missing_hacker_questions(self):
        result = evaluate(_brief_missing("hacker-questions"))
        self.assertEqual(result["verdict"], "fail-missing-hacker-questions")
        self.assertFalse(result["passed"])

    def test_empty_brief_reports_all_missing_in_order(self):
        result = evaluate("nothing relevant here at all")
        # First missing section in canonical order drives the verdict.
        self.assertEqual(result["verdict"], "fail-missing-mcp-recall")
        self.assertEqual(result["missing_sections"], SECTION_ORDER)

    def test_multi_missing_reports_first_in_order(self):
        # Has hunt-definition + skip-set, missing mcp-recall + brain-prime +
        # hacker-questions. First missing in order is mcp-recall.
        text = "## TASK\nHunt.\n\nConsult the skip-set first."
        result = evaluate(text)
        self.assertEqual(result["verdict"], "fail-missing-mcp-recall")
        self.assertIn("brain-prime", result["missing_sections"])
        self.assertIn("hacker-questions", result["missing_sections"])
        self.assertNotIn("hunt-definition", result["missing_sections"])
        self.assertNotIn("skip-set", result["missing_sections"])

    def test_rebuttal_visible_line(self):
        text = _brief_missing("brain-prime") + "\nwbc-rebuttal: drill lane, mindset n/a"
        result = evaluate(text)
        self.assertEqual(result["verdict"], "ok-rebuttal")
        self.assertTrue(result["passed"])
        self.assertEqual(result["rebuttal_reason"], "drill lane, mindset n/a")

    def test_rebuttal_html_comment(self):
        text = _brief_missing("skip-set") + "\n<!-- wbc-rebuttal: fresh workspace, no dead-ends yet -->"
        result = evaluate(text)
        self.assertEqual(result["verdict"], "ok-rebuttal")
        self.assertTrue(result["passed"])

    def test_rebuttal_does_not_override_complete(self):
        # A complete brief still reports pass-brief-complete even with a marker.
        text = COMPLETE_BRIEF + "\nwbc-rebuttal: not needed"
        result = evaluate(text)
        self.assertEqual(result["verdict"], "pass-brief-complete")

    def test_empty_rebuttal_ignored(self):
        text = _brief_missing("brain-prime") + "\nwbc-rebuttal:   "
        result = evaluate(text)
        self.assertEqual(result["verdict"], "fail-missing-brain-prime")

    def test_oversized_rebuttal_ignored(self):
        text = _brief_missing("brain-prime") + "\nwbc-rebuttal: " + ("x" * 201)
        result = evaluate(text)
        self.assertEqual(result["verdict"], "fail-missing-brain-prime")

    def test_strict_recall_requires_pack_id_value(self):
        # Mentions the recall commands but no concrete context_pack_id value.
        text = (
            "## MCP-FIRST RECALL\nRun vault_resume_context and vault_known_dead_ends.\n\n"
            + _brief_missing("mcp-recall")
        )
        # Non-strict: mention of recall commands suffices.
        self.assertTrue(evaluate(text)["sections_present"]["mcp-recall"])
        # Strict: missing a concrete pack-id value -> mcp-recall fails.
        strict = evaluate(text, strict_recall=True)
        self.assertFalse(strict["sections_present"]["mcp-recall"])
        self.assertEqual(strict["verdict"], "fail-missing-mcp-recall")

    def test_strict_recall_passes_with_pack_id_value(self):
        result = evaluate(COMPLETE_BRIEF, strict_recall=True)
        self.assertEqual(result["verdict"], "pass-brief-complete")
        self.assertTrue(result["strict_recall"])


class TestMainCli(unittest.TestCase):
    def _write(self, text: str) -> str:
        fd = tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        )
        fd.write(text)
        fd.close()
        return fd.name

    def test_main_pass_exit_zero(self):
        path = self._write(COMPLETE_BRIEF)
        self.assertEqual(main([path, "--json"]), 0)

    def test_main_fail_exit_one(self):
        path = self._write(_brief_missing("hacker-questions"))
        self.assertEqual(main([path]), 1)

    def test_main_missing_file_exit_two(self):
        self.assertEqual(main(["/nonexistent/brief.md", "--json"]), 2)

    def test_main_empty_file_exit_two(self):
        path = self._write("   \n  ")
        self.assertEqual(main([path, "--json"]), 2)


if __name__ == "__main__":
    unittest.main()
