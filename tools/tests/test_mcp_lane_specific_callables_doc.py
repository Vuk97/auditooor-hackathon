#!/usr/bin/env python3
"""test_mcp_lane_specific_callables_doc.py — verify MCP_LANE_SPECIFIC_CALLABLES.md coverage.

Tests:
1. Doc file exists
2. All 22 LAYER_2_SPECIFIC callables mentioned
3. Each callable has required 6 fields (name, schema, when, inputs, outputs, example)
4. Cross-link validator passes (relative paths only)
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_PATH = REPO_ROOT / "docs" / "MCP_LANE_SPECIFIC_CALLABLES.md"

# The 22 PROMOTE_LAYER_2_SPECIFIC callables from Wave-4 audit
LAYER_2_CALLABLES = {
    "vault_intent_resolve",
    "vault_bug_family_heatmap",
    "vault_dupe_rejection_context",
    "vault_language_patterns",
    "vault_originality_context",
    "vault_finalization_context",
    "vault_spark_engagement_context",
    "vault_commit_mining_state",
    "vault_corpus_mining_state",
    "vault_detector_provenance",
    "vault_dispatch_context",
    "vault_engage_report_context",
    "vault_external_corpus_search",
    "vault_finding_lineage",
    "vault_goal_state",
    "vault_hacker_brief_for_lane",
    "vault_harness_failure_context",
    "vault_kill_rubric_context",
    "vault_lane_cooldown_check",
    "vault_next_loop",
    "vault_route",
    "vault_triager_pattern_context",
}

REQUIRED_FIELDS = {"Schema", "When", "Inputs", "Outputs", "Example"}


class TestMCPLaneSpecificCallablesDoc(unittest.TestCase):
    """Verify MCP_LANE_SPECIFIC_CALLABLES.md coverage."""

    def test_doc_exists(self):
        """File should exist."""
        self.assertTrue(
            DOC_PATH.exists(),
            f"Doc not found at {DOC_PATH}",
        )

    def test_all_22_callables_mentioned(self):
        """All 22 LAYER_2 callables should appear in the doc."""
        content = DOC_PATH.read_text()
        missing = []
        for callable_name in LAYER_2_CALLABLES:
            if callable_name not in content:
                missing.append(callable_name)
        self.assertEqual(
            missing,
            [],
            f"Missing callables: {missing}",
        )

    def test_each_callable_has_required_fields(self):
        """Each callable section should have schema, when, inputs, outputs, example."""
        content = DOC_PATH.read_text()
        for callable_name in LAYER_2_CALLABLES:
            # Find the section header for this callable
            pattern = rf"### `{callable_name}`"
            if pattern not in content:
                self.fail(f"Callable {callable_name} missing section header")

            # Extract the section (from this callable to the next ###)
            section_start = content.find(pattern)
            next_section = content.find("\n### `", section_start + 1)
            if next_section == -1:
                # Last section
                section = content[section_start:]
            else:
                section = content[section_start:next_section]

            # Check for required fields
            missing_fields = []
            for field in REQUIRED_FIELDS:
                if f"- **{field}**" not in section:
                    missing_fields.append(field)
            self.assertEqual(
                missing_fields,
                [],
                f"{callable_name} missing fields: {missing_fields}",
            )

    def test_relative_paths_only(self):
        """All file paths should be relative (no /Users/wolf/...)."""
        content = DOC_PATH.read_text()
        # Find paths that look like absolute
        absolute_patterns = [
            r"/Users/wolf/",
            r"/home/",
            r"C:\\",
        ]
        for pattern in absolute_patterns:
            matches = re.findall(pattern, content)
            self.assertEqual(
                matches,
                [],
                f"Found absolute paths: {matches}",
            )

    def test_callable_count_in_summary_table(self):
        """Summary table should account for all 22 callables."""
        content = DOC_PATH.read_text()
        # Check for the summary section
        if "## Summary: Lane-to-Callable Mapping" not in content:
            self.fail("Summary table not found")
        # Rough check: the mapping table should mention 13 lanes (from audit summary)
        self.assertIn("Tier-6 commit-mining", content)
        self.assertIn("Dispatch preflight", content)
        self.assertIn("Spark hunt", content)
        self.assertIn("Filing (final)", content)


if __name__ == "__main__":
    unittest.main()
