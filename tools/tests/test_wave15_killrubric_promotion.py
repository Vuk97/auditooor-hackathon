"""Tests for wave-15 kill-rubric promotion: 3 new sections in KILL_RUBRIC_LIBRARY.md.

Verifies that the 3 newly-promoted rubrics (R-PRIV, R-DOCM, R-LOSC) are
correctly parsed by vault_kill_rubric_context, have the required fields,
and can be individually filtered.

Sections promoted from wave13/wave14 compiled lessons sidecars:
  - R-PRIVILEGEDACTION: Privileged-Action Prerequisite (740 source rows)
  - R-DOCUMENTEDMECHANICS: Documented-Mechanics / Intended-Behavior Kill (289 source rows)
  - R-LOWSEVERITY: Low-Severity Cap (4 source rows)
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
LIVE_LIBRARY = REPO_ROOT / "docs" / "KILL_RUBRIC_LIBRARY.md"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()

PROMOTED_TITLES = {
    "Privileged-Action Prerequisite",
    "Documented-Mechanics / Intended-Behavior Kill",
    "Low-Severity Cap",
}

PROMOTED_IDS = {
    "R-PRIVILEGEDACTION",
    "R-DOCUMENTEDMECHANICS",
    "R-LOWSEVERITY",
}


class TestWave15KillRubricPromotion(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-w15kr-test-")
        self.root = REPO_ROOT  # use real repo root so live library is loaded
        vault_dir = REPO_ROOT / "obsidian-vault"
        self.vault = vault_mcp_server.VaultQuery(vault_dir, REPO_ROOT)

    def tearDown(self):
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # Test 1: Live library section count.
    #
    # The wave-15 promotion added 3 sections on top of the 6 that existed
    # then (=9). LANE G7 later appended the per-impact kill rubrics needed to
    # resolve every impact_hunting_methodology.yaml `kill_rubric_xref`, taking
    # the live count to 22 (sections 1-13 DeFi/BC + 14-22 the G7 additions).
    # This stays an EXACT-count lock (a dropped or duplicated section fails it);
    # bump it deliberately when sections are added, never to silence a drop.
    # ------------------------------------------------------------------

    def test_section_count_after_promotion(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root)
        )
        self.assertTrue(result["library_found"], "Live library must be found")
        self.assertEqual(
            result["sections_returned"], 22,
            f"Expected 22 sections (13 DeFi/BC + 9 LANE-G7), got {result['sections_returned']}"
        )

    # ------------------------------------------------------------------
    # Test 2: All 3 promoted rubric titles present
    # ------------------------------------------------------------------

    def test_all_promoted_titles_present(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root)
        )
        titles = {row["title"] for row in result["rubric_rows"]}
        for expected_title in PROMOTED_TITLES:
            self.assertIn(
                expected_title, titles,
                f"Promoted title '{expected_title}' not found in library"
            )

    # ------------------------------------------------------------------
    # Test 3: All 3 promoted rubric IDs present
    # ------------------------------------------------------------------

    def test_all_promoted_ids_present(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root)
        )
        ids = {row["id"] for row in result["rubric_rows"]}
        for expected_id in PROMOTED_IDS:
            self.assertIn(
                expected_id, ids,
                f"Promoted ID '{expected_id}' not found in library"
            )

    # ------------------------------------------------------------------
    # Test 4: Each promoted rubric has 6 checklist items
    # ------------------------------------------------------------------

    def test_promoted_rubrics_have_six_checklist_items(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root)
        )
        promoted_rows = [
            row for row in result["rubric_rows"]
            if row["id"] in PROMOTED_IDS
        ]
        self.assertEqual(len(promoted_rows), 3, "Expected 3 promoted rows")
        for row in promoted_rows:
            self.assertEqual(
                len(row["checklist"]), 6,
                f"Rubric {row['id']} should have 6 checklist items, got {len(row['checklist'])}"
            )

    # ------------------------------------------------------------------
    # Test 5: R-PRIV filter by bug_class "privileged"
    # ------------------------------------------------------------------

    def test_filter_privileged_action(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root),
            bug_class="privileged"
        )
        self.assertGreaterEqual(result["sections_returned"], 1)
        ids = [row["id"] for row in result["rubric_rows"]]
        self.assertIn("R-PRIVILEGEDACTION", ids)

    # ------------------------------------------------------------------
    # Test 6: R-DOCM filter by bug_class "documented"
    # ------------------------------------------------------------------

    def test_filter_documented_mechanics(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root),
            bug_class="documented"
        )
        self.assertGreaterEqual(result["sections_returned"], 1)
        ids = [row["id"] for row in result["rubric_rows"]]
        self.assertIn("R-DOCUMENTEDMECHANICS", ids)

    # ------------------------------------------------------------------
    # Test 7: R-LOSC filter by bug_class "severity"
    # ------------------------------------------------------------------

    def test_filter_low_severity_cap(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root),
            bug_class="severity"
        )
        self.assertGreaterEqual(result["sections_returned"], 1)
        ids = [row["id"] for row in result["rubric_rows"]]
        self.assertIn("R-LOWSEVERITY", ids)

    # ------------------------------------------------------------------
    # Test 8: Promoted rubrics have applies_to field populated
    # ------------------------------------------------------------------

    def test_promoted_rubrics_have_applies_to(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root)
        )
        promoted_rows = [
            row for row in result["rubric_rows"]
            if row["id"] in PROMOTED_IDS
        ]
        for row in promoted_rows:
            self.assertTrue(
                row.get("applies_to", "").strip(),
                f"Rubric {row['id']} must have non-empty applies_to"
            )

    # ------------------------------------------------------------------
    # Test 9: Promoted rubrics have kill_verdict_template populated
    # ------------------------------------------------------------------

    def test_promoted_rubrics_have_kill_verdict_template(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root)
        )
        promoted_rows = [
            row for row in result["rubric_rows"]
            if row["id"] in PROMOTED_IDS
        ]
        for row in promoted_rows:
            tmpl = row.get("kill_verdict_template", "")
            self.assertIn(
                "Kill verdict:", tmpl,
                f"Rubric {row['id']} kill_verdict_template must start with 'Kill verdict:'"
            )

    # ------------------------------------------------------------------
    # Test 10: Pre-existing 6 rubrics are still present (non-regression)
    # ------------------------------------------------------------------

    def test_pre_existing_rubrics_not_removed(self):
        result = self.vault.vault_kill_rubric_context(
            workspace_path=str(self.root)
        )
        ids = {row["id"] for row in result["rubric_rows"]}
        pre_existing = {"R-AMM", "R-REENTRANCY", "R-ORACLE", "R-GOVERNANCE", "R-UPGRADE", "R-BRIDGE"}
        for pre_id in pre_existing:
            self.assertIn(pre_id, ids, f"Pre-existing rubric {pre_id} must still be present")


if __name__ == "__main__":
    unittest.main()
