#!/usr/bin/env python3
"""Tests for tools/post-merge-reconcile.py — V5-P0-20 / Gap 37.

Hermetic via ``--mock-dir`` JSON fixtures. The fixtures live under
``tools/tests/fixtures/reconcile/`` and contain three case shapes:

  case_clean        — no merged or closed PRs since cutoff -> exit 0
  case_unlanded     — closed-without-merge PRs whose head SHA is NOT in
                      main -> exit 1, manifest lists them as needs_reopen
  case_stale_tracker— a merged PR title mentions V5-P0-NN that the
                      tracker still calls DETECTED -> exit 1, manifest
                      lists tracker_status_updates

Exercises Codex tests #4 (tracker status reconcile) and #5 (auto-closed
PR with un-landed code).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "post-merge-reconcile.py"
FIXTURE_ROOT = REPO_ROOT / "tools" / "tests" / "fixtures" / "reconcile"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "post_merge_reconcile", TOOL_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["post_merge_reconcile"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


class ReconcileCleanCaseTest(unittest.TestCase):
    def test_clean_case_returns_empty_lists(self) -> None:
        manifest = MOD.reconcile(
            REPO_ROOT, since="HEAD~5",
            mock_dir=FIXTURE_ROOT / "case_clean",
        )
        self.assertEqual(manifest["merged_prs"], [])
        self.assertEqual(manifest["auto_closed_prs"], [])
        self.assertEqual(manifest["auto_closed_with_unlanded_code"], [])
        self.assertEqual(manifest["tracker_status_updates"], [])
        self.assertEqual(manifest["schema"], "auditooor.post_merge_reconcile.v1")


class ReconcileUnlandedCodeTest(unittest.TestCase):
    """Codex test #5: an auto-closed PR with code not yet on main is
    flagged for reopen."""

    def test_unlanded_code_flagged_for_reopen(self) -> None:
        manifest = MOD.reconcile(
            REPO_ROOT, since="HEAD~5",
            mock_dir=FIXTURE_ROOT / "case_unlanded",
        )
        unlanded = manifest["auto_closed_with_unlanded_code"]
        self.assertEqual(len(unlanded), 2,
                         f"expected 2 unlanded PRs, got {unlanded!r}")
        numbers = sorted(row["number"] for row in unlanded)
        self.assertEqual(numbers, [235, 238])
        for row in unlanded:
            self.assertTrue(row["needs_reopen"])


class TrackerStatusReconcileTest(unittest.TestCase):
    """Codex test #4: a merged PR closing V5-P0-17 in its title flips a
    DETECTED row to a suggested FIXED update."""

    def test_stale_tracker_row_suggested_for_update(self) -> None:
        # Build a temp tracker doc that says V5-P0-17 DETECTED. We patch
        # MOD.REPO_ROOT to point at the tmp root so reconcile reads it.
        with tempfile.TemporaryDirectory(prefix="pmr-") as tmp:
            tmp_root = Path(tmp)
            (tmp_root / "docs").mkdir()
            (tmp_root / "docs" / "V5_P0_FOLLOWUPS.md").write_text(
                "# V5 P0 follow-ups\n\n"
                "| ID         | Status   | Notes |\n"
                "| ---------- | -------- | ----- |\n"
                "| V5-P0-17   | DETECTED | yaml-wave17 mismatch detected |\n"
                "| V5-P0-19   | FIXED    | already done |\n"
            )
            saved_root = MOD.REPO_ROOT
            try:
                MOD.REPO_ROOT = tmp_root
                manifest = MOD.reconcile(
                    REPO_ROOT, since="HEAD~5",
                    mock_dir=FIXTURE_ROOT / "case_stale_tracker",
                )
            finally:
                MOD.REPO_ROOT = saved_root

        updates = manifest["tracker_status_updates"]
        self.assertEqual(len(updates), 1, f"updates={updates!r}")
        self.assertEqual(updates[0]["row_id"], "V5-P0-17")
        self.assertEqual(updates[0]["from"], "DETECTED")
        self.assertEqual(updates[0]["to"], "FIXED")
        self.assertEqual(updates[0]["evidence_pr"], 999)


class ParseFollowupsStatusTest(unittest.TestCase):
    """Smoke test the simple markdown parser."""

    def test_parses_well_formed_table(self) -> None:
        text = (
            "| V5-P0-17 | DETECTED | x |\n"
            "| V5-P0-19 | FIXED    | y |\n"
            "| V5-P0-21 | IN_PROGRESS | z |\n"
        )
        statuses = MOD.parse_followups_status(text)
        self.assertEqual(statuses, {
            "V5-P0-17": "DETECTED",
            "V5-P0-19": "FIXED",
            "V5-P0-21": "IN_PROGRESS",
        })

    def test_skips_lines_without_status_token(self) -> None:
        text = "V5-P0-99 mentioned in passing\nV5-P0-17 DETECTED\n"
        statuses = MOD.parse_followups_status(text)
        self.assertEqual(statuses, {"V5-P0-17": "DETECTED"})


class RenderMarkdownSmokeTest(unittest.TestCase):
    def test_clean_renders_clean_marker(self) -> None:
        manifest = {
            "since": "HEAD~5",
            "merged_prs": [],
            "auto_closed_prs": [],
            "auto_closed_with_unlanded_code": [],
            "tracker_status_updates": [],
        }
        out = MOD.render_markdown(manifest)
        self.assertIn("RECONCILE CLEAN", out)


if __name__ == "__main__":
    unittest.main()
