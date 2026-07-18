#!/usr/bin/env python3
"""
Tests for tools/operator-action-tracker.py

Covers each source type, empty workspace, and credential detection.
Rule 37: test-only file, no corpus records emitted.
"""
import datetime as _dt
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "operator_action_tracker",
        REPO_ROOT / "tools" / "operator-action-tracker.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_mod = _load_module()
ActionItem = _mod.ActionItem
ETA_MAP = _mod.ETA_MAP
_compute_delta = _mod._compute_delta
_is_pending_status = _mod._is_pending_status
parse_blocker_ledger = _mod.parse_blocker_ledger
parse_lane_reports = _mod.parse_lane_reports
parse_lesson_source_decisions = _mod.parse_lesson_source_decisions
parse_mcp_credentials = _mod.parse_mcp_credentials
parse_submissions = _mod.parse_submissions
render_json = _mod.render_json
render_markdown = _mod.render_markdown


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data, indent=2))
    else:
        path.write_text(str(data))


# ---------------------------------------------------------------------------
# 1. Blocker ledger - external_state_required open rows surfaced
# ---------------------------------------------------------------------------


class TestBlockerLedger(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())

    def _write_ledger(self, blockers: list[dict]) -> None:
        _write(
            self.tmp / "reports" / "v3_blocker_ledger" / "blocker_ledger.json",
            {"schema": "v1", "generated_on": "2026-05-23", "blockers": blockers},
        )

    def test_open_external_row_surfaced(self) -> None:
        """Open external_state_required blocker is returned."""
        self._write_ledger(
            [
                {
                    "blocker_id": "BLK-TEST-CREDS",
                    "category": "source_mining.external_api_access",
                    "status": "blocked_needs_credentials",
                    "external_state_required": True,
                    "next_action": "Provide SOLODIT_API_KEY",
                }
            ]
        )
        items = parse_blocker_ledger(self.tmp)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].item_id, "BLK-TEST-CREDS")
        self.assertEqual(items[0].action_class, "credentials")

    def test_closed_row_not_surfaced(self) -> None:
        """Closed blocker is not returned."""
        self._write_ledger(
            [
                {
                    "blocker_id": "BLK-CLOSED",
                    "category": "source_mining",
                    "status": "closed_by_bounded_live_delta",
                    "external_state_required": True,
                    "next_action": "Closed",
                }
            ]
        )
        items = parse_blocker_ledger(self.tmp)
        self.assertEqual(len(items), 0)

    def test_non_external_row_not_surfaced(self) -> None:
        """Row without external_state_required=True is skipped."""
        self._write_ledger(
            [
                {
                    "blocker_id": "BLK-LOCAL",
                    "category": "lesson_writeback",
                    "status": "blocked_no_safe_writeback_candidate",
                    "external_state_required": False,
                    "next_action": "local action",
                }
            ]
        )
        items = parse_blocker_ledger(self.tmp)
        self.assertEqual(len(items), 0)

    def test_missing_ledger_returns_empty(self) -> None:
        """Missing blocker_ledger.json returns empty list."""
        items = parse_blocker_ledger(self.tmp)
        self.assertEqual(items, [])


# ---------------------------------------------------------------------------
# 2. SUBMISSIONS.md - pending rows surfaced
# ---------------------------------------------------------------------------


class TestSubmissions(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.audits_root = self.tmp / "audits"

    def _write_subs(self, ws_name: str, content: str) -> None:
        p = self.audits_root / ws_name / "submissions" / "SUBMISSIONS.md"
        _write(p, content)

    def test_pending_row_surfaced(self) -> None:
        """A table row with 'Pending' status is returned."""
        self._write_subs(
            "dydx",
            "| #18 | 2026-05-08 | High | Pending | Blocksync verification gap |\n",
        )
        items = parse_submissions(self.audits_root)
        self.assertTrue(any(it.item_id == "#18" for it in items))

    def test_filed_row_not_surfaced(self) -> None:
        """A table row with 'Filed' status is not returned."""
        self._write_subs(
            "dydx",
            "| #48 | 2026-05-08 | Critical | Filed | Some finding |\n",
        )
        items = parse_submissions(self.audits_root)
        self.assertEqual(items, [])

    def test_in_review_row_surfaced(self) -> None:
        """A table row with 'IN_REVIEW' status is returned."""
        self._write_subs(
            "morpho",
            "| #X1 | 2026-05-10 | Medium | IN_REVIEW | Some finding |\n",
        )
        items = parse_submissions(self.audits_root)
        self.assertTrue(any("X1" in it.item_id for it in items))

    def test_since_filter_drops_old_rows(self) -> None:
        """Rows before --since date are excluded."""
        self._write_subs(
            "spark",
            "| #S1 | 2026-04-01 | Critical | Pending | Old finding |\n",
        )
        items = parse_submissions(
            self.audits_root, since=_dt.date(2026, 5, 1)
        )
        self.assertEqual(items, [])

    def test_missing_audits_root_returns_empty(self) -> None:
        items = parse_submissions(self.tmp / "no_such_audits_dir")
        self.assertEqual(items, [])


# ---------------------------------------------------------------------------
# 3. MCP credentials - empty values flagged
# ---------------------------------------------------------------------------


class TestMcpCredentials(unittest.TestCase):
    """Tests parse_mcp_credentials via the loaded module (_mod) directly."""

    def test_empty_key_flagged(self) -> None:
        """Empty env value is returned as a credential action item."""
        fake_config = {
            "mcpServers": {
                "solodit": {"env": {"SOLODIT_API_KEY": ""}},
            }
        }
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / ".claude.json").write_text(json.dumps(fake_config))
            # Temporarily monkey-patch the module's Path.home
            orig_home = _mod.Path.home
            _mod.Path.home = staticmethod(lambda: td_path)
            try:
                items = _mod.parse_mcp_credentials()
            finally:
                _mod.Path.home = staticmethod(orig_home)
        self.assertTrue(
            any("SOLODIT_API_KEY" in it.item_id for it in items),
            f"Expected SOLODIT_API_KEY flagged; got: {[it.item_id for it in items]}",
        )

    def test_set_key_not_flagged(self) -> None:
        """Non-empty env value is NOT returned as a credential action item."""
        fake_config = {
            "mcpServers": {
                "solodit": {"env": {"SOLODIT_API_KEY": "sk-real-value"}},
            }
        }
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / ".claude.json").write_text(json.dumps(fake_config))
            orig_home = _mod.Path.home
            _mod.Path.home = staticmethod(lambda: td_path)
            try:
                items = _mod.parse_mcp_credentials()
            finally:
                _mod.Path.home = staticmethod(orig_home)
        self.assertEqual(items, [])


# ---------------------------------------------------------------------------
# 4. Lane reports - operator action required in SUMMARY
# ---------------------------------------------------------------------------


class TestLaneReports(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())

    def test_summary_with_flag_surfaced(self) -> None:
        """SUMMARY.md mentioning 'operator action required' is returned."""
        ao = self.tmp / "agent_outputs" / "v3_lane_test"
        ao.mkdir(parents=True, exist_ok=True)
        (ao / "SUMMARY.md").write_text(
            "## Results\noperator action required: paste API key\n"
        )
        items = parse_lane_reports(self.tmp)
        self.assertTrue(len(items) >= 1)
        self.assertTrue(any("SUMMARY.md" in it.item_id for it in items))

    def test_summary_without_flag_not_surfaced(self) -> None:
        """SUMMARY.md without the keyword is not returned."""
        ao = self.tmp / "agent_outputs" / "v3_lane_clean"
        ao.mkdir(parents=True, exist_ok=True)
        (ao / "SUMMARY.md").write_text("## Results\nAll good.\n")
        items = parse_lane_reports(self.tmp)
        self.assertEqual(items, [])

    def test_missing_agent_outputs_returns_empty(self) -> None:
        items = parse_lane_reports(self.tmp)
        self.assertEqual(items, [])


# ---------------------------------------------------------------------------
# 5. Lesson source decisions - decision_required rows
# ---------------------------------------------------------------------------


class TestLessonSourceDecisions(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())

    def _write_lsd(self, decisions: list[dict]) -> None:
        _write(
            self.tmp / ".auditooor" / "lesson_source_decisions.json",
            {"schema": "v1", "decisions": decisions},
        )

    def test_decision_required_row_surfaced(self) -> None:
        """decision_required=True row is returned."""
        self._write_lsd(
            [
                {
                    "decision_id": "LSD-TEST-001",
                    "decision_required": True,
                    "needs_human_reason": "Needs operator approval for gate change",
                    "generated_at_utc": "2026-05-20T00:00:00Z",
                }
            ]
        )
        items = parse_lesson_source_decisions(self.tmp)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].item_id, "LSD-TEST-001")
        self.assertEqual(items[0].action_class, "policy-promotion")

    def test_no_decision_required_not_surfaced(self) -> None:
        """decision_required=False row is not returned."""
        self._write_lsd(
            [
                {
                    "decision_id": "LSD-NO-001",
                    "decision_required": False,
                    "decision_outcome": "NO_ACTION",
                }
            ]
        )
        items = parse_lesson_source_decisions(self.tmp)
        self.assertEqual(items, [])

    def test_missing_lsd_returns_empty(self) -> None:
        items = parse_lesson_source_decisions(self.tmp)
        self.assertEqual(items, [])


# ---------------------------------------------------------------------------
# 6. Empty workspace - all parsers return empty
# ---------------------------------------------------------------------------


class TestEmptyWorkspace(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())

    def test_all_parsers_empty_on_bare_dir(self) -> None:
        """All parsers return empty list on an empty directory."""
        self.assertEqual(parse_blocker_ledger(self.tmp), [])
        self.assertEqual(parse_submissions(self.tmp), [])
        self.assertEqual(parse_lane_reports(self.tmp), [])
        self.assertEqual(parse_lesson_source_decisions(self.tmp), [])


# ---------------------------------------------------------------------------
# 7. Delta computation
# ---------------------------------------------------------------------------


class TestDeltaComputation(unittest.TestCase):
    def test_newly_added(self) -> None:
        current = {"a:1", "a:2", "b:3"}
        prev_state = {"item_ids": ["a:1"]}
        added, cleared = _compute_delta(current, prev_state)
        self.assertIn("a:2", added)
        self.assertIn("b:3", added)
        self.assertEqual(cleared, set())

    def test_newly_cleared(self) -> None:
        current = {"a:1"}
        prev_state = {"item_ids": ["a:1", "b:old"]}
        added, cleared = _compute_delta(current, prev_state)
        self.assertEqual(added, set())
        self.assertIn("b:old", cleared)

    def test_empty_prev_state(self) -> None:
        current = {"x:1"}
        added, cleared = _compute_delta(current, {})
        self.assertEqual(added, {"x:1"})
        self.assertEqual(cleared, set())


# ---------------------------------------------------------------------------
# 8. Rendering - markdown and JSON contain expected keys
# ---------------------------------------------------------------------------


class TestRendering(unittest.TestCase):
    def _make_item(self, ac: str = "credentials") -> ActionItem:
        return ActionItem(
            source="test",
            item_id="TEST-001",
            description="Test description",
            action="Do the thing",
            action_class=ac,
            created_at="2026-05-20",
        )

    def test_markdown_contains_item_id(self) -> None:
        items = [self._make_item()]
        md = render_markdown(items, set(), "2026-05-23T00:00:00Z")
        self.assertIn("TEST-001", md)
        self.assertIn("credentials", md)

    def test_json_contains_schema(self) -> None:
        items = [self._make_item("platform-outcome")]
        j = render_json(items, {"old:x"}, "2026-05-23T00:00:00Z")
        data = json.loads(j)
        self.assertEqual(data["schema"], "auditooor.operator_action_tracker.v1")
        self.assertEqual(data["total_pending"], 1)
        self.assertIn("old:x", data["cleared_since_last_run"])

    def test_markdown_empty_workspace(self) -> None:
        md = render_markdown([], set(), "2026-05-23T00:00:00Z")
        self.assertIn("No pending operator actions", md)

    def test_json_class_breakdown(self) -> None:
        items = [
            self._make_item("credentials"),
            self._make_item("platform-outcome"),
        ]
        data = json.loads(render_json(items, set(), "2026-05-23T00:00:00Z"))
        self.assertEqual(data["by_class"]["credentials"], 1)
        self.assertEqual(data["by_class"]["platform-outcome"], 1)


# ---------------------------------------------------------------------------
# 9. is_pending_status helper
# ---------------------------------------------------------------------------


class TestIsPendingStatus(unittest.TestCase):
    def test_pending_matches(self) -> None:
        self.assertTrue(_is_pending_status("Pending"))

    def test_in_review_matches(self) -> None:
        self.assertTrue(_is_pending_status("IN_REVIEW"))

    def test_filed_does_not_match(self) -> None:
        self.assertFalse(_is_pending_status("Filed"))

    def test_closed_does_not_match(self) -> None:
        self.assertFalse(_is_pending_status("Closed dupe"))


if __name__ == "__main__":
    unittest.main()
