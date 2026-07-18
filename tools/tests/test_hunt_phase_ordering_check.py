#!/usr/bin/env python3
# r36-rebuttal: lane GAP-FIX-1-gap29 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Tests for tools/hunt-phase-ordering-check.py (Gap #29).

Covers:
  - pass-not-drill-lane (capability / tool-build / filing / unknown lane-type)
  - pass-not-drill-lane (lane-id has no drill/hunt/comp substring)
  - pass-audit-complete-before-drill (marker present, fresh)
  - fail-drill-before-audit (marker missing)
  - fail-stale-audit-state (marker older than LIVE_TARGET_REPORT.md)
  - ok-rebuttal (HTML comment form)
  - ok-rebuttal (visible bounded line form)
  - rebuttal too long is rejected (original fail verdict stands)
  - lane-id with HUNT/DRILL/COMP substring triggers gate even when
    lane-type is something else
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import importlib

mod = importlib.import_module("hunt-phase-ordering-check")  # type: ignore[import-not-found]


class HuntPhaseOrderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / "docs").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _marker(self) -> Path:
        return self.ws / ".auditooor" / "last_audit_complete_marker"

    def _live_target(self) -> Path:
        return self.ws / "docs" / "LIVE_TARGET_REPORT.md"

    # ------------------------------------------------------------------
    # pass-not-drill-lane branch
    # ------------------------------------------------------------------

    def test_not_drill_lane_tool_build(self) -> None:
        r = mod.check(self.ws, lane_id="CAP-FIX-A", lane_type="tool-build")
        self.assertEqual(r["verdict"], "pass-not-drill-lane")
        self.assertEqual(r["exit"], 0)

    def test_not_drill_lane_filing(self) -> None:
        r = mod.check(self.ws, lane_id="FILING-001", lane_type="filing")
        self.assertEqual(r["verdict"], "pass-not-drill-lane")

    def test_not_drill_lane_capability(self) -> None:
        r = mod.check(self.ws, lane_id="CAP-1", lane_type="capability")
        self.assertEqual(r["verdict"], "pass-not-drill-lane")

    # ------------------------------------------------------------------
    # gated lane: marker missing -> fail-drill-before-audit
    # ------------------------------------------------------------------

    def test_drill_lane_marker_missing(self) -> None:
        r = mod.check(self.ws, lane_id="DRILL-9", lane_type="drill")
        self.assertEqual(r["verdict"], "fail-drill-before-audit")
        self.assertEqual(r["exit"], 1)
        self.assertFalse(r["marker_present"])
        self.assertIn("remediation", r)

    def test_hunt_lane_marker_missing(self) -> None:
        r = mod.check(self.ws, lane_id="HUNT-A", lane_type="hunt")
        self.assertEqual(r["verdict"], "fail-drill-before-audit")

    def test_lane_id_drill_substring_triggers_gate(self) -> None:
        # lane-type is "capability" but lane-id has DRILL in it -> still gated
        r = mod.check(self.ws, lane_id="DRILL-WRAPPER-CAP", lane_type="capability")
        self.assertEqual(r["verdict"], "fail-drill-before-audit")

    def test_lane_id_hunt_substring_triggers_gate(self) -> None:
        r = mod.check(self.ws, lane_id="HUNT-SMOKE-A", lane_type="tool-build")
        self.assertEqual(r["verdict"], "fail-drill-before-audit")

    # ------------------------------------------------------------------
    # marker present + fresh -> pass-audit-complete-before-drill
    # ------------------------------------------------------------------

    def test_marker_present_no_live_target(self) -> None:
        self._marker().write_text("complete\n", encoding="utf-8")
        r = mod.check(self.ws, lane_id="DRILL-9", lane_type="drill")
        self.assertEqual(r["verdict"], "pass-audit-complete-before-drill")
        self.assertEqual(r["exit"], 0)

    def test_marker_present_fresher_than_live_target(self) -> None:
        # Live target written first, marker second -> ok
        self._live_target().write_text("body\n", encoding="utf-8")
        time.sleep(0.05)
        self._marker().write_text("complete\n", encoding="utf-8")
        r = mod.check(self.ws, lane_id="DRILL-9", lane_type="drill")
        self.assertEqual(r["verdict"], "pass-audit-complete-before-drill")

    # ------------------------------------------------------------------
    # marker present but stale -> fail-stale-audit-state
    # ------------------------------------------------------------------

    def test_marker_present_but_stale(self) -> None:
        # Marker written first, then live target updated -> stale
        self._marker().write_text("old\n", encoding="utf-8")
        time.sleep(0.05)
        self._live_target().write_text("new\n", encoding="utf-8")
        r = mod.check(self.ws, lane_id="DRILL-9", lane_type="drill")
        self.assertEqual(r["verdict"], "fail-stale-audit-state")
        self.assertEqual(r["exit"], 1)

    # ------------------------------------------------------------------
    # ok-rebuttal
    # ------------------------------------------------------------------

    def test_rebuttal_html_comment(self) -> None:
        text = "<!-- gap29-rebuttal: operator-approved bypass for capability lane -->"
        r = mod.check(self.ws, lane_id="DRILL-9", lane_type="drill", rebuttal_text=text)
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertEqual(r["exit"], 0)

    def test_rebuttal_visible_line(self) -> None:
        text = "Some context\ngap29-rebuttal: dry-run lane, no real drill\nmore"
        r = mod.check(self.ws, lane_id="DRILL-9", lane_type="drill", rebuttal_text=text)
        self.assertEqual(r["verdict"], "ok-rebuttal")

    def test_empty_rebuttal_rejected(self) -> None:
        text = "<!-- gap29-rebuttal:    -->"
        r = mod.check(self.ws, lane_id="DRILL-9", lane_type="drill", rebuttal_text=text)
        # Empty rebuttal -> original fail verdict stands
        self.assertEqual(r["verdict"], "fail-drill-before-audit")

    def test_oversized_rebuttal_rejected(self) -> None:
        text = "<!-- gap29-rebuttal: " + ("x" * 210) + " -->"
        r = mod.check(self.ws, lane_id="DRILL-9", lane_type="drill", rebuttal_text=text)
        self.assertEqual(r["verdict"], "fail-drill-before-audit")

    # ------------------------------------------------------------------
    # error
    # ------------------------------------------------------------------

    def test_nonexistent_workspace(self) -> None:
        r = mod.check(Path("/nonexistent/path/zzz"), lane_id="DRILL-9", lane_type="drill")
        self.assertEqual(r["verdict"], "error")
        self.assertEqual(r["exit"], 2)


if __name__ == "__main__":
    unittest.main()
