#!/usr/bin/env python3
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[]
"""Tests for tools/hunt-brief-full-tier-coverage-check.py (G13.2).

Covers:
  - pass-not-hunt-lane (dispute / filing lane-type)
  - pass-no-severity-md (workspace has no SEVERITY.md)
  - pass-full-tier-coverage-present (all tiers named + directive)
  - fail-missing-tier-in-brief (a fileable tier absent from the brief)
  - fail-no-full-tier-directive (tiers present but no directive)
  - ok-rebuttal (HTML comment + visible line forms)
  - oversized rebuttal is ignored (original fail stands)
"""
from __future__ import annotations

import importlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

mod = importlib.import_module("hunt-brief-full-tier-coverage-check")  # type: ignore

# A SEVERITY.md with 4 tiers (dydx-style).
SEVERITY_4TIER = """# Severity
### Critical - **USD 150,000 to 1,000,000**
- Significant loss or theft of user funds
### High - **USD 50,000-150,000**
- Network-level downtime or liveness failures
### Medium - **USD 5,000-50,000**
- Failures in non-core products that degrade UX
### Low - **USD 50-5,000**
- Display / event-parsing issues that mislead users
"""

# A SEVERITY.md with only critical + high (spark-style).
SEVERITY_2TIER = """# Severity
### Critical (Blockchain/DLT)

| ID | Listed-impact sentence | Reward |
|---|---|---|
| CRIT-1 | Direct loss of funds | USD 100,000 |

### High (Blockchain/DLT)

| ID | Listed-impact sentence | Reward |
|---|---|---|
| HIGH-1 | RPC API crash | USD 25,000 |
"""

GOOD_BRIEF = (
    "## Section 15i-FULL\n"
    "Critical High Medium Low tiers all listed.\n"
    "MANDATORY: hunt and file EVERY tier Low -> Critical.\n"
)


class FullTierCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_sev(self, body: str) -> None:
        (self.ws / "SEVERITY.md").write_text(body, encoding="utf-8")

    def test_not_hunt_lane(self) -> None:
        r = mod.check(self.ws, lane_id="DISP-1", lane_type="dispute", brief_text=GOOD_BRIEF)
        self.assertEqual(r["verdict"], "pass-not-hunt-lane")
        self.assertEqual(r["exit"], 0)

    def test_no_severity_md(self) -> None:
        r = mod.check(self.ws, lane_id="HUNT-A", lane_type="hunt", brief_text=GOOD_BRIEF)
        self.assertEqual(r["verdict"], "pass-no-severity-md")
        self.assertEqual(r["exit"], 0)

    def test_full_tier_coverage_present(self) -> None:
        self._write_sev(SEVERITY_4TIER)
        r = mod.check(self.ws, lane_id="HUNT-A", lane_type="hunt", brief_text=GOOD_BRIEF)
        self.assertEqual(r["verdict"], "pass-full-tier-coverage-present")
        self.assertEqual(r["exit"], 0)
        self.assertEqual(sorted(r["rubric_tiers"]), ["critical", "high", "low", "medium"])

    def test_missing_tier(self) -> None:
        self._write_sev(SEVERITY_4TIER)
        # Brief names only critical (omits high/medium/low) + has directive.
        brief = "hunt and file EVERY tier. Critical is the focus."
        r = mod.check(self.ws, lane_id="HUNT-A", lane_type="hunt", brief_text=brief)
        self.assertEqual(r["verdict"], "fail-missing-tier-in-brief")
        self.assertEqual(r["exit"], 1)
        self.assertIn("high", r["missing_tiers"])

    def test_no_directive(self) -> None:
        self._write_sev(SEVERITY_2TIER)
        # All tiers named but no directive phrase.
        brief = "Critical and High findings are the surface here."
        r = mod.check(self.ws, lane_id="HUNT-A", lane_type="hunt", brief_text=brief)
        self.assertEqual(r["verdict"], "fail-no-full-tier-directive")
        self.assertEqual(r["exit"], 1)

    def test_rebuttal_html(self) -> None:
        self._write_sev(SEVERITY_4TIER)
        brief = "Critical only.\n<!-- g13-rebuttal: single-tier program by design -->"
        r = mod.check(self.ws, lane_id="HUNT-A", lane_type="hunt", brief_text=brief)
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertEqual(r["exit"], 0)

    def test_rebuttal_line(self) -> None:
        self._write_sev(SEVERITY_4TIER)
        brief = "Critical only.\ng13-rebuttal: operator-approved narrow hunt"
        r = mod.check(self.ws, lane_id="HUNT-A", lane_type="hunt", brief_text=brief)
        self.assertEqual(r["verdict"], "ok-rebuttal")

    def test_rebuttal_oversized_ignored(self) -> None:
        self._write_sev(SEVERITY_4TIER)
        brief = "Critical only.\n<!-- g13-rebuttal: " + ("x" * 250) + " -->"
        r = mod.check(self.ws, lane_id="HUNT-A", lane_type="hunt", brief_text=brief)
        self.assertNotEqual(r["verdict"], "ok-rebuttal")

    def test_lane_id_pattern_triggers(self) -> None:
        # r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
        self._write_sev(SEVERITY_2TIER)
        # lane-type unknown but lane-id has DRILL substring -> gated. Brief
        # names only the critical tier (genuinely omits the word "high").
        brief = "Only the Critical tier surface is covered here."
        r = mod.check(self.ws, lane_id="DRILL-7", lane_type="capability", brief_text=brief)
        self.assertEqual(r["verdict"], "fail-missing-tier-in-brief")


if __name__ == "__main__":
    unittest.main()
