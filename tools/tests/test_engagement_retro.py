"""Hermetic tests for tools/engagement-retro.py multi-format parser.

Covers I-27 (PR #158 session-observations): the retro parser previously
only matched the Polymarket markdown-table layout, returning zero
findings on Centrifuge (S-NNN line-item) and Morpho (`# Submission N`
section headers). This test asserts all three layouts are recognised
and that the dispatcher prefers the first one that yields rows.
"""
from __future__ import annotations

import importlib.util
import sys
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "engagement-retro.py"


def _load_module():
    if "engagement_retro" in sys.modules:
        return sys.modules["engagement_retro"]
    spec = importlib.util.spec_from_file_location("engagement_retro", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["engagement_retro"] = module
    spec.loader.exec_module(module)
    return module


class PolymarketTableLayoutTest(unittest.TestCase):
    """Layout 1: markdown table with Status column. The pre-existing
    Polymarket fixture — must continue to work after the I-27 patch."""

    def test_table_layout_parses_rows(self) -> None:
        text = textwrap.dedent(
            """
            # Polymarket Submissions

            | # | Title | Status | Severity |
            |---|-------|--------|----------|
            | 1 | CTFExchange.pause does not halt adapters | Rejected | Medium |
            | 2 | Auth.renounceOperatorRole emits stale event | Paid | Low |
            """
        )
        mod = _load_module()
        rows, layout = mod.parse_submissions(text)
        self.assertEqual(layout, "table")
        self.assertEqual(len(rows), 2)
        titles = sorted(r["title"] for r in rows)
        self.assertIn("CTFExchange.pause does not halt adapters", titles)
        self.assertEqual(
            mod.extract_outcome_class(rows[0]["status"]), "REJECTED"
        )


class CentrifugeLineItemLayoutTest(unittest.TestCase):
    """Layout 2: ``## S-NNN — title`` / ``## #NNN — title`` plus bullet
    pairs of ``- **Status**`` / value-on-next-line."""

    SAMPLE = textwrap.dedent(
        """
        # Centrifuge V3.1 — Submissions Tracker

        Legend:
        - **Status** — `READY_TO_SUBMIT` etc.

        ---

        ## S-001 — Historical pre-submit stub

        - **Severity**
          Medium
        - **Status**
          SUPERSEDED_BY_#418
        - **Outcome**
          PENDING

        ---

        ## #418 — Holdings.decrease unclamped decrement

        - **Severity**
          Medium
        - **Status**
          SUBMITTED
        - **Outcome**
          PAID
        """
    )

    def test_line_item_layout_parses_rows(self) -> None:
        mod = _load_module()
        rows, layout = mod.parse_submissions(self.SAMPLE)
        self.assertEqual(layout, "line_item")
        self.assertEqual(len(rows), 2)

    def test_outcome_promotes_to_status(self) -> None:
        """Once a finding is triaged, the Outcome cell is more useful
        than Status (``SUBMITTED`` is just queue state)."""
        mod = _load_module()
        rows, _ = mod.parse_submissions(self.SAMPLE)
        # Find #418 — the one with Outcome=PAID
        triaged = [r for r in rows if r["title"].startswith("Holdings")][0]
        self.assertEqual(
            mod.extract_outcome_class(triaged["status"]), "PAID"
        )

    def test_outcome_pending_does_not_override_status(self) -> None:
        text = textwrap.dedent(
            """
            ## #999 — Some finding

            - **Status**
              SUBMITTED
            - **Outcome**
              PENDING
            """
        )
        mod = _load_module()
        rows, layout = mod.parse_submissions(text)
        self.assertEqual(layout, "line_item")
        self.assertEqual(rows[0]["status"], "SUBMITTED")

    def test_legend_line_is_not_treated_as_finding(self) -> None:
        """The ``- **Status** — ...`` legend line at the top of a tracker
        must not be picked up as a finding row."""
        text = textwrap.dedent(
            """
            # Tracker

            Legend:
            - **Status** — `READY` · `SUBMITTED`

            (no findings yet)
            """
        )
        mod = _load_module()
        rows, layout = mod.parse_submissions(text)
        self.assertEqual(rows, [])
        self.assertEqual(layout, "none")


class MorphoSectionHeaderLayoutTest(unittest.TestCase):
    """Layout 3: ``# Submission N — title — severity`` plus a
    ``**Status:** ...`` line."""

    SAMPLE = textwrap.dedent(
        """
        # Cantina Submissions — Morpho bounty

        ---

        # 🚀 Submission 1 — #I2.B — Medium

        **Status:** SUBMITTED to Cantina (2026-04-16). PoC passes.

        ### Target

        body...

        ---

        # 🚀 Submission 2 — #I2.A — Critical

        **Status:** PAID — Cantina triager confirmed.
        """
    )

    def test_section_header_layout_parses_rows(self) -> None:
        mod = _load_module()
        rows, layout = mod.parse_submissions(self.SAMPLE)
        self.assertEqual(layout, "section_header")
        self.assertEqual(len(rows), 2)
        titles = sorted(r["title"] for r in rows)
        self.assertEqual(titles, ["#I2.A", "#I2.B"])

    def test_severity_is_extracted_from_section_header(self) -> None:
        mod = _load_module()
        rows, _ = mod.parse_submissions(self.SAMPLE)
        sev_by_title = {r["title"]: r["severity"] for r in rows}
        self.assertEqual(sev_by_title["#I2.B"], "Medium")
        self.assertEqual(sev_by_title["#I2.A"], "Critical")

    def test_paid_outcome_class_resolved(self) -> None:
        mod = _load_module()
        rows, _ = mod.parse_submissions(self.SAMPLE)
        triaged = [r for r in rows if r["title"] == "#I2.A"][0]
        self.assertEqual(
            mod.extract_outcome_class(triaged["status"]), "PAID"
        )


class DispatcherFallbackOrderTest(unittest.TestCase):
    """``parse_submissions`` must try table → line_item → section_header
    and stop at the first non-empty result."""

    def test_empty_input_returns_none(self) -> None:
        mod = _load_module()
        rows, layout = mod.parse_submissions("")
        self.assertEqual(rows, [])
        self.assertEqual(layout, "none")

    def test_table_takes_precedence_over_line_item(self) -> None:
        """If a tracker happens to embed both a table and S-NNN bullets,
        the table wins (it is the most structured, established layout)."""
        text = textwrap.dedent(
            """
            | # | Title | Status |
            |---|-------|--------|
            | 1 | First | Paid   |

            ## S-001 — Decoy

            - **Status**
              SUBMITTED
            """
        )
        mod = _load_module()
        _, layout = mod.parse_submissions(text)
        self.assertEqual(layout, "table")


if __name__ == "__main__":
    unittest.main()
