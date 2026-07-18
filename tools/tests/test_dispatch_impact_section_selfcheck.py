#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for the impact-methodology self-check in
tools/dispatch-agent-with-prebriefing.py.

Theme-enforcement gap: the dispatch brief's impact-methodology section can
silently go missing on a lane-DOWNGRADE (a hunt-class lane downgraded to
"filing") with NO enforcement. The G3 wiring gates the section on the
pre-downgrade lane_type, but nothing FAILED if the section was absent on a
genuine IMPACT_METHODOLOGY_LANE_TYPES lane.

These tests assert ``validate_impact_section_present``:
  * flags a MISSING section on an impact lane (defect surfaced, not silent),
  * flags an EMPTY section body,
  * is CLEAN when the section is present on an impact lane,
  * EXEMPTS a non-impact lane (no false defect),
  * and (sanity) the language-agreement check does not spuriously fire.

The module file is hyphenated, so it is loaded via importlib with a
sys.modules registration BEFORE exec_module (Python 3.14 self-import safety),
matching tools/tests/test_dispatch_impact_methodology_injection.py.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "dispatch_agent_with_prebriefing", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_agent_with_prebriefing"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


MOD = _load_module()


class ValidateImpactSectionPresentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.header = MOD._IMPACT_METHODOLOGY_SECTION_HEADER
        # Sanity: there IS at least one impact lane type to test with.
        self.assertIn("hunt", MOD.IMPACT_METHODOLOGY_LANE_TYPES)

    def test_missing_section_on_impact_lane_is_a_defect(self) -> None:
        """A downgraded hunt lane whose brief lacks the section is flagged."""
        brief = (
            "<!-- BEGIN block -->\n"
            "## Section 15a - some rules\n"
            "no impact methodology here at all\n"
            "<!-- END block -->\n"
        )
        defects = MOD.validate_impact_section_present(brief, "hunt")
        self.assertTrue(defects, "expected a defect for a missing section")
        self.assertTrue(
            any("impact-section-missing" in d for d in defects),
            f"defect text should name the missing section: {defects}",
        )

    def test_empty_section_body_is_a_defect(self) -> None:
        """Header present but no body text -> empty-section defect."""
        brief = f"## intro\n{self.header}\n\n"
        defects = MOD.validate_impact_section_present(brief, "audit-deep")
        self.assertTrue(
            any("impact-section-empty" in d for d in defects),
            f"expected an empty-section defect: {defects}",
        )

    def test_present_section_on_impact_lane_is_clean(self) -> None:
        """When the section is present with body, no defect on an impact lane."""
        brief = (
            f"## intro\n{self.header}\n\n"
            "### Impact: `direct-theft-funds` - real body content here\n"
        )
        defects = MOD.validate_impact_section_present(brief, "poc")
        self.assertEqual(
            defects, [], f"impact lane with present section must be clean: {defects}"
        )

    def test_non_impact_lane_is_exempt(self) -> None:
        """A non-impact lane (e.g. filing) without the section is NOT flagged."""
        brief = "## Section 15a\nnothing impact-related\n"
        defects = MOD.validate_impact_section_present(brief, "filing")
        # No impact-section defect for a non-impact lane.
        self.assertFalse(
            any("impact-section" in d for d in defects),
            f"non-impact lane must be exempt from the presence check: {defects}",
        )

    def test_downgrade_scenario_caller_gates_on_original(self) -> None:
        """The check mirrors the gate: caller passes the ORIGINAL lane type.

        Simulates a 'hunt' lane that was downgraded to 'filing'. The dispatch
        wiring passes impact_lane_type (= original 'hunt'), so a brief that
        DID render the section is clean, and one that dropped it is flagged -
        proving the downgrade no longer silently masks the membership.
        """
        rendered = (
            f"## intro\n{self.header}\n\n### Impact: `x` - body\n"
        )
        dropped = "## intro\nno section\n"
        self.assertEqual(
            MOD.validate_impact_section_present(rendered, "hunt"), []
        )
        self.assertTrue(
            MOD.validate_impact_section_present(dropped, "hunt")
        )

    def test_language_agreement_sanity_no_false_skew(self) -> None:
        """With no workspace, language inference is empty -> no language-skew."""
        brief = (
            f"## intro\n{self.header}\n\n### Impact: `x` - body\n"
        )
        defects = MOD.validate_impact_section_present(
            brief, "hunt", workspace_path=None
        )
        self.assertFalse(
            any("language-skew" in d for d in defects),
            f"empty language must not produce a skew defect: {defects}",
        )

    def test_never_raises_on_garbage(self) -> None:
        """Advisory contract: never raises even on odd input."""
        try:
            MOD.validate_impact_section_present("", "hunt")
            MOD.validate_impact_section_present("x", "")
        except Exception as exc:  # pragma: no cover - failure path
            self.fail(f"validate_impact_section_present raised: {exc!r}")

    def test_emit_wrapper_returns_defects_and_does_not_raise(self) -> None:
        """_emit_impact_section_defects logs + returns the same defects."""
        brief = "## intro\nno section\n"
        defects = MOD._emit_impact_section_defects(brief, "hunt")
        self.assertTrue(
            any("impact-section-missing" in d for d in defects),
            f"emit wrapper should return the missing-section defect: {defects}",
        )


if __name__ == "__main__":
    unittest.main()
