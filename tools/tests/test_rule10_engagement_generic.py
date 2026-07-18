#!/usr/bin/env python3
"""Regression: Rule 10 (Check #50) cross-engagement rubric-leak gate must be
GENERIC, not fail-open for non-spark/dydx programs.

Before 2026-06-27 _detect_workspace_engagement keyed on a 4-token path allowlist
(spark/dydx-or-cantina/sherlock/c4) and check_50 soft-skip-PASSED on 'unknown' -
so the gate was fail-open for every Immunefi/other engagement (ssv, polygon,
optimism, etherfi, near, ...): a draft could carry foreign-rubric phrasing and
the submission gate passed silently. Fix: detect platform from SCOPE.md + fail
CLOSED (scan all contest rubrics) when the engagement is unknown."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "pre-submit-rules-13-16-checks.py"
_s = importlib.util.spec_from_file_location("psr", _T)
psr = importlib.util.module_from_spec(_s)
_s.loader.exec_module(psr)


class Rule10GenericTest(unittest.TestCase):
    def test_platform_detected_from_scope_md(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t) / "ws"
            (ws / "submissions").mkdir(parents=True)
            (ws / "SCOPE.md").write_text("# SCOPE - Morpho\n- Platform: Cantina\n", encoding="utf-8")
            self.assertEqual(
                psr._detect_workspace_engagement(ws / "submissions" / "x.md"), "cantina")

    def test_immunefi_and_hackenproof_detected(self):
        for plat in ("immunefi", "hackenproof"):
            with tempfile.TemporaryDirectory() as t:
                ws = Path(t) / "ws"
                (ws / "submissions").mkdir(parents=True)
                (ws / "SCOPE.md").write_text(f"# SCOPE\n- Platform: {plat}\n", encoding="utf-8")
                self.assertEqual(
                    psr._detect_workspace_engagement(ws / "submissions" / "x.md"), plat)

    def test_unknown_engagement_fails_closed_on_foreign_phrase(self):
        # No SCOPE.md, no path token -> unknown. A foreign Sherlock-rubric phrase
        # must now FAIL (was soft-skip-PASS = fail-open).
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "nope" / "x.md"
            d.parent.mkdir(parents=True)
            ok, msg = psr.check_50_wrong_rubric_contamination(
                "Severity Critical per the Sherlock severity matrix; high-impact.", d)
            self.assertFalse(ok, f"unknown engagement must fail-closed, got pass: {msg}")

    def test_clean_draft_still_passes(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t) / "ws"
            (ws / "submissions").mkdir(parents=True)
            (ws / "SCOPE.md").write_text("# SCOPE - Morpho\n- Platform: Cantina\n", encoding="utf-8")
            ok, msg = psr.check_50_wrong_rubric_contamination(
                "Unprivileged caller drains vault shares via rounding; loss of user funds.",
                ws / "submissions" / "x.md")
            self.assertTrue(ok, f"clean draft should pass: {msg}")

    def test_r10_rebuttal_override(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "nope" / "x.md"
            d.parent.mkdir(parents=True)
            ok, _ = psr.check_50_wrong_rubric_contamination(
                "<!-- r10-rebuttal: cantina-native phrasing -->\nSherlock severity matrix", d)
            self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
