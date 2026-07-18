#!/usr/bin/env python3
# r36-rebuttal: lane GAP-FIX-1-gap30 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Tests for tools/always-escalate-platform-oos-check.py (Gap #30).

Covers:
  - pass-no-scope-file (no SCOPE.md / SEVERITY.md, framing benign)
  - pass-candidate-framing-not-oos (SCOPE.md exists but framing benign)
  - fail-candidate-framing-matches-platform-oos via default-seed phrase
    (Hyperbridge anchor "theoretical vulnerabilities without...")
  - fail-candidate-framing-matches-platform-oos via SCOPE.md row match
  - fail via env-extra pattern (AUDITOOOR_GAP30_OOS_PATTERNS)
  - fail via platform-overlay (workspace name contains "polymarket")
  - ok-rebuttal HTML comment
  - ok-rebuttal visible line
  - empty rebuttal rejected
  - error on nonexistent workspace
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

mod = importlib.import_module("always-escalate-platform-oos-check")  # type: ignore[import-not-found]


class AlwaysEscalatePlatformOOSTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pre_submit_gate_is_wired(self) -> None:
        script = (REPO_ROOT / "tools" / "pre-submit-check.sh").read_text(encoding="utf-8")
        self.assertIn("Check #126: GAP30-ALWAYS-ESCALATE-PLATFORM-OOS", script)
        self.assertIn("tools/always-escalate-platform-oos-check.py", script)
        self.assertIn("--framing-file \"$SUB\"", script)

    # ------------------------------------------------------------------
    # pass-no-scope-file (no SCOPE.md / SEVERITY.md / env / platform)
    # ------------------------------------------------------------------

    def test_no_scope_file_benign_framing(self) -> None:
        r = mod.check(
            workspace=self.ws,
            candidate_framing="reentrancy in withdraw() leading to direct loss of funds",
        )
        self.assertEqual(r["verdict"], "pass-no-scope-file")
        self.assertEqual(r["exit"], 0)

    # ------------------------------------------------------------------
    # default-seed matches: empirical anchor - Hyperbridge theoretical
    # ------------------------------------------------------------------

    def test_default_seed_matches_theoretical_without_proof(self) -> None:
        framing = "theoretical vulnerability without proof in the call-decompressor pathway"
        r = mod.check(workspace=self.ws, candidate_framing=framing)
        self.assertEqual(r["verdict"], "fail-candidate-framing-matches-platform-oos")
        self.assertEqual(r["exit"], 1)
        self.assertGreater(len(r["evidence"]), 0)

    def test_default_seed_matches_speculative(self) -> None:
        framing = "speculative attack on the verifier requiring future research"
        r = mod.check(workspace=self.ws, candidate_framing=framing)
        self.assertEqual(r["verdict"], "fail-candidate-framing-matches-platform-oos")

    def test_default_seed_matches_acknowledged_by_design(self) -> None:
        framing = "centralization risk acknowledged by design in admin module"
        r = mod.check(workspace=self.ws, candidate_framing=framing)
        self.assertEqual(r["verdict"], "fail-candidate-framing-matches-platform-oos")

    # ------------------------------------------------------------------
    # SCOPE.md row matching
    # ------------------------------------------------------------------

    # r36-rebuttal: lane GAP-FIX-1-gap30 declared in agent_pathspec.json via tools/agent-pathspec-register.py
    def test_scope_md_row_matching(self) -> None:
        scope = (
            "## Out-of-scope\n"
            "- Front-running attacks on public mempool are out of scope\n"
            "- Theoretical issues without proof of concept are not eligible\n"
        )
        (self.ws / "SCOPE.md").write_text(scope, encoding="utf-8")
        # Framing shares a 4-token window with the SCOPE.md row.
        framing = "describes front-running attacks on public mempool as direct loss"
        r = mod.check(workspace=self.ws, candidate_framing=framing)
        self.assertEqual(r["verdict"], "fail-candidate-framing-matches-platform-oos")

    def test_scope_md_present_benign_framing(self) -> None:
        (self.ws / "SCOPE.md").write_text(
            "## OOS\n- Front-running is excluded\n",
            encoding="utf-8",
        )
        framing = "missing nonce check in withdraw enables replay drain"
        r = mod.check(workspace=self.ws, candidate_framing=framing)
        self.assertEqual(r["verdict"], "pass-candidate-framing-not-oos")

    # ------------------------------------------------------------------
    # env-extra pattern
    # ------------------------------------------------------------------

    def test_env_extra_pattern(self) -> None:
        framing = "fancy custom oos phrase that no default catches"
        r = mod.check(
            workspace=self.ws,
            candidate_framing=framing,
            env_extra_patterns="fancy\\s+custom\\s+oos\\s+phrase",
        )
        self.assertEqual(r["verdict"], "fail-candidate-framing-matches-platform-oos")

    # ------------------------------------------------------------------
    # platform-overlay (workspace name based)
    # ------------------------------------------------------------------

    def test_platform_overlay_polymarket(self) -> None:
        # Create a workspace whose name contains "polymarket" by using a
        # subdir.
        ws = self.ws / "polymarket-audit"
        ws.mkdir()
        framing = "POLY_1271 signature replay restricted to deposit wallets only"
        r = mod.check(workspace=ws, candidate_framing=framing)
        self.assertEqual(r["verdict"], "fail-candidate-framing-matches-platform-oos")
        self.assertEqual(r["platform"], "polymarket")

    # ------------------------------------------------------------------
    # ok-rebuttal
    # ------------------------------------------------------------------

    def test_rebuttal_html_comment(self) -> None:
        framing = "theoretical vulnerability without proof"
        text = "<!-- gap30-rebuttal: operator-cleared, PoC just landed -->"
        r = mod.check(
            workspace=self.ws,
            candidate_framing=framing,
            rebuttal_text=text,
        )
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertEqual(r["exit"], 0)

    def test_rebuttal_visible_line(self) -> None:
        framing = "theoretical vulnerability without proof"
        text = "context\ngap30-rebuttal: PoC available in adjacent gist\nmore"
        r = mod.check(
            workspace=self.ws,
            candidate_framing=framing,
            rebuttal_text=text,
        )
        self.assertEqual(r["verdict"], "ok-rebuttal")

    def test_empty_rebuttal_rejected(self) -> None:
        framing = "theoretical vulnerability without proof"
        r = mod.check(
            workspace=self.ws,
            candidate_framing=framing,
            rebuttal_text="<!-- gap30-rebuttal:   -->",
        )
        self.assertEqual(r["verdict"], "fail-candidate-framing-matches-platform-oos")

    # ------------------------------------------------------------------
    # error
    # ------------------------------------------------------------------

    def test_nonexistent_workspace(self) -> None:
        r = mod.check(
            workspace=Path("/nonexistent/path/zzz"),
            candidate_framing="anything",
        )
        self.assertEqual(r["verdict"], "error")
        self.assertEqual(r["exit"], 2)


if __name__ == "__main__":
    unittest.main()
