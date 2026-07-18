#!/usr/bin/env python3
# r36-rebuttal: lane-GAP-FIX-3-B (this test file declared in agent_pathspec.json)
"""Tests for Gap #52 hunt-lane emit handshake (tools/lane-integrator.py).

Gap #52 (codified 2026-05-26): SESSION-GAP-HUNT surfaced HUNT-SMT-1 emit
"NEGATIVE-CLOSED" verdict without invoking Check #109 (Gap #37 exhaustion-
verdict-tools-attempt-required) and the salvage-negation-verdict gate.
The handshake closes that hole by composing both sub-checks behind a
single `--lane-emit-handshake` flag on tools/lane-integrator.py (and the
`make lane-emit` Makefile target).

Schema: auditooor.lane_integrator.v1.2 (verdict extensions for
        pass-handshake-ok / pass-no-exhaustion-trigger /
        fail-lane-emit-gate-fail / ok-rebuttal).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOL_PATH = _REPO_ROOT / "tools" / "lane-integrator.py"


def _import_tool():
    """Import lane-integrator.py as a module via importlib."""
    sys.path.insert(0, str(_REPO_ROOT))
    spec = importlib.util.spec_from_file_location(
        "lane_integrator_gap52", _TOOL_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


GATE = _import_tool()


def _write(p: Path, body: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _run_cli(args: list[str]) -> tuple[int, dict]:
    """Run lane-integrator.py with PYTHONPATH set and parse JSON output."""
    env = {
        "PYTHONPATH": str(_REPO_ROOT),
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    }
    proc = subprocess.run(
        [sys.executable, str(_TOOL_PATH)] + args,
        capture_output=True, text=True, env=env, check=False,
    )
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        data = {"_raw_stdout": proc.stdout, "_raw_stderr": proc.stderr}
    return proc.returncode, data


class TestGap52ExhaustionTriggerDetector(unittest.TestCase):
    """Unit tests for the _detect_gap52_exhaustion_trigger helper."""

    def test_no_exhaustion_keyword_returns_false(self):
        ok, excerpt = GATE._detect_gap52_exhaustion_trigger(
            "## verdict\nHIGH-confirmed; PoC builds.\n"
        )
        self.assertFalse(ok)
        self.assertEqual(excerpt, "")

    def test_exhausted_keyword_triggers(self):
        ok, excerpt = GATE._detect_gap52_exhaustion_trigger(
            "## verdict\nThe surface is exhausted at file:line depth.\n"
        )
        self.assertTrue(ok)
        self.assertIn("exhausted", excerpt.lower())

    def test_negative_closed_triggers(self):
        ok, _ = GATE._detect_gap52_exhaustion_trigger(
            "verdict: NEGATIVE-CLOSED disposition for X.\n"
        )
        self.assertTrue(ok)

    def test_drop_confirmed_triggers(self):
        ok, _ = GATE._detect_gap52_exhaustion_trigger("DROP-CONFIRMED\n")
        self.assertTrue(ok)

    def test_not_salvageable_confirmed_triggers(self):
        ok, _ = GATE._detect_gap52_exhaustion_trigger(
            "NOT-SALVAGEABLE-CONFIRMED after deep sweep.\n"
        )
        self.assertTrue(ok)


class TestGap52RebuttalDetector(unittest.TestCase):
    def test_html_comment_form_accepted(self):
        text = "body <!-- gap52-rebuttal: manual verification offline --> tail"
        self.assertEqual(
            GATE._detect_gap52_rebuttal(text),
            "manual verification offline",
        )

    def test_visible_line_form_accepted(self):
        text = "body\ngap52-rebuttal: bypass-reason-here\nmore body"
        self.assertEqual(
            GATE._detect_gap52_rebuttal(text),
            "bypass-reason-here",
        )

    def test_empty_rebuttal_rejected(self):
        text = "<!-- gap52-rebuttal:  -->"
        self.assertEqual(GATE._detect_gap52_rebuttal(text), "")

    def test_oversized_rebuttal_rejected(self):
        long_reason = "x" * 250
        text = f"<!-- gap52-rebuttal: {long_reason} -->"
        # Regex pattern caps inner at 200 chars; over-length will not match.
        # If it matches as a partial, our function still rejects len > 200.
        result = GATE._detect_gap52_rebuttal(text)
        self.assertEqual(result, "")


class TestGap52CLIPaths(unittest.TestCase):
    """End-to-end tests via the lane-integrator CLI."""

    def test_no_exhaustion_trigger_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp) / "results.md"
            _write(results, "context_pack_id: test\n## verdict\nHIGH-confirmed\n")
            rc, data = _run_cli([
                "--lane-emit-handshake", str(results), "--json",
            ])
            self.assertEqual(rc, 0)
            self.assertEqual(data.get("verdict"), "pass-no-exhaustion-trigger")

    def test_hunt_smt_1_anchor_fails_closed(self):
        """Empirical anchor: HUNT-SMT-1 results.md should fail-closed."""
        hunt_results = (
            _REPO_ROOT / "reports" / "v3_iter_2026-05-26_hunt"
            / "lane_HUNT_SMT_1" / "results.md"
        )
        if not hunt_results.exists():
            self.skipTest("HUNT-SMT-1 anchor results.md not present")
        rc, data = _run_cli([
            "--lane-emit-handshake", str(hunt_results), "--json",
        ])
        self.assertEqual(rc, 1)
        self.assertEqual(data.get("verdict"), "fail-lane-emit-gate-fail")
        h = data.get("lane_emit_handshake", {})
        self.assertEqual(
            h.get("exhaustion_check", {}).get("verdict"),
            "fail-exhaustion-tools-incomplete",
        )
        self.assertEqual(
            h.get("salvage_check", {}).get("verdict"),
            "fail-no-negation-evidence-list",
        )

    def test_gap52_rebuttal_marker_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Place under reports/v3_iter_*/lane_*/results.md so salvage-
            # negation-check fires (it is path-scoped).
            results = (
                Path(tmp)
                / "reports" / "v3_iter_2026-05-26_test" / "lane_GAP52_REB"
                / "results.md"
            )
            _write(results, """context_pack_id: test
## verdict
EXHAUSTED at file:line depth.
NEGATIVE-CLOSED disposition for X.
<!-- gap52-rebuttal: hand-verified manual sweep proves negation; gates offline -->
""")
            rc, data = _run_cli([
                "--lane-emit-handshake", str(results), "--json",
            ])
            self.assertEqual(rc, 0)
            self.assertEqual(data.get("verdict"), "ok-rebuttal")
            h = data.get("lane_emit_handshake", {})
            self.assertIn(
                "hand-verified", h.get("rebuttal", ""),
            )

    def test_missing_results_md_emits_error(self):
        rc, data = _run_cli([
            "--lane-emit-handshake", "/tmp/does-not-exist-gap52.md",
            "--json",
        ])
        self.assertEqual(rc, 2)
        self.assertEqual(data.get("verdict"), "error")
        self.assertIn(
            "not found",
            data.get("lane_emit_handshake", {}).get("reason", ""),
        )


class TestGap52ScopeIsolation(unittest.TestCase):
    """Handshake mode must not require --lane-id (works standalone)."""

    def test_handshake_without_lane_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp) / "results.md"
            _write(results, "## verdict\nHIGH-confirmed\n")
            # No --lane-id supplied. The CLI must NOT error on that.
            rc, data = _run_cli([
                "--lane-emit-handshake", str(results), "--json",
            ])
            self.assertEqual(rc, 0)
            self.assertEqual(data.get("verdict"), "pass-no-exhaustion-trigger")


if __name__ == "__main__":
    unittest.main()
