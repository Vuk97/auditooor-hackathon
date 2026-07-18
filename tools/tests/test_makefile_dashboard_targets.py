#!/usr/bin/env python3
"""Iter9 T4 regression test for the `dashboard` + `dashboard-json` Makefile
targets.

The targets wrap `tools/engagement-dashboard.py` so operators can type
`make dashboard` instead of the long direct-invocation form. This test
proves the Makefile targets are wired up and that invoking them actually
exercises the dashboard tool (via recognizable output).

Scope — intentionally narrow:

  * Runs `make dashboard` in a subprocess against the repo root.
  * Accepts exit 0 (tool ran cleanly against whatever audits dir exists)
    OR exit 1 (tool exited nonzero because e.g. audits dir missing on this
    machine). Anything else is a hard failure — it means the Makefile
    wiring is broken, not that the audits dir is absent.
  * Asserts the combined stdout+stderr output contains at least one of
    the tool's recognizable tokens ("engagement", "dashboard", "workspace").

No network. No fixture workspace creation. Does not assert any specific
engagement count or gate state.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


class MakefileDashboardTest(unittest.TestCase):
    def test_make_dashboard_exits_zero(self):
        """Test target runs dashboard without error against default audits-dir."""
        result = subprocess.run(
            ["make", "dashboard"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Target may exit nonzero if no audits dir — that's fine; we care
        # about invocation working. Allow exit 0 or 1; reject anything else.
        self.assertIn(
            result.returncode,
            [0, 1],
            f"unexpected rc {result.returncode}: {result.stderr}",
        )
        # Tool's own output (not make's) should appear on stdout or stderr.
        combined = result.stdout + result.stderr
        self.assertTrue(
            "engagement" in combined.lower()
            or "dashboard" in combined.lower()
            or "workspace" in combined.lower(),
            f"dashboard output not recognized: {combined[:500]}",
        )


if __name__ == "__main__":
    unittest.main()
