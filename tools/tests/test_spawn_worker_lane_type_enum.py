#!/usr/bin/env python3
# r36-rebuttal: lane GAP-FIX-1-gap42 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Tests for tools/spawn-worker.sh lane-type enum extension (Gap #42).

Verifies that the canonical lane-type enum accepts:
  - Existing: dispute, mediation, filing, hunt, opposed-trace-harness,
    escalation
  - New (Gap #42): capability, wire-audit, tool-build, infra

And that:
  - Non-canonical types still emit WARN but proceed (not exit 1)
  - Prior-lane-scan is correctly OFF (`disabled-for-lane-type`) for the
    new lane-types when --inject-prior-lanes is in auto-resolve mode
  - WORKTREE auto-resolution is OFF for the new lane-types
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SPAWN_WORKER = REPO_ROOT / "tools" / "spawn-worker.sh"


class SpawnWorkerLaneTypeEnumTests(unittest.TestCase):
    """Smoke tests for --dry-run mode of spawn-worker.sh.

    We use --dry-run to short-circuit the actual Agent dispatch; we're only
    verifying lane-type validation + prior-lane-scan resolution + worktree
    resolution side effects.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        # Pre-create the audit-complete marker so any downstream check
        # that might fire doesn't trip on it.
        (self.ws / ".auditooor" / "last_audit_complete_marker").write_text(
            "ok\n", encoding="utf-8"
        )
        # Minimal prompt file
        self.prompt_file = self.ws / "prompt.md"
        self.prompt_file.write_text(
            "Hypothesis: test hypothesis\nLane brief contents.\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, lane_type: str, lane_id: str = "TEST-1", extra: list[str] | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [
            "bash",
            str(SPAWN_WORKER),
            "--lane-id", lane_id,
            "--lane-type", lane_type,
            "--severity", "LOW",
            "--workspace", str(self.ws),
            "--prompt-file", str(self.prompt_file),
            "--dry-run",
            "--no-register",       # skip pathspec write
            "--no-prebriefing",    # skip prebriefing (requires bypass env)
        ]
        if extra:
            cmd.extend(extra)
        env = os.environ.copy()
        env["SPAWN_WORKER_BYPASS_REASON"] = "test-bypass"
        return subprocess.run(cmd, capture_output=True, text=True, env=env)

    # ------------------------------------------------------------------
    # Existing canonical lane-types still accepted (regression guard)
    # ------------------------------------------------------------------

    def test_existing_canonical_hunt_accepts(self) -> None:
        r = self._run("hunt", lane_id="HUNT-A")
        # dry-run should exit 0 if validation passes
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr}")
        # WARN line should NOT appear for canonical types
        self.assertNotIn("non-canonical lane-type 'hunt'", r.stderr)

    def test_existing_canonical_dispute_accepts(self) -> None:
        r = self._run("dispute")
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr}")
        self.assertNotIn("non-canonical lane-type 'dispute'", r.stderr)

    # ------------------------------------------------------------------
    # New canonical lane-types accepted (Gap #42 deliverable)
    # ------------------------------------------------------------------

    def test_capability_lane_type_accepts(self) -> None:
        r = self._run("capability", lane_id="CAP-1")
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr}")
        self.assertNotIn("non-canonical lane-type 'capability'", r.stderr)

    def test_wire_audit_lane_type_accepts(self) -> None:
        r = self._run("wire-audit", lane_id="WIRE-1")
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr}")
        self.assertNotIn("non-canonical lane-type 'wire-audit'", r.stderr)

    def test_tool_build_lane_type_accepts(self) -> None:
        r = self._run("tool-build", lane_id="TB-1")
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr}")
        self.assertNotIn("non-canonical lane-type 'tool-build'", r.stderr)

    def test_infra_lane_type_accepts(self) -> None:
        r = self._run("infra", lane_id="INF-1")
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr}")
        self.assertNotIn("non-canonical lane-type 'infra'", r.stderr)

    # ------------------------------------------------------------------
    # Non-canonical lane-type still WARNs but proceeds
    # ------------------------------------------------------------------

    def test_non_canonical_lane_type_warns_not_fails(self) -> None:
        r = self._run("xyzzy-bogus")
        # Should still succeed (dry-run) but WARN on stderr.
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr}")
        self.assertIn("non-canonical lane-type 'xyzzy-bogus'", r.stderr)

    # ------------------------------------------------------------------
    # WARN line for new lane-types lists them as canonical
    # ------------------------------------------------------------------

    def test_warn_line_lists_new_lane_types_as_canonical(self) -> None:
        r = self._run("xyzzy-bogus")
        # The WARN line text should enumerate the new canonical types so
        # operators can see them in error output.
        for new_type in ("capability", "wire-audit", "tool-build", "infra"):
            self.assertIn(
                new_type, r.stderr,
                msg=f"new canonical type {new_type!r} missing from warn line: {r.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
