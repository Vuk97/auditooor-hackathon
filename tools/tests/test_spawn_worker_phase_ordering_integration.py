#!/usr/bin/env python3
# r36-rebuttal: lane GAP-INTEG-1 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Integration tests for tools/spawn-worker.sh Step 1.5 (Gap #29 auto-invoke).

Verifies the GAP-INTEG-1 deliverable: spawn-worker.sh now auto-invokes
tools/hunt-phase-ordering-check.py for hunt / opposed-trace-harness /
escalation / dispute / drill / comp lanes at MEDIUM+ severity.

Behaviour matrix:

  Lane type           Severity   Marker  Live-report  Expected
  ------------------ ---------- ------- ------------ ----------------------
  hunt               MEDIUM     present fresh        exit 0 + pass-audit-...
  hunt               MEDIUM     MISSING n/a          exit 6 (refused)
  hunt               MEDIUM     stale   newer        exit 6 (refused)
  hunt               LOW        any     any          exit 0 (skipped-sev)
  capability         MEDIUM     missing any          exit 0 (skipped-type)
  hunt               MEDIUM     missing -            exit 0 + rebuttal accept
  hunt               MEDIUM     missing -            exit 0 with env disable

Empirical anchor: hyperbridge full-hunt iter spawned drill lanes before
make audit completed; drills read stale docs/LIVE_TARGET_REPORT.md.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SPAWN_WORKER = REPO_ROOT / "tools" / "spawn-worker.sh"
GAP29_TOOL = REPO_ROOT / "tools" / "hunt-phase-ordering-check.py"


class SpawnWorkerPhaseOrderingIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / "docs").mkdir(parents=True, exist_ok=True)
        self.prompt_file = self.ws / "prompt.md"
        self.prompt_file.write_text(
            "Hypothesis: integration test for Gap #29 phase ordering\n"
            "Lane brief contents.\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_marker(self, mtime_offset_sec: float = 0.0) -> Path:
        m = self.ws / ".auditooor" / "last_audit_complete_marker"
        m.write_text("ok\n", encoding="utf-8")
        if mtime_offset_sec:
            now = time.time() + mtime_offset_sec
            os.utime(m, (now, now))
        return m

    def _write_live_report(self, mtime_offset_sec: float = 0.0) -> Path:
        r = self.ws / "docs" / "LIVE_TARGET_REPORT.md"
        r.write_text("# Live target report\n", encoding="utf-8")
        if mtime_offset_sec:
            now = time.time() + mtime_offset_sec
            os.utime(r, (now, now))
        return r

    def _run(
        self,
        lane_type: str,
        severity: str,
        lane_id: str = "TEST-HUNT-1",
        extra_env: dict[str, str] | None = None,
        extra_args: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            "bash",
            str(SPAWN_WORKER),
            "--lane-id", lane_id,
            "--lane-type", lane_type,
            "--severity", severity,
            "--workspace", str(self.ws),
            "--prompt-file", str(self.prompt_file),
            "--dry-run",
            "--no-register",
            "--no-prebriefing",
        ]
        if extra_args:
            cmd.extend(extra_args)
        env = os.environ.copy()
        env["SPAWN_WORKER_BYPASS_REASON"] = "test-bypass"
        if extra_env:
            env.update(extra_env)
        return subprocess.run(cmd, capture_output=True, text=True, env=env)

    # ------------------------------------------------------------------
    # GREEN paths
    # ------------------------------------------------------------------

    def test_hunt_medium_marker_present_passes(self) -> None:
        """Gated lane + gated severity + fresh marker = spawn succeeds with pass-audit-complete-before-drill."""
        self._write_marker()
        r = self._run("hunt", "MEDIUM")
        self.assertEqual(r.returncode, 0, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        # The stderr OK line carries pathspec/prebriefing status; gap29
        # status appears in the log row. Confirm log row.
        log_path = self.ws / ".auditooor" / "spawn_worker_log.jsonl"
        # spawn_worker_log path defaults to <repo>/.auditooor/... not WS;
        # check that no refusal happened by absence of ERROR line.
        self.assertNotIn("Gap #29 phase-ordering refused spawn", r.stderr)

    def test_dispute_low_severity_skipped(self) -> None:
        """Gated lane-type + ungated severity (LOW) = skip Gap #29 even with no marker."""
        # No marker written.
        r = self._run("dispute", "LOW")
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr!r}")
        self.assertNotIn("Gap #29 phase-ordering refused spawn", r.stderr)

    def test_capability_lane_type_skipped(self) -> None:
        """Ungated lane-type (capability) bypasses Gap #29 even at HIGH severity with no marker."""
        # No marker written.
        r = self._run("capability", "HIGH", lane_id="CAP-1")
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr!r}")
        self.assertNotIn("Gap #29 phase-ordering refused spawn", r.stderr)

    def test_env_disable_bypasses_gap29(self) -> None:
        """SPAWN_WORKER_GAP29_DISABLE=1 force-skips Gap #29 even when marker missing."""
        # No marker written.
        r = self._run(
            "hunt",
            "HIGH",
            extra_env={"SPAWN_WORKER_GAP29_DISABLE": "1"},
        )
        self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr!r}")
        self.assertNotIn("Gap #29 phase-ordering refused spawn", r.stderr)

    def test_rebuttal_in_prompt_accepted(self) -> None:
        """`<!-- gap29-rebuttal: <reason> -->` in prompt-file bypasses Gap #29."""
        # No marker written.
        self.prompt_file.write_text(
            "Hypothesis: rebuttal-accepted test\n"
            "<!-- gap29-rebuttal: orchestrator validated marker offline; spawning anyway -->\n",
            encoding="utf-8",
        )
        r = self._run("hunt", "HIGH")
        self.assertEqual(r.returncode, 0, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertNotIn("Gap #29 phase-ordering refused spawn", r.stderr)

    # ------------------------------------------------------------------
    # RED paths (refusals)
    # ------------------------------------------------------------------

    def test_hunt_medium_no_marker_refuses(self) -> None:
        """Gated lane + gated severity + missing marker = exit 6 refusal."""
        # No marker written.
        r = self._run("hunt", "MEDIUM")
        self.assertEqual(r.returncode, 6, msg=f"stdout={r.stdout!r} stderr={r.stderr!r}")
        self.assertIn("Gap #29 phase-ordering refused spawn", r.stderr)
        self.assertIn("fail-drill-before-audit", r.stderr)

    def test_opposed_trace_critical_no_marker_refuses(self) -> None:
        """opposed-trace-harness at CRITICAL with no marker also refuses."""
        r = self._run("opposed-trace-harness", "CRITICAL", lane_id="OPP-1")
        self.assertEqual(r.returncode, 6, msg=f"stderr={r.stderr!r}")
        self.assertIn("Gap #29 phase-ordering refused spawn", r.stderr)

    def test_hunt_medium_stale_marker_refuses(self) -> None:
        """Marker older than LIVE_TARGET_REPORT.md = fail-stale-audit-state."""
        # Marker written 1h in the past, live report fresh.
        self._write_marker(mtime_offset_sec=-3600.0)
        self._write_live_report()
        r = self._run("hunt", "HIGH")
        self.assertEqual(r.returncode, 6, msg=f"stderr={r.stderr!r}")
        self.assertIn("fail-stale-audit-state", r.stderr)

    # ------------------------------------------------------------------
    # Log row carries gap29 fields
    # ------------------------------------------------------------------

    def test_log_row_records_gap29_fields_on_pass(self) -> None:
        """JSON log row in spawn_worker_log.jsonl contains gap29_status."""
        self._write_marker()
        # Force a custom log path so we can inspect it.
        log_path = Path(tempfile.mkdtemp()) / "spawn_worker_log.jsonl"
        try:
            r = self._run(
                "hunt",
                "MEDIUM",
                extra_env={"SPAWN_WORKER_LOG_PATH": str(log_path)},
            )
            self.assertEqual(r.returncode, 0, msg=f"stderr={r.stderr!r}")
            self.assertTrue(log_path.is_file(), msg=f"log not written at {log_path}")
            rows = [
                json.loads(line)
                for line in log_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertGreaterEqual(len(rows), 1)
            row = rows[-1]
            self.assertIn("gap29_status", row)
            self.assertTrue(
                row["gap29_status"].startswith("pass:"),
                msg=f"unexpected gap29_status: {row.get('gap29_status')}",
            )
        finally:
            try:
                log_path.unlink(missing_ok=True)
                log_path.parent.rmdir()
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
