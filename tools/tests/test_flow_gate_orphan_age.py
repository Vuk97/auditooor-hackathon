#!/usr/bin/env python3
"""Tests for flow-gate Step 13 orphan-age handling (I-11, PR #158 audit).

Behaviour expected after the fix:

* Fresh orphans (mtime within ``THIS_SESSION_HOURS``) trigger SOFT WARN in
  default mode and HARD STOP under ``--strict`` (existing Codex semantics).
* Prior-session orphans (mtime older than ``THIS_SESSION_HOURS``) are
  auto-archived NON-DESTRUCTIVELY into ``agent_outputs/_archive_<YYYY-MM-DD>/``
  with an AUTO-ARCHIVE soft-warn line. They never trigger HARD STOP.
* Non-orphan, properly-paired outputs do not trigger any warning.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FLOW_GATE = ROOT / "tools" / "flow-gate.sh"

# 5 days in seconds — comfortably older than the 24h default threshold.
OLD_AGE_SECONDS = 5 * 24 * 3600

# AUTO-ARCHIVE message embeds the actual archive directory name produced by the
# script. Parse it from the output instead of recomputing the date in Python —
# otherwise the test flakes when the subprocess starts just before UTC midnight
# and the assertion runs just after (Kimi PR #159 blocker #3).
_ARCHIVE_DIR_RE = re.compile(r"agent_outputs/(_archive_\d{4}-\d{2}-\d{2})/")


def _extract_archive_dirname(combined_output: str) -> str:
    """Return the `_archive_YYYY-MM-DD` directory name from the script output.

    The AUTO-ARCHIVE soft-warn line includes the path
    `agent_outputs/_archive_<DATE>/` — using the script's own emitted date keeps
    the assertion in lockstep with the subprocess across UTC-midnight boundaries.
    """
    match = _ARCHIVE_DIR_RE.search(combined_output)
    if match is None:
        raise AssertionError(
            "expected AUTO-ARCHIVE line with agent_outputs/_archive_<DATE>/ path "
            "in flow-gate output; got:\n" + combined_output
        )
    return match.group(1)


def _make_minimal_workspace(td: Path) -> Path:
    ws = td / "ws"
    (ws / "agent_outputs").mkdir(parents=True)
    return ws


def _set_old_mtime(p: Path, age_seconds: int = OLD_AGE_SECONDS) -> None:
    """Backdate atime+mtime to ``age_seconds`` ago."""
    target = time.time() - age_seconds
    os.utime(p, (target, target))


def _run_flow_gate(
    ws: Path,
    *,
    strict: bool = False,
    this_session_hours: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = ["bash", str(FLOW_GATE), str(ws)]
    if strict:
        cmd.append("--strict")
    env = os.environ.copy()
    if this_session_hours is not None:
        env["THIS_SESSION_HOURS"] = this_session_hours
    return subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class FlowGateOrphanAgeTests(unittest.TestCase):
    def test_old_orphan_auto_archived_non_destructively(self) -> None:
        with tempfile.TemporaryDirectory() as raw_td:
            td = Path(raw_td)
            ws = _make_minimal_workspace(td)
            old_orphan = ws / "agent_outputs" / "20260101T000000Z_explorer_oldslug.md"
            old_orphan.write_text("# old orphan\n", encoding="utf-8")
            _set_old_mtime(old_orphan)

            proc = _run_flow_gate(ws)

            combined = proc.stdout + proc.stderr
            self.assertIn("AUTO-ARCHIVE", combined, combined)
            # Original location must be empty (non-destructive move).
            self.assertFalse(old_orphan.exists(), "old orphan should have been moved")
            # Use the directory name the SCRIPT emitted (not re-computed in
            # Python after the subprocess returned) — avoids midnight flakes.
            archive_dirname = _extract_archive_dirname(combined)
            archive_dir = ws / "agent_outputs" / archive_dirname
            self.assertTrue(archive_dir.is_dir(), "_archive_<DATE>/ must be created")
            self.assertTrue(
                (archive_dir / old_orphan.name).is_file(),
                "old orphan must be moved into _archive_<DATE>/, not deleted",
            )

    def test_old_orphan_does_not_hard_stop_under_strict(self) -> None:
        with tempfile.TemporaryDirectory() as raw_td:
            td = Path(raw_td)
            ws = _make_minimal_workspace(td)
            old_orphan = ws / "agent_outputs" / "20260102T010101Z_explorer_old.md"
            old_orphan.write_text("# old orphan\n", encoding="utf-8")
            _set_old_mtime(old_orphan)

            proc = _run_flow_gate(ws, strict=True)

            combined = proc.stdout + proc.stderr
            # Step 13 must report AUTO-ARCHIVE, not HARD STOP for the old orphan.
            # The full flow-gate may HARD STOP on other unrelated steps in this
            # bare workspace; we only care that the orphan-age branch doesn't
            # fire HARD STOP for the prior-session file.
            self.assertIn("AUTO-ARCHIVE", combined, combined)
            self.assertNotIn(
                "HARD STOP — 1 this-session orphan", combined, combined
            )

    def test_fresh_orphan_soft_warn_default(self) -> None:
        with tempfile.TemporaryDirectory() as raw_td:
            td = Path(raw_td)
            ws = _make_minimal_workspace(td)
            fresh_orphan = ws / "agent_outputs" / "20260425T120000Z_explorer_freshslug.md"
            fresh_orphan.write_text("# fresh orphan\n", encoding="utf-8")
            # Leave default (current) mtime.

            proc = _run_flow_gate(ws)

            combined = proc.stdout + proc.stderr
            self.assertIn(
                "SOFT WARN — 1 this-session orphan", combined, combined
            )
            # Fresh orphans must not be archived.
            self.assertTrue(fresh_orphan.exists(), "fresh orphan must NOT be archived")

    def test_fresh_orphan_hard_stops_under_strict(self) -> None:
        with tempfile.TemporaryDirectory() as raw_td:
            td = Path(raw_td)
            ws = _make_minimal_workspace(td)
            fresh_orphan = ws / "agent_outputs" / "20260425T130000Z_explorer_freshslug.md"
            fresh_orphan.write_text("# fresh orphan\n", encoding="utf-8")

            proc = _run_flow_gate(ws, strict=True)

            combined = proc.stdout + proc.stderr
            self.assertIn(
                "HARD STOP — 1 this-session orphan", combined, combined
            )

    def test_mixed_old_and_fresh_handled_independently(self) -> None:
        with tempfile.TemporaryDirectory() as raw_td:
            td = Path(raw_td)
            ws = _make_minimal_workspace(td)
            outputs = ws / "agent_outputs"

            old_orphan = outputs / "20260101T000000Z_explorer_oldslug.md"
            old_orphan.write_text("# old orphan\n", encoding="utf-8")
            _set_old_mtime(old_orphan)

            fresh_orphan = outputs / "20260425T120000Z_explorer_freshslug.md"
            fresh_orphan.write_text("# fresh orphan\n", encoding="utf-8")

            proc = _run_flow_gate(ws)

            combined = proc.stdout + proc.stderr
            self.assertIn("AUTO-ARCHIVE — 1", combined, combined)
            self.assertIn("SOFT WARN — 1 this-session orphan", combined, combined)
            self.assertFalse(old_orphan.exists())
            self.assertTrue(fresh_orphan.exists())

    def test_paired_brief_suppresses_orphan_logic(self) -> None:
        with tempfile.TemporaryDirectory() as raw_td:
            td = Path(raw_td)
            ws = _make_minimal_workspace(td)
            outputs = ws / "agent_outputs"

            (outputs / "brief_20260425T110000Z_freshslug.md").write_text(
                "# brief\n", encoding="utf-8"
            )
            (outputs / "20260425T120000Z_explorer_freshslug.md").write_text(
                "# paired output\n", encoding="utf-8"
            )

            proc = _run_flow_gate(ws)

            combined = proc.stdout + proc.stderr
            # Active assertion: Step 13 actually ran AND found the trail intact.
            # Without this, the test would false-pass if flow-gate.sh skipped or
            # short-circuited the agent-dispatch block — both negative
            # assertions below would silently hold (Kimi PR #159 blocker #4).
            self.assertIn(
                "agent dispatch audit trail intact", combined, combined
            )
            self.assertNotIn("SOFT WARN — 1", combined, combined)
            self.assertNotIn("AUTO-ARCHIVE", combined, combined)

    def test_threshold_override_via_env(self) -> None:
        # With THIS_SESSION_HOURS=0, EVERY file is "older than 0h" → archived.
        with tempfile.TemporaryDirectory() as raw_td:
            td = Path(raw_td)
            ws = _make_minimal_workspace(td)
            output = ws / "agent_outputs" / "20260425T120000Z_explorer_someslug.md"
            output.write_text("# output\n", encoding="utf-8")
            # Backdate by ~2 minutes so find -mmin +0 sees it as "old enough".
            _set_old_mtime(output, age_seconds=120)

            proc = _run_flow_gate(ws, this_session_hours="0")

            combined = proc.stdout + proc.stderr
            self.assertIn("AUTO-ARCHIVE", combined, combined)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
