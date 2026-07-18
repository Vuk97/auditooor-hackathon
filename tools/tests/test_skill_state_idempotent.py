#!/usr/bin/env python3
"""V5-P0-07 / Gap 17 — idempotent `skill-state.sh init`.

Stdlib-only, hermetic via ``tempfile.TemporaryDirectory``. Tests:

  1. test_init_on_fresh_workspace_writes_marked_state
  2. test_init_twice_is_noop_when_marker_present
  3. test_init_with_unmarked_state_backs_up_and_rewrites
  4. test_backup_filename_is_unique_per_invocation

Each test invokes ``tools/skill-state.sh <ws> init`` as a subprocess and
checks the on-disk state. No network, no external services.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_STATE = REPO_ROOT / "tools" / "skill-state.sh"
MARKER = "auditooor.skill_state.v1"


def _run_init(ws: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SKILL_STATE), str(ws), "init"],
        capture_output=True,
        text=True,
        check=False,
    )


class TestSkillStateIdempotent(unittest.TestCase):
    def test_init_on_fresh_workspace_writes_marked_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            res = _run_init(ws)
            self.assertEqual(
                res.returncode,
                0,
                f"init rc={res.returncode}; stderr={res.stderr}",
            )
            state = ws / ".skill_state.yaml"
            self.assertTrue(state.is_file(), "state file not created")
            content = state.read_text()
            self.assertIn(MARKER, content)
            # Marker is in a YAML comment, not a YAML key — keeps the file
            # parseable by downstream tooling.
            self.assertIn(f"# {MARKER}", content)

    def test_init_twice_is_noop_when_marker_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)

            res1 = _run_init(ws)
            self.assertEqual(res1.returncode, 0, res1.stderr)
            state = ws / ".skill_state.yaml"
            content_after_first = state.read_text()

            # Sleep one second so any rewrite would be detectable via
            # `created:` timestamp drift, not just mtime.
            time.sleep(1)

            res2 = _run_init(ws)
            self.assertEqual(
                res2.returncode,
                0,
                f"second init rc={res2.returncode}; stderr={res2.stderr}",
            )
            self.assertIn("already initialized", res2.stdout)

            # Content is byte-identical — second init did NOT rewrite.
            self.assertEqual(state.read_text(), content_after_first)

            # No backup file was created.
            backups = list(ws.glob(".skill_state.yaml.bak.*"))
            self.assertEqual(
                backups,
                [],
                f"unexpected backups created on no-op init: {backups}",
            )

    def test_init_with_unmarked_state_backs_up_and_rewrites(self) -> None:
        """Legacy/unmarked .skill_state.yaml: backup, then write fresh."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            state = ws / ".skill_state.yaml"
            # Simulate a legacy (pre-V5-P0-07) state file with operator
            # data but no marker.
            legacy = (
                "# auditooor workspace state (Issue #104)\n"
                "version: 1\n"
                "created: 2026-01-01T00:00:00Z\n"
                "workspace: legacy\n"
                "operator_note: do not lose this\n"
            )
            state.write_text(legacy)
            self.assertNotIn(MARKER, state.read_text())

            res = _run_init(ws)
            self.assertEqual(
                res.returncode,
                0,
                f"init rc={res.returncode}; stderr={res.stderr}",
            )

            # New state was written and carries the marker.
            new_content = state.read_text()
            self.assertIn(MARKER, new_content)
            # Operator note from the legacy file is NOT silently merged
            # into the new file. The whole point of the backup is that
            # the old content is preserved separately.
            self.assertNotIn("do not lose this", new_content)

            # Backup file exists, retains original legacy content.
            backups = list(ws.glob(".skill_state.yaml.bak.*"))
            self.assertEqual(
                len(backups),
                1,
                f"expected exactly one backup, got {backups}",
            )
            self.assertEqual(backups[0].read_text(), legacy)

    def test_backup_filename_is_unique_per_invocation(self) -> None:
        """Two unmarked-state inits in the same second must not collide."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            state = ws / ".skill_state.yaml"

            # First unmarked write + init.
            state.write_text("# legacy file 1\n")
            res1 = _run_init(ws)
            self.assertEqual(res1.returncode, 0, res1.stderr)

            # Manually de-mark the resulting state file and re-init.
            # This forces the backup path again immediately.
            current = state.read_text()
            stripped = current.replace(MARKER, "stripped-marker")
            state.write_text(stripped)
            self.assertNotIn(MARKER, state.read_text())

            res2 = _run_init(ws)
            self.assertEqual(res2.returncode, 0, res2.stderr)

            backups = sorted(ws.glob(".skill_state.yaml.bak.*"))
            self.assertEqual(
                len(backups),
                2,
                f"expected two distinct backups, got {backups}",
            )
            # Filenames differ.
            self.assertNotEqual(backups[0].name, backups[1].name)
            # Naming convention is .bak.<digits>(.<n>)?
            for b in backups:
                self.assertRegex(
                    b.name,
                    r"^\.skill_state\.yaml\.bak\.\d+(\.\d+)?$",
                    f"unexpected backup filename: {b.name}",
                )


if __name__ == "__main__":
    unittest.main()
