#!/usr/bin/env python3
"""Smoke tests for the ``find -maxdepth 0 -mmin "+N"`` construct used by
flow-gate.sh Step 13 (PR #159) for prior-session orphan archival.

Background
----------
Kimi K2.6's review of PR #159 flagged the line

    find "$out" -maxdepth 0 -mmin "+${MMIN_THRESHOLD}" 2>/dev/null | grep -q .

as having two macOS-portability blockers:

  Blocker #1: ``-maxdepth 0`` is a GNU-find extension; BSD find (macOS)
              rejects it as an unknown primary.
  Blocker #2: The silent ``2>/dev/null`` swallows that failure, so the
              pipeline returns empty, ``is_old`` stays 0, and prior-session
              files are mis-classified as fresh orphans -> spurious
              HARD STOP under ``--strict``.

These tests exercise the exact construct against the host's ``find`` (the
default ``/usr/bin/find`` on macOS, GNU find on Linux) and assert that:

  * The construct exits cleanly (no "unknown primary" error).
  * A freshly-touched file is classified as is_old=0.
  * A back-dated file (mtime > threshold) is classified as is_old=1.

If Kimi's claim were correct, both classifications would land on 0 (because
the find invocation would error to /dev/null and grep would always fail),
which test_old_file_classified_as_old would catch.

These tests therefore stand as a regression guard against any future
flow-gate.sh refactor that re-introduces a non-portable invocation, and
document the verification result for PR #159 reviewers.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


# Mirrors the inline construct in tools/flow-gate.sh Step 13 (PR #159).
# Threshold here is intentionally small (1 minute) so the test stays fast.
SHELL_SNIPPET = r"""
set -u
out="$1"
mmin="$2"
is_old=0
if find "$out" -maxdepth 0 -mmin "+${mmin}" 2>/dev/null | grep -q .; then
  is_old=1
fi
printf '%s' "$is_old"
"""


def _classify(path: Path, mmin: int = 1) -> str:
    """Run the snippet under bash and return is_old as a string."""
    proc = subprocess.run(
        ["bash", "-c", SHELL_SNIPPET, "_", str(path), str(mmin)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # The script always exits 0; failures surface via empty/garbled stdout.
    assert proc.returncode == 0, (
        f"snippet exited non-zero: rc={proc.returncode!r} "
        f"stderr={proc.stderr!r} stdout={proc.stdout!r}"
    )
    return proc.stdout


class BsdFindCompatTests(unittest.TestCase):
    """Verify the PR #159 find invocation is portable on the host platform."""

    def test_fresh_file_classified_as_not_old(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "fresh.md"
            target.write_text("fresh", encoding="utf-8")
            self.assertEqual(_classify(target, mmin=1), "0")

    def test_old_file_classified_as_old(self) -> None:
        # If -maxdepth 0 were rejected by find, this assertion would flip to
        # "0" (the silent error swallow), reproducing Kimi's blocker #2.
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "old.md"
            target.write_text("old", encoding="utf-8")
            ten_min_ago = time.time() - (10 * 60)
            os.utime(target, (ten_min_ago, ten_min_ago))
            self.assertEqual(_classify(target, mmin=1), "1")

    def test_find_invocation_emits_no_unknown_primary_error(self) -> None:
        # Direct probe: run the bare construct and capture stderr without
        # the 2>/dev/null swallow. Any "unknown primary" / "illegal option"
        # message would indicate Kimi blocker #1 reproducing on this host.
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "probe.md"
            target.write_text("probe", encoding="utf-8")
            proc = subprocess.run(
                ["bash", "-c", 'find "$1" -maxdepth 0 -mmin "+0"', "_", str(target)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"find exited non-zero: stderr={proc.stderr!r}",
            )
            stderr_lc = proc.stderr.lower()
            for needle in ("unknown primary", "illegal option", "unknown option"):
                self.assertNotIn(
                    needle,
                    stderr_lc,
                    f"find emitted portability error: {proc.stderr!r}",
                )


if __name__ == "__main__":
    unittest.main()
