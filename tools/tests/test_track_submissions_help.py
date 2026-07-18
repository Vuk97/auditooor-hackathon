#!/usr/bin/env python3
"""iter7 T2 — `--help` regression test for tools/track-submissions.py.

Operator-visibility rationale: track-submissions is the manual outcome
ledger — operators invoke it interactively every time they file a report
on HackenProof/Cantina/Sherlock/Immunefi. A silent breakage of `--help`
(e.g. an argparse regression from adding a new subcommand) would waste
the operator's first attempt at every new engagement. This test spawns
the tool as a subprocess and asserts `--help` exits 0 with a usage line.

Offline. Stdlib only. No network. No real dispatch.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "track-submissions.py"


class TrackSubmissionsHelpTest(unittest.TestCase):
    def test_track_submissions_help_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
