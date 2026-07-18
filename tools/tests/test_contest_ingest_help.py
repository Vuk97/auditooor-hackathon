#!/usr/bin/env python3
"""iter7 T2 — `--help` regression test for tools/contest-ingest.py.

Operator-visibility rationale: contest-ingest is the offline novelty-seed
harvester; operators invoke it directly to refresh
`reference/contest_patterns.jsonl` after populating the cache. The tool
carries a deliberate hard-error path for `--live-fetch`; a broken
`--help` would make it harder to discover the correct offline flags
(`--test-fixtures`, `--promote-to-live`). This test asserts `--help`
exits 0 with a usage line.

Offline. Stdlib only. No network. No cache mutation.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "contest-ingest.py"


class ContestIngestHelpTest(unittest.TestCase):
    def test_contest_ingest_help_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
