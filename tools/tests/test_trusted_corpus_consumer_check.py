"""Tests for the active-hunt trusted-corpus routing check (PR2b)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "trusted-corpus-consumer-check.py"


class TestConsumerCheck(unittest.TestCase):
    def test_all_consumers_routed(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--json"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        res = json.loads(proc.stdout)
        self.assertEqual(res["verdict"], "pass-all-consumers-routed")
        labels = {c["label"] for c in res["consumers"]}
        self.assertEqual(labels, {"hunt-guidance", "backtest", "originality"})
        for c in res["consumers"]:
            self.assertTrue(c["imports_resolver"], c["consumer"])
            self.assertTrue(c["annotates_trust"], c["consumer"])


if __name__ == "__main__":
    unittest.main()
