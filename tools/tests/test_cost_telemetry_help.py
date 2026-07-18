#!/usr/bin/env python3
"""iter7 T2 — `--help` regression test for tools/cost-telemetry.py.

Operator-visibility rationale: cost-telemetry ships a `--summarize`
operator-facing CLI that aggregates per-stage JSON under
`<ws>/cost_runs/` into a total-duration + total-cost breakdown. Its
context-manager API is library-only, but the `--summarize` path is
interactive and run after every engagement. A silent argparse regression
would hide the cost dashboard. This test asserts `--help` exits 0 with a
usage line.

Offline. Stdlib only. No network. No workspace mutation.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "cost-telemetry.py"


class CostTelemetryHelpTest(unittest.TestCase):
    def test_cost_telemetry_help_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
