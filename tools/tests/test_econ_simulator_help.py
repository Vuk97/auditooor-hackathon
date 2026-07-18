#!/usr/bin/env python3
"""iter8 T2 — `--help` regression test for tools/econ-simulator.py.

Closes the second of the two `--help` regression-test gaps deferred from
iter7 T2 (the other is `tools/adversarial-copilot.py`; see its sibling
test file). Operator-visibility rationale: econ-simulator is the PR 207
advisory-only economic-simulator prototype. It enforces a
dry-run-default discipline (`--live` hard-stops unless halmos + anvil
are on PATH) and a strict status vocabulary
`{pass, counterexample, no-counterexample, timeout, error, skipped}`.
Operators invoke it directly when producing packaged bundles for
validated targets (first target: POLY-ITER3-R77-06). A silent argparse
regression would hide the `--bundle` / `--angle` / `--replay-manifest`
flags. This test spawns the tool as a subprocess and asserts `--help`
exits 0 with a usage line.

Offline. Stdlib only. No network. No halmos / anvil invocation.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "econ-simulator.py"


class EconSimulatorHelpTest(unittest.TestCase):
    def test_econ_simulator_help_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
