#!/usr/bin/env python3
"""iter8 T2 — `--help` regression test for tools/adversarial-copilot.py.

Closes one of the two `--help` regression-test gaps deferred from iter7
T2 (the other is `tools/econ-simulator.py`; see its sibling test file).
Operator-visibility rationale: adversarial-copilot is invoked downstream
of the swarm-orchestrator pipeline to classify agent outputs as
`{break, hold, skipped, error}`. It is less-interactive than the three
tools covered in iter7 T2, but a silent argparse regression (e.g. a
future subcommand addition) would still hide the `--live` /
`--swarm-tool` flags from any operator running it directly. This test
spawns the tool as a subprocess and asserts `--help` exits 0 with a
usage line.

Offline. Stdlib only. No network. No real swarm dispatch.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "adversarial-copilot.py"


class AdversarialCopilotHelpTest(unittest.TestCase):
    def test_adversarial_copilot_help_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("usage:", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
