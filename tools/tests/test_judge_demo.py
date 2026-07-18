from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class JudgeDemoTest(unittest.TestCase):
    def test_demo_proves_ordered_drive_rejection(self) -> None:
        result = subprocess.run(
            [sys.executable, "tools/judge-demo.py"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("required steps: 69 of 69", result.stdout)
        self.assertIn("reasoning before drive: PASS", result.stdout)
        self.assertIn("reasoners and routes: 35 reasoners, 35 routes (parity=PASS)", result.stdout)
        self.assertIn("reasoner handoffs: queue=35, questions=35, proof=35, resolution=35", result.stdout)
        self.assertIn("early drive attempt: BLOCKED (earlier_run_sequence_blocks)", result.stdout)
        self.assertIn("empty closeout: BLOCKED (current receipts=0/69;", result.stdout)
        self.assertIn("tampered state: BLOCKED (state_self_hash_mismatch)", result.stdout)


if __name__ == "__main__":
    unittest.main()
