#!/usr/bin/env python3
"""Regression tests for gen-composition-fuzz.sh path resolution."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "gen-composition-fuzz.sh"


class TestGenCompositionFuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("bash"):
            raise unittest.SkipTest("bash not on PATH")
        if not SCRIPT.is_file():
            raise unittest.SkipTest(f"{SCRIPT} not found")

    def test_relative_contract_paths_are_resolved_from_workspace(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gen_composition_fuzz_") as td:
            root = Path(td)
            ws = root / "workspace"
            (ws / "src").mkdir(parents=True, exist_ok=True)
            (ws / "src" / "A.sol").write_text(
                "contract A { function ping() external {} }\n",
                encoding="utf-8",
            )
            (ws / "src" / "B.sol").write_text(
                "contract B { function pong() public {} }\n",
                encoding="utf-8",
            )
            contract_list = root / "contracts.txt"
            contract_list.write_text(
                "A:src/A.sol\nB:src/B.sol\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                ["bash", str(SCRIPT), str(ws), str(contract_list)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=60,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("[warn] file not found", proc.stdout)
            self.assertIn("extracted 2 public/external signatures", proc.stdout)

            out = ws / "composition_fuzz" / "A_vs_B.t.sol"
            self.assertTrue(out.is_file())
            text = out.read_text(encoding="utf-8")
            self.assertIn("function act_A_ping", text)
            self.assertIn("function act_B_pong", text)


if __name__ == "__main__":
    unittest.main()
