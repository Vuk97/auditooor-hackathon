from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "a_broken_hook_can_block_user_funds"
PYTHON_SLITHER = Path("/opt/homebrew/opt/python@3.13/bin/python3.13")
PATTERN = "a-broken-hook-can-block-user-funds"


def _slither_python() -> str | None:
    candidates = [PYTHON_SLITHER, Path("/opt/homebrew/bin/python3.13")]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        proc = subprocess.run(
            [str(candidate), "-c", "import slither"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return str(candidate)
    return None


@unittest.skipUnless(_slither_python(), "slither-enabled python is not available")
class BrokenHookCanBlockUserFundsSmokeTests(unittest.TestCase):
    def _hits(self, fixture_name: str) -> int:
        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                _slither_python() or "python3",
                str(RUNNER),
                "--tier=ALL",
                str(FIXTURE_DIR / fixture_name),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits("ssi-fix-002_positive.sol"), 1)
        self.assertEqual(self._hits("ssi-fix-002_clean.sol"), 0)


if __name__ == "__main__":
    unittest.main()
