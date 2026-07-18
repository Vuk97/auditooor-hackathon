from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "fund-loss-via-arithmetic-value-math"
DETECTOR = ROOT / "detectors" / "wave17" / "fund_loss_via_arithmetic_value_math.py"
OWNED_VULN = ROOT / "detectors" / "fixtures" / "fund_loss_via_arithmetic_value_math" / "positive.sol"
OWNED_CLEAN = ROOT / "detectors" / "fixtures" / "fund_loss_via_arithmetic_value_math" / "clean.sol"
CONSTRUCTOR_VULN = ROOT / "detectors" / "test_fixtures" / "constructor_precision_factor_truncates_to_zero_vulnerable.sol"
CONSTRUCTOR_CLEAN = ROOT / "detectors" / "test_fixtures" / "constructor_precision_factor_truncates_to_zero_clean.sol"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class FundLossViaArithmeticValueMathConstructorScaleTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_owned_fixture_pair_still_fires_and_stays_clean(self) -> None:
        self.assertGreaterEqual(self._hits(OWNED_VULN), 1)
        self.assertEqual(self._hits(OWNED_CLEAN), 0)

    def test_constructor_scale_pair_now_fires_and_stays_clean(self) -> None:
        self.assertGreaterEqual(self._hits(CONSTRUCTOR_VULN), 1)
        self.assertEqual(self._hits(CONSTRUCTOR_CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
