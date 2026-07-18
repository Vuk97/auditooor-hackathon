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
PATTERN = "rd-rounding-direction-zero-payout-after-balance-debit"
DETECTOR = ROOT / "detectors" / "wave17" / "rd_rounding_direction_zero_payout_after_balance_debit.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
DECIMAL_POSITIVE = ROOT / "patterns" / "fixtures" / "decimal-precision-18-to-6-downscale-loss_vuln.sol"
DECIMAL_CLEAN = ROOT / "patterns" / "fixtures" / "decimal-precision-18-to-6-downscale-loss_clean.sol"


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


class RdRoundingDirectionZeroPayoutAfterBalanceDebitTest(unittest.TestCase):
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
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixtures_are_source_scoped(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn("decimal-precision-18-to-6-downscale-loss", reference_text)
        self.assertIn("source artifacts partial", reference_text)
        self.assertIn("does not try\n# to port those shapes", reference_text)

        self.assertIn("shares18[msg.sender] -= amount18;", positive_text)
        self.assertIn("uint256 payout6 = amount18 / 1e12;", positive_text)
        self.assertIn("usdc.transfer(msg.sender, payout6);", positive_text)

        self.assertIn("uint256 payout6 = amount18.ceilDiv(1e12);", clean_text)
        self.assertIn("require(payout6 > 0", clean_text)
        self.assertLess(clean_text.index("uint256 payout6"), clean_text.index("shares18[msg.sender] -="))

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)

    def test_existing_decimal_sample_is_now_same_class_covered(self) -> None:
        self.assertGreaterEqual(self._hits(DECIMAL_POSITIVE), 1)
        self.assertEqual(self._hits(DECIMAL_CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
