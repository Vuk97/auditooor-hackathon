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
PATTERN = "fund-loss-value-math-state-scale-mismatch"
DETECTOR = ROOT / "detectors" / "wave18" / "fund_loss_value_math_state_scale_mismatch.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "fund_loss_value_math_state_scale_mismatch"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
EC_CONFIRMED = ROOT / "patterns" / "fixtures" / "ec-borrow-supply-rate-snapshot-mismatch_vuln.sol"
FEE_CONFIRMED = ROOT / "detectors" / "fixtures" / "fee_redirect_user_controlled_sink" / "positive.sol"


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


class FundLossValueMathStateScaleMismatchTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
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
        self.assertIn(f"=== Running {PATTERN} ===", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("ec-borrow-supply-rate-snapshot-mismatch", detector_text)
        self.assertIn("fee-redirect-user-controlled-sink", detector_text)
        self.assertIn("fund-loss-via-arithmetic-value-math", detector_text)
        self.assertIn("branch = \"stale rate snapshot\"", detector_text)
        self.assertIn("branch = \"state scaled value move\"", detector_text)
        self.assertIn("branch = \"fee state to user sink\"", detector_text)

        self.assertIn("assets = shares / exchangeRate * 1e18;", positive_text)
        self.assertIn("token.transfer(feeRecipient, feeAmount);", positive_text)
        self.assertIn("borrow = getBorrowRate();", positive_text)
        self.assertIn("supply = getSupplyRate();", positive_text)

        self.assertIn("accrueInterest();", clean_text)
        self.assertIn("MathLike.mulDiv(shares, 1e18, exchangeRate)", clean_text)
        self.assertIn("require(assets > 0", clean_text)
        self.assertIn("token.transfer(treasury, feeAmount);", clean_text)

    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_output = self._hits(POSITIVE)
        clean_hits, clean_output = self._hits(CLEAN)

        self.assertGreaterEqual(positive_hits, 3, positive_output)
        self.assertEqual(clean_hits, 0, clean_output)

    def test_confirmed_scoreboard_fixtures_are_caught(self) -> None:
        ec_hits, ec_output = self._hits(EC_CONFIRMED)
        fee_hits, fee_output = self._hits(FEE_CONFIRMED)

        self.assertGreaterEqual(ec_hits, 1, ec_output)
        self.assertGreaterEqual(fee_hits, 1, fee_output)


if __name__ == "__main__":
    unittest.main()
