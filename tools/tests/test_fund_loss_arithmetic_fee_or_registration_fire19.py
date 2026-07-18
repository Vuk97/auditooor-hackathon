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
PATTERN = "fund-loss-arithmetic-fee-or-registration-fire19"
DETECTOR = ROOT / "detectors" / "wave17" / "fund_loss_arithmetic_fee_or_registration_fire19.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "fund_loss_arithmetic_fee_or_registration_fire19.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "fund_loss_arithmetic_fee_or_registration_fire19.sol"
)


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "python3",
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


class FundLossArithmeticFeeOrRegistrationFire19Test(unittest.TestCase):
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
        negative_text = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("caller-controlled fee sink", detector_text)
        self.assertIn("duplicate registration", detector_text)
        self.assertIn("bare uint128 cast", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("token.safeTransfer(referralSink, referralFee);", positive_text)
        self.assertIn("_registerPoolWithVault(pool);", positive_text)
        self.assertIn("_registerPoolWithFactory(pool);", positive_text)
        self.assertIn("claimable[msg.sender] += (amount * creditRate) / 1e18;", positive_text)
        self.assertIn("uint128 amount = uint128(delta);", positive_text)

        self.assertIn("approvedReferral[referralSink]", negative_text)
        self.assertIn("require(!registeredPool[pool]", negative_text)
        self.assertIn("require(!registered[msg.sender]", negative_text)
        self.assertIn("require(delta >= 0", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_output = self._hits(POSITIVE)
        negative_hits, negative_output = self._hits(NEGATIVE)

        self.assertGreaterEqual(positive_hits, 4, positive_output)
        self.assertEqual(negative_hits, 0, negative_output)


if __name__ == "__main__":
    unittest.main()
