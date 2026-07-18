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
PATTERN = "oracle-price-bounds-or-asymmetric-min-fire18"
DETECTOR = ROOT / "detectors" / "wave17" / "oracle_price_bounds_or_asymmetric_min_fire18.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "oracle_price_bounds_or_asymmetric_min_fire18.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "oracle_price_bounds_or_asymmetric_min_fire18.sol"
)


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


class OraclePriceBoundsOrAsymmetricMinFire18Test(unittest.TestCase):
    def _run_detector(self, fixture: Path) -> tuple[int, str]:
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_compiles_and_declares_candidate_posture(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("symmetric-min-price-sides", detector_text)
        self.assertIn("missing-oracle-bound-or-freshness", detector_text)
        self.assertIn("ltv-liquidation-threshold-bound-missing", detector_text)
        self.assertIn("hardcoded-oracle-price-denominator", detector_text)
        self.assertIn("oracle-supply-tally-refresh-missing", detector_text)

    def test_positive_and_negative_fixture_semantics(self) -> None:
        positive_text = POSITIVE.read_text(encoding="utf-8")
        negative_text = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("uint256 price = _min(chainlink.getPrice(), twap.getPrice());", positive_text)
        self.assertIn("function setLtv(uint256 newLtv) external", positive_text)
        self.assertIn("return collateralAmount * oraclePrice / 1e18;", positive_text)
        self.assertNotIn("feedDecimals", positive_text)
        self.assertNotIn("block.timestamp - updatedAt <= MAX_STALE", positive_text)

        self.assertIn("uint256 collateralPrice = _min(primaryPrice, fallbackPrice);", negative_text)
        self.assertIn("uint256 debtPrice = _max(primaryPrice, fallbackPrice);", negative_text)
        self.assertIn("require(newLtv <= liquidationThreshold", negative_text)
        self.assertIn("block.timestamp - updatedAt <= MAX_STALE", negative_text)
        self.assertIn("uint8 feedDecimals = priceFeed.decimals();", negative_text)
        self.assertIn("_accrue();", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_stays_quiet(self) -> None:
        positive_hits, positive_stdout = self._run_detector(POSITIVE)
        negative_hits, negative_stdout = self._run_detector(NEGATIVE)

        self.assertGreaterEqual(positive_hits, 4, positive_stdout)
        self.assertEqual(negative_hits, 0, negative_stdout)
        self.assertIn("symmetric-min-price-sides", positive_stdout)
        self.assertIn("missing-oracle-bound-or-freshness", positive_stdout)
        self.assertIn("ltv-liquidation-threshold-bound-missing", positive_stdout)
        self.assertIn("hardcoded-oracle-price-denominator", positive_stdout)


if __name__ == "__main__":
    unittest.main()
