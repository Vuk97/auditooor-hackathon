from __future__ import annotations

import importlib.util
import json
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "arithmetic_conversion_order_fire33.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "arithmetic_conversion_order_fire33.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "arithmetic_conversion_order_fire33.sol"
)
PATTERN = "arithmetic-conversion-order-fire33"


def _load_detector():
    module_name = "arithmetic_conversion_order_fire33"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class ArithmeticConversionOrderFire33Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("fund-loss-via-arithmetic", detector_text)
        self.assertIn("reports/detector_lift_fire32_20260605/post_priorities_all.md", detector_text)
        self.assertIn("fund-loss-via-arithmetic-value-math.yaml", detector_text)
        self.assertIn("fund-loss-via-arithmetic-conversion-output-zero.yaml", detector_text)
        self.assertIn("oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals.yaml", detector_text)
        self.assertIn("conversion-divides-before-multiply", detector_text)
        self.assertIn("scale-or-denominator-divided-before-multiply", detector_text)
        self.assertIn("hardcoded-oracle-scale-without-feed-decimals", detector_text)
        self.assertIn("truncated-output-after-state-debit", detector_text)

    def test_fixture_text_covers_positive_and_negative_boundaries(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("uint256 mintedShares = assets / totalAssets * totalShares;", positive)
        self.assertIn("uint256 rewardAmount = stake[msg.sender] / totalStake * rewardPool;", positive)
        self.assertIn("uint256 feeAmount = tradeAmount / BPS * feeBps;", positive)
        self.assertIn("uint256 receiptShares = assetAmount * uint256(answer) / 1e18;", positive)
        self.assertIn("uint256 assetsOut = shareAmount / WAD * exchangeRate;", positive)
        self.assertIn("uint256 debtCredit = collateralAmount / WAD * exchangeRate;", positive)
        self.assertIn("priceFeed.latestRoundData()", positive)
        self.assertNotIn("priceFeed.decimals()", positive)

        self.assertIn("uint256 mintedShares = MathLike.mulDiv(assets, totalShares, totalAssets);", negative)
        self.assertIn('require(mintedShares > 0, "zero shares");', negative)
        self.assertIn("uint256 feeAmount = MathLike.mulDiv(tradeAmount, feeBps, BPS);", negative)
        self.assertIn("uint8 feedDecimals = priceFeed.decimals();", negative)
        self.assertIn("10 ** uint256(feedDecimals)", negative)
        self.assertIn("function previewUnsafeFormula", negative)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        negative_hits = detector.scan(NEGATIVE.read_text(encoding="utf-8"), str(NEGATIVE))

        self.assertEqual(len(negative_hits), 0)
        self.assertGreaterEqual(len(positive_hits), 6)
        self.assertEqual({hit.detector for hit in positive_hits}, {PATTERN})
        self.assertEqual({hit.severity for hit in positive_hits}, {"Medium"})

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("depositDividesBeforeMultiplying", messages)
        self.assertIn("claimRewardDividesBeforeMultiplying", messages)
        self.assertIn("collectFeeWithWrongScaleOrder", messages)
        self.assertIn("depositWithHardcodedOracleScale", messages)
        self.assertIn("redeemTruncatesBeforeMovingValue", messages)
        self.assertIn("repayWithWrongScaleOrder", messages)
        self.assertIn("mintedShares", messages)
        self.assertIn("rewardAmount", messages)
        self.assertIn("feeAmount", messages)
        self.assertIn("receiptShares", messages)
        self.assertIn("assetsOut", messages)
        self.assertIn("debtCredit", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

        branches = {hit.branch for hit in positive_hits}
        self.assertIn("scale-or-denominator-divided-before-multiply:external-token-movement", branches)
        self.assertIn("conversion-divides-before-multiply:accounting-write", branches)
        self.assertIn("hardcoded-oracle-scale-without-feed-decimals:external-token-movement", branches)

    def test_regex_runner_positive_fixture_fires_and_negative_stays_quiet(self) -> None:
        with tempfile.TemporaryDirectory(prefix="arithmetic_conversion_order_fire33_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            positive_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(POSITIVE),
                    "--detector",
                    PATTERN,
                    "--output",
                    str(positive_manifest),
                    "--workspace",
                    str(ROOT),
                    "--json-only",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)

            negative_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(NEGATIVE),
                    "--detector",
                    PATTERN,
                    "--output",
                    str(negative_manifest),
                    "--workspace",
                    str(ROOT),
                    "--json-only",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertGreaterEqual(positive_data["per_detector_counts"][PATTERN], 6)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
