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
DETECTOR = ROOT / "detectors" / "wave17" / "oracle_threshold_scale_mismatch_fire28.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "oracle_threshold_scale_mismatch_fire28.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "oracle_threshold_scale_mismatch_fire28.sol"
)
PATTERN = "oracle-threshold-scale-mismatch-fire28"


def _load_detector():
    spec = importlib.util.spec_from_file_location("oracle_threshold_scale_mismatch_fire28", DETECTOR)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["oracle_threshold_scale_mismatch_fire28"] = mod
    spec.loader.exec_module(mod)
    return mod


class OracleThresholdScaleMismatchFire28Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', text)
        self.assertIn("maxmin-raw-comparison-across-different-decimals.yaml", text)
        self.assertIn("scaled-vs-unscaled-threshold-comparison.yaml", text)
        self.assertIn("incorrect-handling-of-pricefeed-decimals-only-works-for-8-dec-feeds.yaml", text)
        self.assertIn("hardcoded-8-decimal-feed-assumption", text)
        self.assertIn("raw-oracle-threshold-scale-mismatch", text)
        self.assertIn("scaled-runtime-value-vs-unscaled-threshold", text)
        self.assertIn("raw-minmax-across-different-decimal-domains", text)

    def test_fixture_text_covers_positive_and_negative_boundaries(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("require(rawEthPrice <= maxOraclePrice", positive)
        self.assertIn("healthFactor < MIN_HEALTH_FACTOR", positive)
        self.assertIn("Math.min(usdcPrice, wbtcPrice)", positive)
        self.assertIn("return collateralAmount * oraclePrice / 1e8;", positive)

        self.assertIn("uint8 feedDecimals = ethFeed.decimals();", negative)
        self.assertIn("require(normalizedPrice <= MAX_ORACLE_PRICE_WAD", negative)
        self.assertIn("healthFactor < MIN_HEALTH_FACTOR_WAD", negative)
        self.assertIn("Math.min(usdcPrice, wbtcPrice)", negative)
        self.assertIn("uint8 priceDecimals = ethFeed.decimals();", negative)
        self.assertIn("10 ** (18 - feedDecimals)", negative)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        mod = _load_detector()
        positive_hits = mod.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        negative_hits = mod.scan(NEGATIVE.read_text(encoding="utf-8"), str(NEGATIVE))

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertGreaterEqual(len(positive_hits), 4, messages)
        self.assertIn("raw-oracle-threshold-scale-mismatch", messages)
        self.assertIn("scaled-runtime-value-vs-unscaled-threshold", messages)
        self.assertIn("raw-minmax-across-different-decimal-domains", messages)
        self.assertIn("hardcoded-8-decimal-feed-assumption", messages)
        self.assertEqual(negative_hits, [])

    def test_regex_runner_positive_fixture_fires_and_negative_stays_quiet(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oracle_threshold_scale_mismatch_fire28_") as tmp:
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
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)
            self.assertIn(PATTERN, positive_proc.stdout)
            self.assertIn("raw-oracle-threshold-scale-mismatch", positive_proc.stdout)

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
            self.assertGreaterEqual(positive_data["per_detector_counts"][PATTERN], 4)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)


if __name__ == "__main__":
    unittest.main()
