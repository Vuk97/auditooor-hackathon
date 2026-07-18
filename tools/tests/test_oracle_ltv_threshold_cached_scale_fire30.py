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
DETECTOR = ROOT / "detectors" / "wave17" / "oracle_ltv_threshold_cached_scale_fire30.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "oracle_ltv_threshold_cached_scale_fire30.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "oracle_ltv_threshold_cached_scale_fire30.sol"
)
PATTERN = "oracle-ltv-threshold-cached-scale-fire30"


def _load_detector():
    module_name = "oracle_ltv_threshold_cached_scale_fire30"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class OracleLtvThresholdCachedScaleFire30Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("oracle-price-manipulation", detector_text)
        self.assertIn("post_priorities_solidity.md", detector_text)
        self.assertIn("erc4626-share-price-used-as-collateral-oracle.yaml", detector_text)
        self.assertIn("oracle-config-changes-do-not-invalidate-cached-prices.yaml", detector_text)
        self.assertIn("asymmetrical-norm-in-price-update-threshold.yaml", detector_text)
        self.assertIn("config-change-without-cache-invalidation", detector_text)

    def test_fixture_text_covers_positive_and_negative_boundaries(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("risk[asset] = RiskConfig", positive)
        self.assertIn("cachedOracleScale[asset] = 10 ** (18 - config.feedDecimals);", positive)
        self.assertIn("collateralBalance[user][asset] * cachedPrice[asset] * cachedOracleScale[asset]", positive)
        self.assertIn("return collateralValue * config.ltvBps / BPS;", positive)
        self.assertIn("config.liquidationThresholdBps", positive)

        self.assertIn("delete cachedPrice[asset];", negative)
        self.assertIn("delete cachedOracleScale[asset];", negative)
        self.assertIn("uint8 feedDecimals = config.oracle.decimals();", negative)
        self.assertIn("_freshScaledPrice(asset)", negative)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        negative_hits = detector.scan(NEGATIVE.read_text(encoding="utf-8"), str(NEGATIVE))

        self.assertEqual(len(negative_hits), 0)
        self.assertGreaterEqual(len(positive_hits), 2)
        self.assertEqual({hit.detector for hit in positive_hits}, {PATTERN})
        self.assertEqual({hit.severity for hit in positive_hits}, {"High"})

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("config-change-without-cache-invalidation", messages)
        self.assertIn("setOracleRiskConfig", messages)
        self.assertIn("cachedPrice", messages)
        self.assertIn("maxBorrowValue", messages)
        self.assertIn("isLiquidatable", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_regex_runner_positive_fixture_fires_and_negative_stays_quiet(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oracle_ltv_threshold_cached_scale_fire30_") as tmp:
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

            self.assertGreaterEqual(positive_data["per_detector_counts"][PATTERN], 2)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
