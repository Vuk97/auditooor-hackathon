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
DETECTOR = ROOT / "detectors" / "wave17" / "value_math_transfer_rounding_fire31.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "value_math_transfer_rounding_fire31.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "value_math_transfer_rounding_fire31.sol"
)
PATTERN = "value-math-transfer-rounding-fire31"


def _load_detector():
    module_name = "value_math_transfer_rounding_fire31"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class ValueMathTransferRoundingFire31Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("fund-loss-via-arithmetic", detector_text)
        self.assertIn("post_priorities_all.md", detector_text)
        self.assertIn("fund-loss-value-math-external-transfer-fire10.yaml", detector_text)
        self.assertIn("value_math_constructor_scale_fire29.py", detector_text)
        self.assertIn("division-before-multiplication-transfer-rounding", detector_text)
        self.assertIn("hardcoded-scale-transfer-conversion", detector_text)
        self.assertIn("unchecked-division-rounded-transfer-amount", detector_text)

    def test_fixture_text_covers_positive_and_negative_boundaries(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("uint256 sharesMinted = assets / index * WAD;", positive)
        self.assertIn("uint256 assetsOut = value / price * 1e18;", positive)
        self.assertIn("uint256 payoutAmount = rewardUnits * 1e18 / exchangeRate;", positive)
        self.assertIn("asset.transfer(msg.sender, assetsOut);", positive)
        self.assertIn("shares[msg.sender] += sharesMinted;", positive)

        self.assertIn("uint256 sharesMinted = MathLike.mulDiv(assets, WAD, index);", negative)
        self.assertIn('require(sharesMinted >= minShares, "min shares");', negative)
        self.assertIn("uint256 assetsOut = MathLike.mulDiv(value, WAD, price);", negative)
        self.assertIn('require(assetsOut >= minAssetsOut, "min assets");', negative)
        self.assertIn("function previewUnsafeFormula", negative)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(POSITIVE.read_text(encoding="utf-8"), str(POSITIVE))
        negative_hits = detector.scan(NEGATIVE.read_text(encoding="utf-8"), str(NEGATIVE))

        self.assertEqual(len(negative_hits), 0)
        self.assertGreaterEqual(len(positive_hits), 3)
        self.assertEqual({hit.detector for hit in positive_hits}, {PATTERN})
        self.assertEqual({hit.severity for hit in positive_hits}, {"Medium"})

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("depositWithIndex", messages)
        self.assertIn("redeemByValue", messages)
        self.assertIn("claimWithHardcodedScale", messages)
        self.assertIn("sharesMinted", messages)
        self.assertIn("assetsOut", messages)
        self.assertIn("payoutAmount", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_regex_runner_positive_fixture_fires_and_negative_stays_quiet(self) -> None:
        with tempfile.TemporaryDirectory(prefix="value_math_transfer_rounding_fire31_") as tmp:
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

            self.assertGreaterEqual(positive_data["per_detector_counts"][PATTERN], 3)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
