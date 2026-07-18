from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "fund_loss_external_transfer_math_fire36.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "fund_loss_external_transfer_math_fire36.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "fund_loss_external_transfer_math_fire36.sol"
)
PATTERN = "fund-loss-external-transfer-math-fire36"


def _load_detector():
    module_name = "fund_loss_external_transfer_math_fire36"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class FundLossExternalTransferMathFire36Test(unittest.TestCase):
    def test_detector_and_fixtures_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("PROMOTION_ALLOWED = False", detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("fund-loss-via-arithmetic", detector_text)
        self.assertIn("fund-loss-via-arithmetic-value-math.yaml", detector_text)
        self.assertIn("fund_loss_memory_writeback_fire35.py", detector_text)
        self.assertIn("integer_clamp_fee_scale_fire34.py", detector_text)

        self.assertIn("uint256 assets = shares / totalShares * poolAssets;", positive_text)
        self.assertIn("uint128 burnAmount = uint128(rawDebt * debtIndex / SCALE);", positive_text)
        self.assertIn("uint256 cachedScale = shareScale;", positive_text)
        self.assertIn("Position memory position = positions[user];", positive_text)
        self.assertIn("debtLedger.settleDebt(user, repayAmount);", positive_text)

        self.assertIn("uint256 assets = Math.mulDiv(shares, poolAssets, totalShares);", negative_text)
        self.assertIn("require(wideBurn <= type(uint128).max", negative_text)
        self.assertIn("_refreshShareScale();", negative_text)
        self.assertIn("positions[user] = position;", negative_text)
        self.assertIn("function quoteOnly", negative_text)

    def test_direct_scan_positive_fires_and_negative_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_hits = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(negative_hits, [])
        self.assertEqual(len(positive_hits), 4, positive_hits)
        self.assertEqual({hit.detector for hit in positive_hits}, {PATTERN})
        self.assertEqual({hit.severity for hit in positive_hits}, {"Medium"})
        self.assertEqual(
            {hit.function for hit in positive_hits},
            {
                "withdrawRounded",
                "burnPackedDebt",
                "mintWithStaleScale",
                "repayFromMemory",
            },
        )

        messages = "\n".join(hit.message for hit in positive_hits)
        self.assertIn("lossy-division-before-transfer-amount", messages)
        self.assertIn("narrow-cast-before-transfer-amount", messages)
        self.assertIn("stale-scale-before-transfer-amount", messages)
        self.assertIn("memory-writeback-before-debt-settlement", messages)
        self.assertIn("external-value-movement sink", messages)
        self.assertIn("debt-settlement sink", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_direct_scan_ignores_no_sink_and_internal_paths(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.24;
        contract NoSink {
            uint256 public totalShares;
            uint256 public poolAssets;
            function quote(uint256 shares) external view returns (uint256) {
                uint256 assets = shares / totalShares * poolAssets;
                return assets;
            }
            function helper(uint256 shares) internal returns (uint256) {
                uint256 assets = shares / totalShares * poolAssets;
                return assets;
            }
        }
        """
        self.assertEqual(detector.scan(source, "NoSink.sol"), [])

    def test_regex_runner_positive_fixture_fires_and_negative_stays_quiet(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fund_loss_external_transfer_math_fire36_") as tmp:
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
                    tmp,
                    "--json-only",
                ],
                cwd=ROOT,
                env=env,
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
                    tmp,
                    "--json-only",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=60,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][PATTERN], 4)
            self.assertEqual(negative_data["per_detector_counts"][PATTERN], 0)
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
