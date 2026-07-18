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


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "irm_kink_truncation_fire28.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "irm_kink_truncation_fire28.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "irm_kink_truncation_fire28.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "irm-kink-truncation-fire28"


def _load_detector():
    module_name = "irm_kink_truncation_fire28"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class IrmKinkTruncationFire28Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("amm-quote-overflow-can-disable-swaps-and-liquidations", detector_text)
        self.assertIn("scaled-vs-unscaled-threshold-comparison", detector_text)
        self.assertIn("integer-overflow-clamp", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("function borrowRate", positive_text)
        self.assertIn("uint64 kink = uint64(kinkRay);", positive_text)
        self.assertIn("uint128 maxRate = uint128(maxRateRay);", positive_text)
        self.assertIn("if (utilizationWad > KINK)", positive_text)
        self.assertIn("return amountInWithFee / reserveIn * reserveOut;", positive_text)

        self.assertIn("using SafeCast for uint256;", negative_text)
        self.assertIn("kinkWad.toUint64();", negative_text)
        self.assertIn("FixedPointMathLib.mulDiv", negative_text)
        self.assertIn("if (utilizationWad > KINK_WAD)", negative_text)
        self.assertIn("uint256 minimumHealthBps = 12000;", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertGreaterEqual(len(positive_findings), 3)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertIn("borrowRate", {finding.function for finding in positive_findings})
        self.assertIn("quoteAmountOut", {finding.function for finding in positive_findings})
        self.assertIn("healthRate", {finding.function for finding in positive_findings})

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("SafeCast", messages)
        self.assertIn("fixed-point normalization", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_guarded_inline_sources_are_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        library Math {
            function mulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
                return x * y / d;
            }
        }
        contract GuardedRateMath {
            uint256 constant WAD = 1e18;
            uint256 constant KINK_WAD = 0.8e18;
            function getBorrowRate(uint256 cash, uint256 borrows, uint256 maxRateWad)
                public
                pure
                returns (uint256)
            {
                uint256 utilizationWad = Math.mulDiv(borrows, WAD, cash + borrows);
                if (utilizationWad > KINK_WAD) {
                    return Math.mulDiv(maxRateWad, utilizationWad, WAD);
                }
                return Math.mulDiv(utilizationWad, maxRateWad, KINK_WAD);
            }
        }
        """
        self.assertEqual(detector.scan(source, "GuardedRateMath.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire28_irm_kink_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            positive_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(POSITIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(positive_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)

            negative_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(NEGATIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(negative_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertGreaterEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 3)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
