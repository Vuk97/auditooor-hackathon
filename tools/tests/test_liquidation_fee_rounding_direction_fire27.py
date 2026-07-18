from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "liquidation_fee_rounding_direction_fire27.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "liquidation-fee-rounding-direction-fire27"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "liquidation_fee_rounding_direction_fire27.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "liquidation_fee_rounding_direction_fire27.sol"
)
SOURCE_REFS = (
    ROOT / "reference" / "patterns.dsl" / "fx-aave-liquidation-fee-rounding-direction.yaml",
    ROOT / "reference" / "patterns.dsl" / "ec-reward-per-token-precision-loss.yaml",
    ROOT / "reference" / "patterns.dsl" / "flashloan-no-fee-charged.yaml",
)


def _load_detector():
    module_name = "liquidation_fee_rounding_direction_fire27"
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


class LiquidationFeeRoundingDirectionFire27Test(unittest.TestCase):
    def test_detector_compile_and_provenance(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        detector_text = _read(DETECTOR_PATH)

        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertIn("attack_class: rounding-direction-attack", detector_text)
        self.assertIn("fx-aave-liquidation-fee-rounding-direction.yaml", detector_text)
        self.assertIn("ec-reward-per-token-precision-loss.yaml", detector_text)
        self.assertIn("flashloan-no-fee-charged.yaml", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        for source_ref in SOURCE_REFS:
            self.assertTrue(source_ref.exists(), source_ref)

    def test_positive_fixture_fires_on_liquidation_and_repay_rounding(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {"liquidate", "repayWithCloseFactor", "executeLiquidationCall"},
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("divides liquidation or repay value before applying", messages)
        self.assertIn("floor-rounds liquidation or repay fee math to zero", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_negative_fixture_uses_upward_rounding_and_is_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean_text = _read(NEGATIVE)
        self.assertIn("Math.Rounding.Up", clean_text)
        self.assertIn("repayFee < minimumProtocolFee", clean_text)
        self.assertIn("rayDivCeil", clean_text)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire27_liquidation_rounding_") as tmp:
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
                cwd=ROOT,
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
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 3)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
