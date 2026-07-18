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
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "integer_clamp_underflow_fire38.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "integer-clamp-underflow-fire38"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "integer_clamp_underflow_fire38.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "integer_clamp_underflow_fire38.sol"
)


def _load_detector():
    module_name = "integer_clamp_underflow_fire38"
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


class IntegerClampUnderflowFire38Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(__file__, doraise=True)
        detector = _load_detector()
        detector_text = _read(DETECTOR_PATH)

        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertIn("integer-overflow-clamp", detector_text)
        self.assertIn("post_priorities_solidity.md", detector_text)
        self.assertIn("fund_loss_external_transfer_math_fire36.py", detector_text)
        self.assertIn("unsafe-downcast-uint-truncation.yaml", detector_text)
        self.assertIn("flashloan-fee-underflow-or-missing", detector_text)
        self.assertIn("fx-balancer-surge-fee-underflow", detector_text)
        self.assertIn(".auditooor/memory_context_receipt.json", detector_text)

    def test_fixture_sources_pin_boundaries(self) -> None:
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn("amount - premiumFee", positive_text)
        self.assertIn("maxSurgeFeePercentage - staticSwapFeePercentage", positive_text)
        self.assertIn("utilization - kinkRate", positive_text)
        self.assertIn("amount * feeBps", positive_text)
        self.assertIn("uint8(flashFeeBps)", positive_text)
        self.assertIn("uint16(kinkRate)", positive_text)

        self.assertIn("require(premiumFee <= amount", negative_text)
        self.assertIn("maxSurgeFeePercentage <= staticSwapFeePercentage", negative_text)
        self.assertIn("utilization <= kinkRate", negative_text)
        self.assertIn("Fire38Math.mulDiv(amount, feeBps, BPS)", negative_text)
        self.assertIn("SafeCast.toUint8(flashFeeBps)", negative_text)
        self.assertIn("require(kinkRate <= type(uint16).max", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 6)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {
                "flashLoanNetAfterPremium",
                "balancerSurgeRangeClamp",
                "irmBorrowRateAboveKink",
                "flashLoanFeeOverflowThenClamp",
                "packedFlashFeeCanZero",
                "packedKinkRateCanZero",
            },
        )
        self.assertEqual(
            {finding.branch for finding in positive_findings},
            {"subtract-before-bound", "overflow-before-clamp", "unsafe-cast-zero"},
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("subtracts premiumFee before checking the lower bound", messages)
        self.assertIn("subtracts staticSwapFeePercentage before checking the lower bound", messages)
        self.assertIn("subtracts kinkRate before checking the lower bound", messages)
        self.assertIn("computes fee or rate arithmetic before applying the cap", messages)
        self.assertIn("narrows flashFeeBps to uint8 before range validation", messages)
        self.assertIn("narrows kinkRate to uint16 before range validation", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def _run_regex_runner(self, target: Path, manifest: Path) -> dict:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                str(target),
                "--workspace",
                str(manifest.parent),
                "--output",
                str(manifest),
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
        self.assertEqual(proc.returncode, 0, proc.stdout)
        return json.loads(manifest.read_text(encoding="utf-8"))

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire38_integer_clamp_underflow_") as tmp:
            positive_data = self._run_regex_runner(POSITIVE, Path(tmp) / "positive.json")
            negative_data = self._run_regex_runner(NEGATIVE, Path(tmp) / "negative.json")

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 6)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(positive_data["files_scanned"], 1)
            self.assertEqual(negative_data["files_scanned"], 1)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
