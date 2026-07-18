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
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "integer_fee_underflow_clamp_fire35.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "integer-fee-underflow-clamp-fire35"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "integer_fee_underflow_clamp_fire35.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "integer_fee_underflow_clamp_fire35.sol"
)


def _load_detector():
    module_name = "integer_fee_underflow_clamp_fire35"
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


class IntegerFeeUnderflowClampFire35Test(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(__file__, doraise=True)
        detector = _load_detector()
        detector_text = _read(DETECTOR_PATH)

        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertIn("integer-overflow-clamp", detector_text)
        self.assertIn("post_priorities_all.md", detector_text)
        self.assertIn("integer-clamp-fee-or-debt-underflow-boundary.yaml", detector_text)
        self.assertIn("integer-overflow-clamp-arithmetic-loss.yaml", detector_text)
        self.assertIn("fx-balancer-surge-fee-underflow.yaml", detector_text)
        self.assertIn("integer_clamp_fee_scale_fire34.py", detector_text)
        self.assertIn("flashloan_fee_underflow_or_missing.py", detector_text)

    def test_positive_fixture_fires_on_fee_underflow_clamps(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 6)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "flashLoanPayoutAfterPremium",
                "swapOutputAfterProtocolFee",
                "borrowRepaymentAfterFeeCredit",
                "liquidationProceedsAfterFee",
                "balancerLikeSurgeFeeRange",
                "positiveBranchOnlyFeeClamp",
            },
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("netAmount subtracts premiumFee before the cap or floor", messages)
        self.assertIn("netOut subtracts protocolFee before the cap or floor", messages)
        self.assertIn("amountDue subtracts upfrontFee before the cap or floor", messages)
        self.assertIn("borrowerProceeds subtracts liquidationFee before the cap or floor", messages)
        self.assertIn("surgeRange subtracts staticSwapFeePercentage before the cap or floor", messages)
        self.assertIn("amountAfterFee only subtracts protocolFee on the positive branch", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_negative_fixture_guards_fee_before_subtraction(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean_text = _read(NEGATIVE)
        self.assertIn("require(premiumFee <= amount", clean_text)
        self.assertIn("feeToCharge = protocolFee > amountOut ? amountOut : protocolFee", clean_text)
        self.assertIn("if (upfrontFee >= principal)", clean_text)
        self.assertIn("if (liquidationFee > collateralValue)", clean_text)
        self.assertIn("if (staticSwapFeePercentage >= maxSurgeFeePercentage)", clean_text)
        self.assertIn("uint64 packedEpoch = uint64(epoch)", clean_text)

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
        with tempfile.TemporaryDirectory(prefix="fire35_fee_underflow_clamp_") as tmp:
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
