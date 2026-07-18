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
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "balancer_surge_fee_underflow_fire27.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "balancer-surge-fee-underflow-fire27"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "balancer_surge_fee_underflow_fire27.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "balancer_surge_fee_underflow_fire27.sol"
)


def _load_detector():
    module_name = "balancer_surge_fee_underflow_fire27"
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


class BalancerSurgeFeeUnderflowFire27Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(__file__, doraise=True)
        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")

    def test_provenance_and_fixture_boundaries_are_pinned(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn("fx-balancer-surge-fee-underflow.yaml", detector_text)
        self.assertIn("flashloan-fee-underflow-or-missing.yaml", detector_text)
        self.assertIn("fx-euler-irm-kink-type-truncation.yaml", detector_text)
        self.assertIn("integer-overflow-clamp", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("maxSurgeFeePercentage - staticSwapFeePercentage", positive_text)
        self.assertIn("? 0", positive_text)
        self.assertIn("targetBalance - poolBalance", positive_text)
        self.assertIn("return staticSwapFeePercentage;", positive_text)

        self.assertIn("return staticSwapFeePercentage;", negative_text)
        self.assertIn("Fire27Math.absDiff", negative_text)
        self.assertIn("poolBalance >= targetBalance", negative_text)
        self.assertIn("poolImbalanceRatio <= poolStressThreshold", negative_text)
        self.assertIn("Fire27Math.mulDiv", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 4)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {
                "computeSurgeFeeUncheckedRange",
                "computeDynamicFeeClampedOnStress",
                "computeBalanceImbalanceUnderflow",
                "computeStressBranchReturnsBaseFee",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("max-surge minus static-fee", messages)
        self.assertIn("clamps the fee delta to zero", messages)
        self.assertIn("target minus current pool-imbalance", messages)
        self.assertIn("returns base, static, or zero fee", messages)
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
        with tempfile.TemporaryDirectory(prefix="fire27_balancer_surge_fee_") as tmp:
            positive_data = self._run_regex_runner(POSITIVE, Path(tmp) / "positive.json")
            negative_data = self._run_regex_runner(NEGATIVE, Path(tmp) / "negative.json")

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 4)
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
