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
DETECTOR_PATH = (
    ROOT
    / "detectors"
    / "wave17"
    / "integer_clamp_decimal_or_claim_underflow_fire18.py"
)
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "integer-clamp-decimal-or-claim-underflow-fire18"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "integer_clamp_decimal_or_claim_underflow_fire18.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "integer_clamp_decimal_or_claim_underflow_fire18.sol"
)
FIRE17_POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "integer_clamp_supply_or_fee_truncation_fire17.sol"
)


def _load_detector():
    module_name = "integer_clamp_decimal_or_claim_underflow_fire18"
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


class IntegerClampDecimalOrClaimUnderflowFire18Test(unittest.TestCase):
    def test_detector_compiles_and_declares_expected_name(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")

    def test_positive_fixture_fires_on_claim_decimal_and_price_shapes(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {"claim", "handleDeposit", "checkRatio"},
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("raw total minus claimed", messages)
        self.assertIn("decimals greater than 18 branch", messages)
        self.assertIn("threshold check can truncate", messages)

    def test_negative_fixture_keeps_same_arithmetic_but_stays_quiet(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean_text = _read(NEGATIVE)
        self.assertIn("if (total >= alreadyClaimed[msg.sender])", clean_text)
        self.assertIn("if (d > 18)", clean_text)
        self.assertIn("FullMathFire18.mulDiv(fromPrice, PRECISION, toPrice)", clean_text)

    def test_does_not_duplicate_fire17_fee_debt_supply_fixture(self) -> None:
        detector = _load_detector()
        self.assertEqual(detector.scan(_read(FIRE17_POSITIVE), str(FIRE17_POSITIVE)), [])

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire18_integer_clamp_") as tmp:
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"
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


if __name__ == "__main__":
    unittest.main()
