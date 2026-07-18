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
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "rounding_direction_attack_fire21.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rounding-direction-attack-fire21"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rounding_direction_attack_fire21.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rounding_direction_attack_fire21.sol"
)


def _load_detector():
    module_name = "rounding_direction_attack_fire21"
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


class RoundingDirectionAttackFire21Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(__file__, doraise=True)
        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")

    def test_positive_fixture_fires_on_confirmed_value_rounding_shapes(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 4)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {"updateRewardPerToken", "flashLoan", "liquidate", "swapExactTokens"},
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("divides before scaling", messages)
        self.assertIn("nonzero fee guard", messages)
        self.assertIn("liquidation fee or collateral", messages)
        self.assertIn("zero or unbounded minimum output", messages)

    def test_negative_fixture_rounds_conservatively_and_stays_quiet(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean_text = _read(NEGATIVE)
        self.assertIn("(reward * PRECISION) / totalSupply", clean_text)
        self.assertIn("require(fee > 0 || amount == 0", clean_text)
        self.assertIn("_mulDivUp(debt, liquidationFeeBps, BPS)", clean_text)
        self.assertIn("require(minOut > 0", clean_text)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire21_rounding_direction_") as tmp:
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

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 4)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )


if __name__ == "__main__":
    unittest.main()
