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
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "rounding_direction_attack_fire22.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rounding-direction-attack-fire22"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rounding_direction_attack_fire22.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rounding_direction_attack_fire22.sol"
)


def _load_detector():
    module_name = "rounding_direction_attack_fire22"
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


class RoundingDirectionAttackFire22Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(__file__, doraise=True)
        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")

    def test_positive_fixture_fires_on_public_reward_floor_to_zero(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {"pokeRewards", "checkpointRewards", "distributeEpochReward"},
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("advances reward state", messages)
        self.assertIn("floor-divided reward-per-share increment", messages)
        self.assertIn("no dust carry or nonzero increment guard", messages)

    def test_negative_fixture_has_scaling_carry_or_nonzero_guard(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean_text = _read(NEGATIVE)
        self.assertIn("rewardRemainder", clean_text)
        self.assertIn("(rewardDelta * ACC_PRECISION) / totalStaked", clean_text)
        self.assertIn("require(rewardPerShareDelta > 0 || newRewards == 0", clean_text)
        self.assertIn("_mulDivUp(rewardAmount, ACC_PRECISION, totalStaked)", clean_text)
        self.assertIn("if (shareIncrement == 0) return;", clean_text)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire22_rounding_direction_") as tmp:
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

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
