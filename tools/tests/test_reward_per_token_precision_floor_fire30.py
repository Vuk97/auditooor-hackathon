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
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "reward_per_token_precision_floor_fire30.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "reward-per-token-precision-floor-fire30"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "reward_per_token_precision_floor_fire30.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "reward_per_token_precision_floor_fire30.sol"
)


def _load_detector():
    module_name = "reward_per_token_precision_floor_fire30"
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


class RewardPerTokenPrecisionFloorFire30Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")

    def test_positive_fixture_fires_on_reward_fee_and_share_flooring(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 4)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "distributeRewardsDirect",
                "distributeRewardsViaTemp",
                "borrowWithFeeFloor",
                "withdrawWithShareFloor",
            },
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("reward per token precision floor", messages)
        self.assertIn("fee precision floor", messages)
        self.assertIn("share conversion precision floor", messages)
        self.assertIn("scale before dividing", messages)

    def test_negative_fixture_scale_first_muldiv_guards_and_bait_are_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean_text = _read(NEGATIVE)
        self.assertIn("(rewardAmount * ACC_PRECISION) / totalStaked", clean_text)
        self.assertIn("Fire30Math.mulDiv(rewardAmount, ACC_PRECISION, totalStaked)", clean_text)
        self.assertIn("if (perTokenFloor == 0) return;", clean_text)
        self.assertIn("queuedRewardRemainder += rewardRemainder;", clean_text)
        self.assertIn("principal * exitFeeBps / FEE_DENOMINATOR", clean_text)
        self.assertIn("Fire30Math.mulDiv(shareAmount, totalAssets, totalShares)", clean_text)
        self.assertIn("rewardPerTokenStored += (rewardAmount / totalStaked) * ACC_PRECISION", clean_text)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire30_reward_precision_floor_") as tmp:
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            for fixture, manifest, expected_hits in (
                (POSITIVE, positive_manifest, 4),
                (NEGATIVE, negative_manifest, 0),
            ):
                with self.subTest(fixture=fixture.name):
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(RUNNER),
                            str(fixture),
                            "--workspace",
                            tmp,
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
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                    self.assertEqual(data["per_detector_counts"][DETECTOR_NAME], expected_hits)

    def test_source_refs_and_no_unicode_dashes_in_owned_sources(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        self.assertIn("reports/detector_lift_fire29_20260605/post_priorities_solidity.md", detector_text)
        self.assertIn("reference/patterns.dsl/rewardloss-in-staking-contracts.yaml", detector_text)
        self.assertIn("reference/patterns.dsl/dh-laura-reward-on-balanceOf-inflatable.yaml", detector_text)
        self.assertIn(
            "reference/patterns.dsl.zellic_k2_mined/rewards-lost-when-total-supply-drops-to-zero.yaml",
            detector_text,
        )
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
