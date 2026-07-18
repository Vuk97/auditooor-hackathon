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
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "rewards_supply_checkpoint_fire31.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rewards-supply-checkpoint-fire31"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rewards_supply_checkpoint_fire31.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rewards_supply_checkpoint_fire31.sol"
)


def _load_detector():
    module_name = "rewards_supply_checkpoint_fire31"
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


class RewardsSupplyCheckpointFire31Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")

    def test_positive_fixture_fires_on_supply_accumulator_debt_and_checkpoint_writes(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 4)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "depositBeforeSettlement",
                "overwriteAccumulatorBeforeUserCheckpoint",
                "resetDebtBeforeCredit",
                "overwriteRewardCheckpointBeforeSettle",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("supply denominator", messages)
        self.assertIn("reward accumulator", messages)
        self.assertIn("user reward debt", messages)
        self.assertIn("reward checkpoint", messages)
        self.assertIn("before old rewards are settled", messages)

    def test_negative_fixture_settles_first_and_bait_is_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean = _read(NEGATIVE)
        self.assertRegex(clean, r"_settleRewards\(msg.sender\);[\s\S]*totalStaked \+= amount;")
        self.assertIn("rewardPerTokenStored += (rewardAmount * ACC_PRECISION) / totalStaked;", clean)
        self.assertIn("Fire31RewardMath.mulDiv(rewardAmount, ACC_PRECISION, totalStaked)", clean)
        self.assertRegex(clean, r"pendingRewards\[user\] \+=[\s\S]*userRewardDebt\[user\] =")
        self.assertRegex(clean, r"_checkpointRewards\(user\);[\s\S]*rewardCheckpoint\[user\] =")
        self.assertIn('string memory bait = "totalStaked += amount; userRewardDebt[user] = 0;";', clean)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire31_rewards_supply_checkpoint_") as tmp:
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
        self.assertIn("reports/detector_lift_fire30_20260605/post_priorities_solidity.md", detector_text)
        self.assertIn("detectors/wave17/reward_per_token_precision_floor_fire30.py", detector_text)
        self.assertIn("reference/patterns.dsl/rewardloss-in-staking-contracts.yaml", detector_text)
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
