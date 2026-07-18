from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "rewards_live_supply_drift_fire34.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rewards-live-supply-drift-fire34"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rewards_live_supply_drift_fire34.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rewards_live_supply_drift_fire34.sol"
)


def _load_detector():
    module_name = "rewards_live_supply_drift_fire34"
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


class RewardsLiveSupplyDriftFire34Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.VERIFICATION_TIER, "tier-3-synthetic-taxonomy-anchored")

    def test_positive_fixture_fires_on_live_supply_balance_and_votes(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {"distributeRewards", "notifyRewardAmount", "allocateRewards"},
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("live denominator `totalStaked`", messages)
        self.assertIn("live denominator `stakingToken.balanceOf(address(this))`", messages)
        self.assertIn("live denominator `votes.getVotes(address(this))`", messages)
        self.assertIn("checkpointed eligible denominator", messages)

    def test_negative_fixture_uses_snapshot_or_cooldown_boundaries(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean = _read(NEGATIVE)
        self.assertIn("_checkpointSupply();", clean)
        self.assertIn("uint256 eligibleSupply = distributionSupply[currentEpoch];", clean)
        self.assertIn("votes.getPastVotes(address(this), snapshotBlock)", clean)
        self.assertIn("require(rewardToken != address(stakingToken)", clean)
        self.assertIn('string memory bait = "accRewardPerShare += rewardAmount / totalStaked;";', clean)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire34_rewards_live_supply_") as tmp:
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"

            for fixture, expected_hits in ((POSITIVE, 3), (NEGATIVE, 0)):
                with self.subTest(fixture=fixture.name):
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(RUNNER),
                            str(fixture),
                            "--workspace",
                            tmp,
                            "--detector",
                            DETECTOR_NAME,
                            "--no-manifest",
                        ],
                        cwd=ROOT,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                    self.assertIsNotNone(match, proc.stdout)
                    self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)

    def test_source_refs_and_no_unicode_dashes_in_owned_sources(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        self.assertIn("reports/detector_lift_fire33_20260605/post_priorities_all.md", detector_text)
        self.assertIn(
            "reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml",
            detector_text,
        )
        self.assertIn(
            "detectors/rust_wave1/reward_index_or_supply_checkpoint_drift_fire20.py",
            detector_text,
        )

        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
