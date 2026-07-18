from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "rewards_distribution_skew_fire18.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "rewards_distribution_skew_fire18.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "rewards_distribution_skew_fire18.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rewards-distribution-skew-fire18"

FORCED_POSITIVE = (
    REPO
    / "detectors"
    / "fixtures"
    / "a_malicious_staker_can_force_validator_withdrawals_by_instantly"
    / "ssi-fix-034_positive.sol"
)
FORCED_CLEAN = (
    REPO
    / "detectors"
    / "fixtures"
    / "a_malicious_staker_can_force_validator_withdrawals_by_instantly"
    / "ssi-fix-034_clean.sol"
)
BLOCK_TIME_POSITIVE = REPO / "patterns" / "fixtures" / "block-number-time-assumption_vuln.sol"
BLOCK_TIME_CLEAN = REPO / "patterns" / "fixtures" / "block-number-time-assumption_clean.sol"
AUCTION_STALL_POSITIVE = REPO / "patterns" / "fixtures" / "auction-failure-stalls-period_vuln.sol"
AUCTION_STALL_CLEAN = REPO / "patterns" / "fixtures" / "auction-failure-stalls-period_clean.sol"
AUCTION_ADVANCE_POSITIVE = REPO / "patterns" / "fixtures" / "auction-failure-stalls-period-advance_vuln.sol"
AUCTION_ADVANCE_CLEAN = REPO / "patterns" / "fixtures" / "auction-failure-stalls-period-advance_clean.sol"


def _load_detector():
    module_name = "rewards_distribution_skew_fire18"
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


class RewardsDistributionSkewFire18Test(unittest.TestCase):
    def test_owned_positive_fires_and_clean_fixture_is_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 5)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "requestUnstake",
                "secondsElapsed",
                "rewardsAccrued",
                "claimRewards",
                "closeAuction",
            },
        )
        self.assertEqual(clean_findings, [])

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("without offsetting currently withdrawable balance", messages)
        self.assertIn("block.number into reward or emission time", messages)
        self.assertIn("before claim or distribution state is advanced", messages)
        self.assertIn("terminal failure branch exits before period", messages)

    def test_fixture_pair_contains_semantic_contrasts(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("requestedWithdrawalBalance += amount;", positive)
        self.assertIn("requestExits(exitsRequired);", positive)
        self.assertIn("(block.number - startBlock) * 12", positive)
        self.assertIn("rewardToken.transfer(msg.sender, reward);", positive)
        self.assertIn("lastClaimedEpoch[msg.sender] = currentEpoch;", positive)
        self.assertIn("return;", positive)

        self.assertIn("availableWithdrawalBalance", negative)
        self.assertIn("block.timestamp - startTimestamp", negative)
        self.assertIn("pendingReward[msg.sender] = 0;", negative)
        self.assertIn("lastClaimedEpoch[msg.sender] = currentEpoch;", negative)
        self.assertIn("currentPeriod++;", negative)
        self.assertIn("noteRewardBudget", negative)

    def test_source_backed_misses_fire_and_clean_controls_are_silent(self) -> None:
        detector = _load_detector()

        source_backed = [
            (FORCED_POSITIVE, 1),
            (BLOCK_TIME_POSITIVE, 2),
            (AUCTION_STALL_POSITIVE, 1),
            (AUCTION_ADVANCE_POSITIVE, 1),
        ]
        clean_controls = [FORCED_CLEAN, BLOCK_TIME_CLEAN, AUCTION_STALL_CLEAN, AUCTION_ADVANCE_CLEAN]

        for fixture, expected_hits in source_backed:
            with self.subTest(fixture=fixture.name):
                findings = detector.scan(_read(fixture), str(fixture))
                self.assertEqual(len(findings), expected_hits)

        for fixture in clean_controls:
            with self.subTest(fixture=fixture.name):
                findings = detector.scan(_read(fixture), str(fixture))
                self.assertEqual(findings, [])

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 5), (NEGATIVE, 0)):
            with self.subTest(fixture=fixture.name):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(RUNNER),
                        str(fixture),
                        "--detector",
                        DETECTOR_NAME,
                        "--no-manifest",
                    ],
                    cwd=REPO,
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


if __name__ == "__main__":
    unittest.main()
