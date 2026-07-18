from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "rewards_branch_asymmetry_fire38.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rewards_branch_asymmetry_fire38.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rewards_branch_asymmetry_fire38.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rewards-branch-asymmetry-fire38"


def _load_detector():
    module_name = "rewards_branch_asymmetry_fire38"
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


class RewardsBranchAsymmetryFire38Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "claimOrQueueReward",
                "processCampaignReward",
                "redelegateRewardEffects",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("rewards branch status asymmetry", messages)
        self.assertIn("recipient, or delegation effects", messages)
        self.assertIn("without the status or checkpoint update", messages)
        self.assertIn("withdrawn, claimed, checkpointed, or processed state", messages)

    def test_fixture_pair_contains_semantic_contrasts(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("claimedReward[msg.sender] = true;", positive)
        self.assertIn("claimableRewards[msg.sender] += amount;", positive)
        self.assertIn("processedCampaign[campaignId] = true;", positive)
        self.assertIn("rewardRecipients[campaignId].push(recipient);", positive)
        self.assertIn("withdrawnReward[account] = true;", positive)
        self.assertIn("delegateRewardRecipients[toDelegate].push(account);", positive)

        self.assertIn("claimedReward[msg.sender] = true;", negative)
        self.assertIn("_markCampaignProcessed(campaignId);", negative)
        self.assertIn("processedCampaign[campaignId] = true;", negative)
        self.assertIn("delegateCheckpoint[account] = block.number;", negative)
        self.assertIn("markerOnlyBranch", negative)

    def test_regex_runner_discovers_detector_for_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 3), (NEGATIVE, 0)):
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
