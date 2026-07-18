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
DETECTOR_PATH = (
    REPO
    / "detectors"
    / "wave17"
    / "reward_skew_branch_or_failed_dispatch_fire19.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "reward_skew_branch_or_failed_dispatch_fire19.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "reward_skew_branch_or_failed_dispatch_fire19.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "reward-skew-branch-or-failed-dispatch-fire19"


def _load_detector():
    module_name = "reward_skew_branch_or_failed_dispatch_fire19"
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


class RewardSkewBranchOrFailedDispatchFire19Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_owned_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 4)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "claimWithAsymmetricFlag",
                "submitInboundMessage",
                "bulkBurnAndReward",
                "redeemBranchSkew",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("idempotency state in only one reward-processing branch", messages)
        self.assertIn("pays relayer reward or refund after a catch path", messages)
        self.assertIn("pre-burn totalSupply snapshot", messages)
        self.assertIn("supply denominator in only one reward branch", messages)

    def test_fixture_pair_contains_semantic_contrasts(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("rewardClaimed[msg.sender] = true;", positive)
        self.assertIn("success = false;", positive)
        self.assertIn("relayerRewards[msg.sender] += relayerReward;", positive)
        self.assertIn("uint256 supplyBefore = totalSupply;", positive)
        self.assertIn("(rewardPool * amounts[i]) / supplyBefore", positive)
        self.assertIn("totalSupply -= amount;", positive)

        self.assertIn("rewardClaimed[msg.sender] = true;", negative)
        self.assertIn("if (success)", negative)
        self.assertIn("uint256 supplyAfterBurn = totalSupply - totalBurn;", negative)
        self.assertIn("_checkpointTotalSupply(supplyAfterBurn);", negative)
        self.assertIn("uint256 supplyAfter = totalSupply - amount;", negative)
        self.assertIn("_checkpointTotalSupply(supplyAfter);", negative)

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 4), (NEGATIVE, 0)):
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
