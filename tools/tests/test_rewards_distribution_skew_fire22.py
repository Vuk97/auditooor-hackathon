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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "rewards_distribution_skew_fire22.py"
FIRE21_PATH = REPO / "detectors" / "wave17" / "rewards_distribution_skew_fire21.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rewards_distribution_skew_fire22.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rewards_distribution_skew_fire22.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rewards-distribution-skew-fire22"


def _load_module(module_name: str, path: Path):
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _load_detector():
    return _load_module("rewards_distribution_skew_fire22", DETECTOR_PATH)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class RewardsDistributionSkewFire22Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_owned_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "claimPendingWithIgnoredCall",
                "harvestWithSwallowedCatch",
                "collectWithRawTransferReturnIgnored",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("low-level call success flag is not enforced", messages)
        self.assertIn("failed try/catch payout is swallowed", messages)
        self.assertIn("ERC20 transfer return value is ignored", messages)

    def test_fixture_pair_contains_semantic_contrasts(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("pendingRewards[msg.sender] = 0;", positive)
        self.assertIn("(bool ok, ) = address(rewardToken).call", positive)
        self.assertIn("ok;", positive)
        self.assertIn("catch {", positive)
        self.assertIn("emit RewardPayoutFailed(msg.sender, amount);", positive)
        self.assertIn("rewardToken.transfer(msg.sender, amount);", positive)

        self.assertIn('require(ok, "reward transfer failed");', negative)
        self.assertIn("catch {", negative)
        self.assertIn('revert("reward transfer failed");', negative)
        self.assertIn("require(rewardToken.transfer(msg.sender, amount)", negative)
        self.assertIn("_safeTransferReward(msg.sender, amount);", negative)

    def test_fire21_detector_is_silent_on_fire22_subshape(self) -> None:
        fire21 = _load_module("rewards_distribution_skew_fire21_for_fire22_test", FIRE21_PATH)

        self.assertEqual(fire21.scan(_read(POSITIVE), str(POSITIVE)), [])

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
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
