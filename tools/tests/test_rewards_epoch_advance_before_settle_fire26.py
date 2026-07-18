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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "rewards_epoch_advance_before_settle_fire26.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rewards_epoch_advance_before_settle_fire26.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rewards_epoch_advance_before_settle_fire26.sol"
)
LEGACY_POSITIVE = REPO / "patterns" / "fixtures" / "can-epoch-advance-before-settle_vuln.sol"
LEGACY_NEGATIVE = REPO / "patterns" / "fixtures" / "can-epoch-advance-before-settle_clean.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rewards-epoch-advance-before-settle-fire26"


def _load_detector():
    module_name = "rewards_epoch_advance_before_settle_fire26"
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


class RewardsEpochAdvanceBeforeSettleFire26Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("candidate evidence only", detector_text)
        self.assertIn("can-epoch-advance-before-settle", detector_text)

    def test_owned_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 2)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.function for finding in findings}, {"advanceEpoch", "rotateRound"})

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("reward epoch advance before settle", messages)
        self.assertIn("pending rewards, user claim indexes, and pool checkpoints", messages)
        self.assertIn("Candidate evidence only", messages)

    def test_legacy_can_epoch_miss_is_now_recalled(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(LEGACY_POSITIVE), str(LEGACY_POSITIVE))
        clean_findings = detector.scan(_read(LEGACY_NEGATIVE), str(LEGACY_NEGATIVE))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].function, "notifyReward")
        self.assertEqual(findings[0].detector, DETECTOR_NAME)
        self.assertEqual(clean_findings, [])

    def test_fixture_pair_contains_semantic_contrasts(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("currentEpoch = currentEpoch + 1;", positive)
        self.assertIn("pendingRewards[user] = amount;", positive)
        self.assertIn("lastClaimedEpoch[user] = currentEpoch;", positive)
        self.assertIn("activeRound = (activeRound + 1) % ROUND_RING;", positive)
        self.assertIn("poolRewardIndex[activeRound][pool] = globalRewardIndex;", positive)
        self.assertNotIn("_settlePendingReward(user, prevEpoch);", positive)
        self.assertNotIn("_settlePoolRewards(pool);", positive)

        self.assertIn("_settlePendingReward(user, prevEpoch);", negative)
        self.assertIn("_checkpointUser(user);", negative)
        self.assertIn("_settlePoolRewards(pool);", negative)
        self.assertIn("_checkpointPool(pool);", negative)
        self.assertIn("currentEpoch = prevEpoch + 1;", negative)
        self.assertIn("activeRound = (activeRound + 1) % ROUND_RING;", negative)

    def test_regex_runner_discovers_detector_for_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 2), (NEGATIVE, 0)):
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
                self.assertNotIn("No custom detectors found", proc.stdout)
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)

    def test_owned_files_have_no_unicode_dashes(self) -> None:
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = _read(path)
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)


if __name__ == "__main__":
    unittest.main()
