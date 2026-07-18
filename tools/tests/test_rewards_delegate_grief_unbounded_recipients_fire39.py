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


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO
    / "detectors"
    / "wave17"
    / "rewards_delegate_grief_unbounded_recipients_fire39.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rewards_delegate_grief_unbounded_recipients_fire39.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rewards_delegate_grief_unbounded_recipients_fire39.sol"
)
FIRE38_POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rewards_branch_asymmetry_fire38.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rewards-delegate-grief-unbounded-recipients-fire39"


def _load_detector():
    module_name = "rewards_delegate_grief_unbounded_recipients_fire39"
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


class RewardsDelegateGriefUnboundedRecipientsFire39Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertEqual(detector.VERIFICATION_TIER, "tier-3-synthetic-taxonomy-anchored")
        self.assertEqual(detector.ATTACK_CLASS, "rewards-distribution-skew")

    def test_positive_fixture_fires_on_delegate_recipient_and_balance_skew(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {"delegateRewards", "distributeReferralRewards", "pendingReward"},
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("reward delegate recipient skew", messages)
        self.assertIn("caller-controlled", messages)
        self.assertIn("small cap", messages)
        self.assertIn("dedupe/domain guard", messages)
        self.assertIn("live balanceOf reward weighting", messages)
        self.assertIn("tracked stake denominator", messages)

    def test_negative_fixture_guards_stay_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        negative = _read(NEGATIVE)
        self.assertIn("require(recipients.length <= MAX_REWARD_RECIPIENTS", negative)
        self.assertIn("require(allowedRecipient[recipient]", negative)
        self.assertIn("recipientSeen[delegatee][recipient] = true;", negative)
        self.assertIn("_settleRewards(msg.sender);", negative)
        self.assertIn("checkpointRewards(user);", negative)
        self.assertIn("external onlyOwner", negative)
        self.assertIn("totalStaked == 0", negative)
        self.assertIn("rewardBalanceSnapshot[user]", negative)

    def test_fire38_branch_asymmetry_shape_is_not_this_detector(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(FIRE38_POSITIVE), str(FIRE38_POSITIVE))

        self.assertEqual(findings, [])

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire39_rewards_delegate_grief_") as tmp:
            for fixture, expected_hits in ((POSITIVE, 3), (NEGATIVE, 0)):
                with self.subTest(fixture=fixture.name):
                    manifest = Path(tmp) / f"{fixture.stem}.json"
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
                        cwd=REPO,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                    self.assertEqual(data["per_detector_counts"][DETECTOR_NAME], expected_hits)

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
