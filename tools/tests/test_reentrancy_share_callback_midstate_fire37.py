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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "reentrancy_share_callback_midstate_fire37.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "reentrancy_share_callback_midstate_fire37.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "reentrancy_share_callback_midstate_fire37.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "reentrancy-share-callback-midstate-fire37"


def _load_detector():
    module_name = "reentrancy_share_callback_midstate_fire37"
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


class ReentrancyShareCallbackMidstateFire37Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertFalse(detector.PROMOTION_ALLOWED)

    def test_positive_fixture_fires_on_midstate_accounting_after_callback(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 5)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "depositSharesAfterReceiver",
                "redeemCollateralAfterTokenTransfer",
                "borrowDebtAfterHook",
                "settlePacketAfterReceiver",
                "claimRewardAfterHook",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("share accounting `sharesBefore`", messages)
        self.assertIn("collateral accounting `collateralBefore`", messages)
        self.assertIn("debt accounting `debtBefore`", messages)
        self.assertIn("packet accounting `packetSharesBefore`", messages)
        self.assertIn("reward accounting `rewardBefore`", messages)
        self.assertIn("external receiver hook or token transfer", messages)
        self.assertIn("after external control transfer", messages)
        self.assertIn("no shared reentrancy guard or post-callback refresh", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_negative_fixture_cei_guard_refresh_and_comment_bait_are_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        negative = _read(NEGATIVE)
        self.assertIn("shares[msg.sender] = sharesBefore + amount;", negative)
        self.assertIn("external nonReentrant", negative)
        self.assertIn("uint256 freshDebtAfter = debtShares[msg.sender];", negative)
        self.assertIn("uint256 freshPacketShares = packets[packetId].shares;", negative)
        self.assertIn("rewardBefore = rewardDebt[msg.sender];", negative)
        self.assertIn("// receiver.onSharesReceived(msg.sender, sharesBefore);", negative)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
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

    def test_source_refs_and_no_unicode_dashes_in_owned_sources(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        self.assertIn("reports/detector_lift_fire36_20260605/post_priorities_solidity.md", detector_text)
        self.assertIn(
            "reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml",
            detector_text,
        )
        self.assertIn("detectors/wave17/reentrancy_callback_balance_snapshot_fire36.py", detector_text)
        self.assertIn("detectors/wave17/readonly_reentrancy_accounting_fire35.py", detector_text)
        self.assertIn("R37", detector_text)
        self.assertIn("R40", detector_text)
        self.assertIn("R76", detector_text)
        self.assertIn("R80", detector_text)

        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
