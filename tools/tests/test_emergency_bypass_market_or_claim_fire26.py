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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "emergency_bypass_market_or_claim_fire26.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "emergency_bypass_market_or_claim_fire26.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "emergency_bypass_market_or_claim_fire26.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "emergency-bypass-market-or-claim-fire26"


def _load_detector():
    module_name = "emergency_bypass_market_or_claim_fire26"
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


class EmergencyBypassMarketOrClaimFire26Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_backed_branches(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("a-market-could-be-deprecated-but-still-prevent-liquidators", text)
        self.assertIn("admin-sweep-blocks-pending-user-claims", text)
        self.assertIn("emergency-withdraw-bypass-lock", text)
        self.assertIn("NOT_SUBMIT_READY", text)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(clean_findings, [])
        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {"sweepRewards", "emergencyWithdraw", "setMarketDeprecated"},
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("admin-sweep-pending-claims", messages)
        self.assertIn("emergency-withdraw-lock-bypass", messages)
        self.assertIn("deprecated-market-pause", messages)

    def test_fixture_pair_contains_semantic_controls(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("rewardToken.transfer(receiver, balance);", positive)
        self.assertIn("stakeToken.transfer(msg.sender, amount);", positive)
        self.assertIn("isLiquidateBorrowPaused[market] = true;", positive)

        self.assertIn("uint256 reserved = totalPendingRewards;", negative)
        self.assertIn("rewardToken.transfer(receiver, balance - reserved);", negative)
        self.assertIn("uint256 penalty = amount / 10;", negative)
        self.assertIn("_refreshMarket(market);", negative)
        self.assertIn("isLiquidateBorrowPaused[market] = false;", negative)

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
