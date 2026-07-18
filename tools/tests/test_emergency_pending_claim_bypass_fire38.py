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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "emergency_pending_claim_bypass_fire38.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "emergency_pending_claim_bypass_fire38.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "emergency_pending_claim_bypass_fire38.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "emergency-pending-claim-bypass-fire38"


def _load_detector():
    module_name = "emergency_pending_claim_bypass_fire38"
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


class EmergencyPendingClaimBypassFire38Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_refs_and_honesty_marker(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("post_priorities_solidity.md", text)
        self.assertIn("admin-bypass-umbrella.yaml", text)
        self.assertIn("a-market-could-be-deprecated-but-still-prevent-liquidators", text)
        self.assertIn("admin-sweep-blocks-pending-user-claims", text)
        self.assertIn("freeze-control-unguarded-state-flip", text)
        self.assertIn("permanent-freeze.yaml was requested", text)
        self.assertIn("NOT_SUBMIT_READY", text)
        self.assertIn("PROMOTION_ALLOWED = False", text)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(clean_findings, [])
        self.assertEqual(len(findings), 4)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "shutdownProtocol",
                "deprecateMarket",
                "emergencySweepClaims",
                "closeRecipientRoute",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("status-update-blocks-pending-user-paths", messages)
        self.assertIn("deprecated-market-locks-liquidation-rescue", messages)
        self.assertIn("emergency-sweep-drains-pending-claim-reserve", messages)
        self.assertIn("recipient-route-closed-without-reassignment", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_false_positive_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("globalStatus = MarketStatus.Closed;", positive)
        self.assertIn("withdrawalsDisabled[address(0)] = true;", positive)
        self.assertIn("isLiquidateBorrowPaused[market] = true;", positive)
        self.assertIn("uint256 balance = payoutToken.balanceOf(address(this));", positive)
        self.assertIn("payoutToken.safeTransfer(receiver, balance);", positive)
        self.assertIn("routeStatus[route] = MarketStatus.Closed;", positive)
        self.assertNotIn("settlePendingClaims();", positive)
        self.assertNotIn("reassignPendingRecipients(route, replacement);", positive)

        self.assertIn("settlePendingClaims();", negative)
        self.assertIn("processQueuedWithdrawals(address(0));", negative)
        self.assertIn("isLiquidateBorrowPaused[market] = false;", negative)
        self.assertIn("uint256 reserved = totalPendingClaims + totalQueuedWithdrawals;", negative)
        self.assertIn("payoutToken.safeTransfer(receiver, balance - reserved);", negative)
        self.assertIn("reassignPendingRecipients(route, replacement);", negative)
        self.assertIn("function claimAfterShutdown(address account) external", negative)
        self.assertIn("function rescueDust(address receiver) external onlyOwner", negative)

    def test_contract_level_rescue_path_suppresses_shutdown_status_lock(self) -> None:
        detector = _load_detector()
        source = """
        contract ContractLevelRescueFire38 {
            enum Status { Active, Closed }
            address public owner;
            Status public globalStatus;
            mapping(address => uint256) public pendingClaims;
            modifier onlyOwner() {
                require(msg.sender == owner, "owner");
                _;
            }
            function claim() external {
                require(globalStatus == Status.Active, "closed");
                pendingClaims[msg.sender] = 0;
            }
            function shutdown() external onlyOwner {
                globalStatus = Status.Closed;
            }
            function claimAfterShutdown(address account) external {
                pendingClaims[account] = 0;
            }
        }
        """
        self.assertEqual(detector.scan(source, "ContractLevelRescueFire38.sol"), [])

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
