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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "emergency_pending_claims_fire34.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "emergency_pending_claims_fire34.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "emergency_pending_claims_fire34.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "emergency-pending-claims-fire34"


def _load_detector():
    module_name = "emergency_pending_claims_fire34"
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


class EmergencyPendingClaimsFire34Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_backed_records_and_honesty_marker(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("post_priorities_all.md", text)
        self.assertIn("emergency-bypass.yaml", text)
        self.assertIn("emergency-withdraw-bypass-lock", text)
        self.assertIn("emergency_asset_scope_bypass_fire31.py", text)
        self.assertIn("emergency_pause_scope_fire32.py", text)
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
                "setMarketDeprecated",
                "pauseWithdrawals",
                "emergencySweep",
                "updateBranchStatus",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("emergency-disable-pending-claims-unresolved", messages)
        self.assertIn("admin-sweep-pending-claims-unresolved", messages)
        self.assertIn("branch-status-update-without-recipient-reassignment", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_false_positive_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function setMarketDeprecated(address market) external onlyOwner", positive)
        self.assertIn("claimsPaused[market] = true;", positive)
        self.assertIn("withdrawalsDisabled[vault] = true;", positive)
        self.assertIn("marketEscrow[market] -= amount;", positive)
        self.assertIn("branchStatus[branch] = BranchStatus.Closed;", positive)
        self.assertNotIn("processPendingClaims(market);", positive)
        self.assertNotIn("reassignBranchRecipients(branch", positive)

        self.assertIn("processPendingClaims(market);", negative)
        self.assertIn("processQueuedWithdrawals(vault);", negative)
        self.assertIn("clearPendingClaims(market);", negative)
        self.assertIn("reassignBranchRecipients(branch, replacement);", negative)
        self.assertIn("function rescueDust(address token, uint256 amount) external onlyOwner", negative)
        self.assertIn("function pauseDeposits(address market) external onlyOwner", negative)

    def test_generic_admin_power_without_claim_surface_is_not_flagged(self) -> None:
        detector = _load_detector()
        source = """
        contract GenericEmergencyAdminFire34 {
            address public owner;
            address public treasury;
            mapping(address => bool) public tokenPaused;
            modifier onlyOwner() {
                require(msg.sender == owner, "owner");
                _;
            }
            function setTokenPaused(address token) external onlyOwner {
                tokenPaused[token] = true;
            }
            function rescueDust(address token, uint256 amount) external onlyOwner {
                Fire34SafeToken(token).safeTransfer(treasury, amount);
            }
        }
        """
        self.assertEqual(detector.scan(source, "GenericEmergencyAdminFire34.sol"), [])

    def test_user_emergency_withdraw_is_not_admin_disable_path(self) -> None:
        detector = _load_detector()
        source = """
        contract UserEmergencyWithdrawFire34 {
            mapping(address => uint256) public pendingClaims;
            mapping(address => uint256) public queuedWithdrawals;
            function claim(address token) external {
                uint256 amount = pendingClaims[msg.sender];
                pendingClaims[msg.sender] = 0;
                Fire34SafeToken(token).safeTransfer(msg.sender, amount);
            }
            function emergencyWithdraw(address token) external {
                uint256 amount = queuedWithdrawals[msg.sender];
                queuedWithdrawals[msg.sender] = 0;
                Fire34SafeToken(token).safeTransfer(msg.sender, amount);
            }
        }
        """
        self.assertEqual(detector.scan(source, "UserEmergencyWithdrawFire34.sol"), [])

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
