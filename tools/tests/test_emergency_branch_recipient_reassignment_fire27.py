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
    REPO / "detectors" / "wave17" / "emergency_branch_recipient_reassignment_fire27.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "emergency_branch_recipient_reassignment_fire27.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "emergency_branch_recipient_reassignment_fire27.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "emergency-branch-recipient-reassignment-fire27"


def _load_detector():
    module_name = "emergency_branch_recipient_reassignment_fire27"
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


class EmergencyBranchRecipientReassignmentFire27Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_backed_records_and_honesty_marker(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("branch-status-update-without-recipient-reassignment", text)
        self.assertIn("bridge-strict-channel-nonce-blocks-governance", text)
        self.assertIn("emergency-withdraw-bypass-lock", text)
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
                "emergencyCloseBranch",
                "pauseChannel",
                "deprecateMarket",
                "rejectClaim",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("status-update-without-recipient-preservation", messages)
        self.assertIn("pending recipient or claim state exists", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_recipient_preservation_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("branchStatus[branchId] = RouteStatus.Paused;", positive)
        self.assertIn("channels[channelId].status = RouteStatus.Rejected;", positive)
        self.assertIn("marketStatus[market] = RouteStatus.Deprecated;", positive)
        self.assertIn("claimStatus[claimId] = RouteStatus.Cancelled;", positive)

        self.assertIn("_preserveBranchRecipient(branchId);", negative)
        self.assertIn("channels[channelId].pendingRecipient = fallbackRecipient;", negative)
        self.assertIn(
            "claimableByRecipient[marketRecipient[market]] += pendingMarketClaims[market];",
            negative,
        )
        self.assertIn("_escrowClaimForRecipient(claimId);", negative)

    def test_status_only_contract_without_claim_ledger_is_not_flagged(self) -> None:
        detector = _load_detector()
        source = """
        contract RouteStatusOnly {
            enum RouteStatus { Open, Paused }
            address public guardian;
            mapping(bytes32 => RouteStatus) public branchStatus;
            modifier onlyGuardian() {
                require(msg.sender == guardian, "guardian");
                _;
            }
            function emergencyCloseBranch(bytes32 branchId) external onlyGuardian {
                branchStatus[branchId] = RouteStatus.Paused;
            }
        }
        """
        self.assertEqual(detector.scan(source, "RouteStatusOnly.sol"), [])

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
