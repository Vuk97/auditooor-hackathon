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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "emergency_admin_sweep_pending_claims_fire27.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "emergency_admin_sweep_pending_claims_fire27.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "emergency_admin_sweep_pending_claims_fire27.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "emergency-admin-sweep-pending-claims-fire27"


def _load_detector():
    module_name = "emergency_admin_sweep_pending_claims_fire27"
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


class EmergencyAdminSweepPendingClaimsFire27Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_backed_records_and_honesty_marker(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("admin-sweep-blocks-pending-user-claims", text)
        self.assertIn("a-market-could-be-deprecated-but-still-prevent-liquidators", text)
        self.assertIn("emergency-withdraw-bypass-lock", text)
        self.assertIn("NOT_SUBMIT_READY", text)
        self.assertIn("PROMOTION_ALLOWED = False", text)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(clean_findings, [])
        self.assertEqual(len(findings), 2)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {"adminSweepRewards", "emergencyDrainReserve"},
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("full-contract-balance-sweep", messages)
        self.assertIn("reserve-balance-sweep", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_bounded_semantics(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("uint256 balance = rewardToken.balanceOf(address(this));", positive)
        self.assertIn("rewardToken.safeTransfer(receiver, balance);", positive)
        self.assertIn("uint256 cash = reserveBalance;", positive)
        self.assertIn("payable(receiver).call{value: cash}", positive)

        self.assertIn("uint256 reserved = totalPendingRewards;", negative)
        self.assertIn("uint256 sweepable = balance - reserved;", negative)
        self.assertIn("_escrowPendingWithdrawals(protectedBalance);", negative)
        self.assertIn("require(address(token) != address(rewardToken)", negative)
        self.assertIn("function rescueDust(address receiver) external onlyOwner", negative)
        self.assertIn("strayToken.safeTransfer(receiver, balance);", negative)

    def test_ordinary_owner_dust_rescue_without_claim_ledger_is_not_flagged(self) -> None:
        detector = _load_detector()
        source = """
        interface TokenDust {
            function balanceOf(address account) external view returns (uint256);
            function safeTransfer(address to, uint256 amount) external returns (bool);
        }
        contract DustRescueOnly {
            TokenDust public token;
            address public owner;
            modifier onlyOwner() {
                require(msg.sender == owner, "owner");
                _;
            }
            function rescueDust(address receiver) external onlyOwner {
                uint256 balance = token.balanceOf(address(this));
                token.safeTransfer(receiver, balance);
            }
        }
        """
        self.assertEqual(detector.scan(source, "DustRescueOnly.sol"), [])

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
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
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)


if __name__ == "__main__":
    unittest.main()
