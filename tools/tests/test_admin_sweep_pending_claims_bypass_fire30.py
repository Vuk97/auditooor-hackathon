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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_sweep_pending_claims_bypass_fire30.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_sweep_pending_claims_bypass_fire30.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_sweep_pending_claims_bypass_fire30.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-sweep-pending-claims-bypass-fire30"


def _load_detector():
    module_name = "admin_sweep_pending_claims_bypass_fire30"
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


class AdminSweepPendingClaimsBypassFire30Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_cites_source_backed_records_and_honesty_marker(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("post_priorities_solidity.md", text)
        self.assertIn("reentrancy-during-pause", text)
        self.assertIn("emergency-admin-can-unpause-reserves-breaking-pause-asymmetry", text)
        self.assertIn("collateral-can-be-enabled-despite-pause-freeze-or-invalid-pricing", text)
        self.assertIn("admin-sweep-blocks-pending-user-claims", text)
        self.assertIn("NOT_SUBMIT_READY", text)
        self.assertIn("PROMOTION_ALLOWED = False", text)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(clean_findings, [])
        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "adminSweepRewards",
                "rescueDeprecatedMarket",
                "emergencyWithdrawFromBranch",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("pending-claims-admin-sweep", messages)
        self.assertIn("deprecated-market-or-branch-sweep", messages)
        self.assertIn("branch-state-emergency-withdraw", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_false_positive_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("uint256 balance = rewardToken.balanceOf(address(this));", positive)
        self.assertIn("rewardToken.safeTransfer(receiver, balance);", positive)
        self.assertIn("marketDeprecated[market] = false;", positive)
        self.assertIn("collateral.safeTransfer(receiver, balance);", positive)
        self.assertIn("collateral.safeTransfer(msg.sender, amount);", positive)

        self.assertIn("uint256 reserved = totalPendingRewards + totalPendingWithdrawals;", negative)
        self.assertIn("uint256 sweepable = balance - reserved;", negative)
        self.assertIn("require(!marketDeprecated[market]", negative)
        self.assertIn("_refreshMarket(market);", negative)
        self.assertIn("_settleMarketClaims(market);", negative)
        self.assertIn("require(branchStatus[branchId] == BranchStatus.Resolved", negative)
        self.assertIn("require(branchPendingClaims[branchId] == 0", negative)
        self.assertIn("require(address(strayToken) != address(rewardToken)", negative)

    def test_ordinary_dust_rescue_without_claim_or_branch_context_is_not_flagged(self) -> None:
        detector = _load_detector()
        source = """
        interface TokenFire30Dust {
            function balanceOf(address account) external view returns (uint256);
            function safeTransfer(address to, uint256 amount) external returns (bool);
        }
        contract DustOnlyFire30 {
            TokenFire30Dust public strayToken;
            address public owner;
            modifier onlyOwner() {
                require(msg.sender == owner, "owner");
                _;
            }
            function rescueDust(address receiver) external onlyOwner {
                uint256 balance = strayToken.balanceOf(address(this));
                strayToken.safeTransfer(receiver, balance);
            }
        }
        """
        self.assertEqual(detector.scan(source, "DustOnlyFire30.sol"), [])

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
