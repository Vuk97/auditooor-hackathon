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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "deprecated_market_liquidation_gate_fire39.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "deprecated_market_liquidation_gate_fire39.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "deprecated_market_liquidation_gate_fire39.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "deprecated-market-liquidation-gate-fire39"


def _load_detector():
    module_name = "deprecated_market_liquidation_gate_fire39"
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


class DeprecatedMarketLiquidationGateFire39Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_docstring_records_tier_context_and_honesty(self) -> None:
        text = _read(DETECTOR_PATH)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", text)
        self.assertIn("attack_class: emergency-bypass", text)
        self.assertIn("context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c", text)
        self.assertIn(
            "context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8",
            text,
        )
        self.assertIn("MCP receipt: .auditooor/memory_context_receipt.json", text)
        self.assertIn("NOT_SUBMIT_READY", text)
        self.assertIn("R40/R76/R80 caveat", text)
        self.assertIn("PROMOTION_ALLOWED = False", text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(negative_findings, [])
        self.assertGreaterEqual(len(positive_findings), 1)
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.function for finding in positive_findings}, {"deprecateMarket"})

        message = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("admin market deprecation path", message)
        self.assertIn("liquidation-only exception", message)
        self.assertIn("liquidateBorrow", message)
        self.assertIn("repayBorrow", message)
        self.assertIn("NOT_SUBMIT_READY", message)

    def test_fixture_pair_locks_semantic_boundary(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("require(m.isLiquidateBorrowPaused", positive)
        self.assertIn("m.status = MarketStatus.Deprecated;", positive)
        self.assertIn("require(m.status != MarketStatus.Deprecated", positive)
        self.assertIn("require(!m.isLiquidateBorrowPaused", positive)
        self.assertNotIn("liquidationExempt[market] = true;", positive)
        self.assertNotIn("m.isLiquidateBorrowPaused = false;", positive)

        self.assertIn("m.isLiquidateBorrowPaused = false;", negative)
        self.assertIn("liquidationExempt[market] = true;", negative)
        self.assertIn("msg.sender == liquidationKeeper", negative)
        self.assertIn("bool debtReductionMode = amount <= m.totalBorrow;", negative)
        self.assertIn("function liquidateDeprecatedMarket", negative)
        self.assertIn("function sweepPendingClaims", negative)

    def test_pending_claim_only_shape_stays_silent(self) -> None:
        detector = _load_detector()
        source = """
        contract PendingClaimOnlyFire39Boundary {
            address public owner;
            bool public claimsPaused;
            mapping(address => uint256) public pendingClaims;
            modifier onlyOwner() {
                require(msg.sender == owner, "owner");
                _;
            }
            function shutdownClaims() external onlyOwner {
                claimsPaused = true;
            }
            function sweepPendingClaims(address receiver) external onlyOwner {
                receiver;
            }
        }
        """
        self.assertEqual(detector.scan(source, "PendingClaimOnlyFire39Boundary.sol"), [])

    def test_liquidation_exception_without_rescue_function_stays_silent(self) -> None:
        detector = _load_detector()
        source = """
        contract LiquidationExceptionFire39Boundary {
            enum MarketStatus { Active, Deprecated }
            struct Market {
                MarketStatus status;
                bool isLiquidateBorrowPaused;
                bool isBorrowPaused;
                uint256 totalBorrow;
            }
            address public owner;
            address public liquidationKeeper;
            mapping(address => Market) public markets;
            modifier onlyOwner() {
                require(msg.sender == owner, "owner");
                _;
            }
            function deprecateMarket(address market) external onlyOwner {
                Market storage m = markets[market];
                require(m.isLiquidateBorrowPaused, "liquidation was paused");
                m.status = MarketStatus.Deprecated;
            }
            function liquidateBorrow(address borrower, address market, uint256 amount) external {
                Market storage m = markets[market];
                require(m.status != MarketStatus.Deprecated || msg.sender == liquidationKeeper, "deprecated");
                if (m.isLiquidateBorrowPaused && msg.sender != liquidationKeeper) revert();
                markets[market].totalBorrow -= amount;
                borrower;
            }
        }
        """
        self.assertEqual(detector.scan(source, "LiquidationExceptionFire39Boundary.sol"), [])

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 1), (NEGATIVE, 0)):
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
