from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO / "detectors" / "wave17" / "fee_redirect_reserve_or_accrual_fire16.py"
)
FIXTURE_DIR = (
    REPO
    / "detectors"
    / "fixtures"
    / "solidity"
    / "fee_redirect_reserve_or_accrual_fire16"
)

SOURCE_BACKED_POSITIVES = [
    ("amm-reserves-fee-conflation", REPO / "patterns" / "fixtures" / "amm-reserves-fee-conflation_vuln.sol", 2),
    ("fee-calculation-accrual-missing", REPO / "patterns" / "fixtures" / "fee-calculation-accrual-missing_vuln.sol", 2),
    ("fx-euler-protocol-fee-share-unbounded", REPO / "patterns" / "fixtures" / "fx-euler-protocol-fee-share-unbounded_vuln.sol", 1),
]

SOURCE_BACKED_CONTROLS = [
    REPO / "patterns" / "fixtures" / "amm-reserves-fee-conflation_clean.sol",
    REPO / "patterns" / "fixtures" / "fee-calculation-accrual-missing_clean.sol",
    REPO / "patterns" / "fixtures" / "fx-euler-protocol-fee-share-unbounded_clean.sol",
]


def _load_detector():
    module_name = "fee_redirect_reserve_or_accrual_fire16"
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


class FeeRedirectReserveOrAccrualFire16Test(unittest.TestCase):
    def test_owned_positive_fires_and_clean_fixture_is_silent(self) -> None:
        detector = _load_detector()

        vuln_findings = detector.scan(_read(FIXTURE_DIR / "vulnerable.sol"), "vulnerable.sol")
        clean_findings = detector.scan(_read(FIXTURE_DIR / "clean.sol"), "clean.sol")

        self.assertEqual(len(vuln_findings), 6)
        self.assertEqual(clean_findings, [])

        hit_functions = {finding.function for finding in vuln_findings}
        self.assertEqual(
            hit_functions,
            {
                "burn",
                "swap",
                "setFeePerSecond",
                "chargeFee",
                "protocolFeeShare",
                "convertFees",
            },
        )
        self.assertTrue(
            all(
                finding.detector == "fee-redirect-reserve-or-accrual-fire16"
                for finding in vuln_findings
            )
        )

    def test_fixture_pair_contains_guard_contrast(self) -> None:
        vuln = _read(FIXTURE_DIR / "vulnerable.sol")
        clean = _read(FIXTURE_DIR / "clean.sol")

        self.assertIn("amount0 = (liquidity * reserve0) / totalSupply;", vuln)
        self.assertIn("feePerSecond = newRate;", vuln)
        self.assertIn("return protocolShare;", vuln)
        self.assertIn("transfer(protocolReceiver, protocolAmount)", vuln)
        self.assertNotIn("realReserve0 = reserve0 - accruedFee;", vuln)
        self.assertNotIn("accrueFee();", vuln)
        self.assertNotIn("protocolReceiver == address(0)", vuln)

        self.assertIn("realReserve0 = reserve0 - accruedFee;", clean)
        self.assertIn("accrueFee();", clean)
        self.assertIn("protocolReceiver == address(0)", clean)
        self.assertIn("protocolShare > MAX_PROTOCOL_FEE_SHARE", clean)

    def test_requested_recall_fixtures_fire_and_clean_controls_are_silent(self) -> None:
        detector = _load_detector()

        for slug, fixture, expected_hits in SOURCE_BACKED_POSITIVES:
            with self.subTest(slug=slug):
                findings = detector.scan(_read(fixture), fixture.name)
                self.assertEqual(len(findings), expected_hits)

        for fixture in SOURCE_BACKED_CONTROLS:
            with self.subTest(fixture=fixture.name):
                findings = detector.scan(_read(fixture), fixture.name)
                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
