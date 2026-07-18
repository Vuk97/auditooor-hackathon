from __future__ import annotations

import importlib.util
import py_compile
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO
    / "detectors"
    / "wave17"
    / "fee_redirect_accrual_or_reserve_conflation_fire17.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "fee_redirect_accrual_or_reserve_conflation_fire17.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "fee_redirect_accrual_or_reserve_conflation_fire17.sol"
)

SOURCE_BACKED_POSITIVES = [
    ("amm-reserves-fee-conflation", REPO / "patterns" / "fixtures" / "amm-reserves-fee-conflation_vuln.sol", 2),
    ("fee-calculation-accrual-missing", REPO / "patterns" / "fixtures" / "fee-calculation-accrual-missing_vuln.sol", 2),
    ("fx-euler-protocol-fee-share-unbounded", REPO / "patterns" / "fixtures" / "fx-euler-protocol-fee-share-unbounded_vuln.sol", 1),
    (
        "fee-redirect-caller-supplied-referral-sink",
        REPO / "detectors" / "fixtures" / "fee_redirect_caller_supplied_referral_sink" / "positive.sol",
        1,
    ),
]

SOURCE_BACKED_CONTROLS = [
    REPO / "patterns" / "fixtures" / "amm-reserves-fee-conflation_clean.sol",
    REPO / "patterns" / "fixtures" / "fee-calculation-accrual-missing_clean.sol",
    REPO / "patterns" / "fixtures" / "fx-euler-protocol-fee-share-unbounded_clean.sol",
    REPO / "detectors" / "fixtures" / "fee_redirect_caller_supplied_referral_sink" / "clean.sol",
]


def _load_detector():
    module_name = "fee_redirect_accrual_or_reserve_conflation_fire17"
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


class FeeRedirectAccrualOrReserveConflationFire17Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_owned_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        vuln_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(vuln_findings), 7)
        self.assertEqual(clean_findings, [])
        self.assertEqual(
            {finding.function for finding in vuln_findings},
            {
                "burn",
                "swap",
                "setFeePerSecond",
                "chargeFee",
                "protocolFeeShare",
                "convertFees",
                "buyPass",
            },
        )
        self.assertTrue(
            all(
                finding.detector
                == "fee-redirect-accrual-or-reserve-conflation-fire17"
                for finding in vuln_findings
            )
        )

    def test_fixture_pair_contains_fee_binding_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("amount0 = (liquidity * reserve0) / totalSupply;", positive)
        self.assertIn("feePerSecond = newRate;", positive)
        self.assertIn("return protocolShare;", positive)
        self.assertIn("token.safeTransfer(protocolReceiver, protocolAmount);", positive)
        self.assertIn("token.safeTransfer(referral, referralFee);", positive)
        self.assertNotIn("realReserve0 = reserve0 - accruedFee;", positive)
        self.assertNotIn("accrueFee();", positive)
        self.assertNotIn("approvedReferral[referral]", positive)

        self.assertIn("realReserve0 = reserve0 - accruedFee;", negative)
        self.assertIn("accrueFee();", negative)
        self.assertIn("protocolReceiver == address(0)", negative)
        self.assertIn("protocolShare > MAX_PROTOCOL_FEE_SHARE", negative)
        self.assertIn("approvedReferral[referral]", negative)
        self.assertIn("referralVault", negative)

    def test_source_backed_examples_fire_and_clean_controls_are_silent(self) -> None:
        detector = _load_detector()

        for slug, fixture, expected_hits in SOURCE_BACKED_POSITIVES:
            with self.subTest(slug=slug):
                findings = detector.scan(_read(fixture), str(fixture))
                self.assertEqual(len(findings), expected_hits)

        for fixture in SOURCE_BACKED_CONTROLS:
            with self.subTest(fixture=fixture.name):
                findings = detector.scan(_read(fixture), str(fixture))
                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
