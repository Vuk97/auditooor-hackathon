from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "state_change_between_check_and_use_amount_boundary.py"
FIXTURES = ROOT / "detectors" / "fixtures" / "solidity" / "state_change_between_check_and_use_amount_boundary"
PATTERNS = ROOT / "patterns" / "fixtures"


def _load_detector():
    module_name = "state_change_between_check_and_use_amount_boundary_detector"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec and spec.loader, f"failed to load {DETECTOR}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class StateChangeBetweenCheckAndUseAmountBoundaryTest(unittest.TestCase):
    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(FIXTURES / "vulnerable.sol"), "vulnerable.sol")
        clean = detector.scan(_read(FIXTURES / "clean.sol"), "clean.sol")

        self.assertEqual(len(positive), 1)
        self.assertEqual(positive[0].detector, "state-change-between-check-and-use-amount-boundary")
        self.assertEqual(positive[0].function, "swap")
        self.assertIn("actual received delta", positive[0].message)
        self.assertEqual(clean, [])

    def test_ec_fot_starting_miss_fires_and_clean_control_is_silent(self) -> None:
        detector = _load_detector()
        ec_vuln = detector.scan(
            _read(PATTERNS / "ec-fot-token-in-non-fot-pool_vuln.sol"),
            "ec-fot-token-in-non-fot-pool_vuln.sol",
        )
        ec_clean = detector.scan(
            _read(PATTERNS / "ec-fot-token-in-non-fot-pool_clean.sol"),
            "ec-fot-token-in-non-fot-pool_clean.sol",
        )

        self.assertEqual(len(ec_vuln), 1)
        self.assertEqual(ec_vuln[0].function, "swap")
        self.assertEqual(ec_clean, [])

    def test_adjacent_starting_misses_are_not_folded_into_amount_boundary(self) -> None:
        detector = _load_detector()
        paymaster = detector.scan(
            _read(PATTERNS / "erc4337-paymaster-no-sender-validation_vuln.sol"),
            "erc4337-paymaster-no-sender-validation_vuln.sol",
        )
        fee_equality = detector.scan(
            _read(PATTERNS / "fx-v4core-swap-fee-equality-check_vuln.sol"),
            "fx-v4core-swap-fee-equality-check_vuln.sol",
        )

        self.assertEqual(paymaster, [])
        self.assertEqual(fee_equality, [])


if __name__ == "__main__":
    unittest.main()
