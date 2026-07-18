from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "swap_fee_equality_toctou_fire27.py"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / "swap_fee_equality_toctou_fire27.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / "swap_fee_equality_toctou_fire27.sol"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
PATTERN_FIXTURES = ROOT / "patterns" / "fixtures"
FEE_EQUALITY_VULN = PATTERN_FIXTURES / "fx-v4core-swap-fee-equality-check_vuln.sol"
PAYMASTER_VULN = PATTERN_FIXTURES / "erc4337-paymaster-no-sender-validation_vuln.sol"
R94_WITHDRAW_VULN = ROOT / "detectors" / "fixtures" / "r94_reverse_withdraw_transfer_failure_swallowed" / "positive.sol"
DETECTOR_NAME = "swap-fee-equality-toctou-fire27"


def _load_detector():
    module_name = "swap_fee_equality_toctou_fire27"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class SwapFeeEqualityToctouFire27Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("state-change-between-check-and-use", detector_text)
        self.assertIn("fx-v4core-swap-fee-equality-check.yaml", detector_text)
        self.assertIn("erc4337-paymaster-no-sender-validation.yaml", detector_text)
        self.assertIn("r94-reverse-withdraw-transfer-failure-swallowed.yaml", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("if (swapFee == MAX_SWAP_FEE)", positive_text)
        self.assertIn("config.hook.beforeSwap(msg.sender, poolId, amountSpecified);", positive_text)
        self.assertIn("_settleSwapWithFee(amountSpecified, swapFee);", positive_text)

        self.assertIn("uint24 refreshedSwapFee = poolConfig[poolId].swapFee;", negative_text)
        self.assertIn("require(refreshedSwapFee <= MAX_SWAP_FEE", negative_text)
        self.assertIn("require(swapFee == poolConfig[poolId].swapFee", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive_hits = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_hits = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_hits), 1, positive_hits)
        self.assertEqual(negative_hits, [])

        hit = positive_hits[0]
        self.assertEqual(hit.detector, DETECTOR_NAME)
        self.assertEqual(hit.severity, "Medium")
        self.assertEqual(hit.function, "swap")
        self.assertIn("swap fee/config state-change-between-check-and-use boundary", hit.message)
        self.assertIn("external hook or mutable call", hit.message)
        self.assertIn("NOT_SUBMIT_READY", hit.message)

    def test_source_ref_fixtures_are_not_folded_into_this_toctou_detector(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.scan(_read(FEE_EQUALITY_VULN), str(FEE_EQUALITY_VULN)), [])
        self.assertEqual(detector.scan(_read(PAYMASTER_VULN), str(PAYMASTER_VULN)), [])
        self.assertEqual(detector.scan(_read(R94_WITHDRAW_VULN), str(R94_WITHDRAW_VULN)), [])

    def test_regex_runner_reports_positive_only(self) -> None:
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
                    cwd=ROOT,
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
