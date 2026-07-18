from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "paymaster_sender_validation_toctou_fire27.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "paymaster_sender_validation_toctou_fire27.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "paymaster_sender_validation_toctou_fire27.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "paymaster-sender-validation-toctou-fire27"
PATTERN_FIXTURES = REPO / "patterns" / "fixtures"
PAYMASTER_VULN = PATTERN_FIXTURES / "erc4337-paymaster-no-sender-validation_vuln.sol"
PAYMASTER_CLEAN = PATTERN_FIXTURES / "erc4337-paymaster-no-sender-validation_clean.sol"
FEE_EQUALITY = PATTERN_FIXTURES / "fx-v4core-swap-fee-equality-check_vuln.sol"
LIDO_DESYNC = PATTERN_FIXTURES / "lido-deposit-blocked-by-attacker_vuln.sol"


def _load_detector():
    module_name = "paymaster_sender_validation_toctou_fire27"
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


class PaymasterSenderValidationToctouFire27Test(unittest.TestCase):
    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), POSITIVE.name)
        negative = detector.scan(_read(NEGATIVE), NEGATIVE.name)

        self.assertEqual(len(positive), 1)
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "validatePaymasterUserOp")
        self.assertEqual(positive[0].severity, "Medium")
        self.assertIn("sender validation check-use boundary", positive[0].message)
        self.assertIn("postOp or charge path", positive[0].message)
        self.assertEqual(negative, [])

    def test_fixture_pair_documents_the_boundary_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("require(sponsored[userOp.sender]", positive)
        self.assertIn("return (abi.encode(maxCost), 0);", positive)
        self.assertIn("charged[msg.sender] += actualGasCost + checkedCost;", positive)

        self.assertIn("return (abi.encode(userOp.sender, maxCost), 0);", negative)
        self.assertIn("address sender, uint256 checkedCost", negative)
        self.assertIn("charged[sender] += actualGasCost + checkedCost;", negative)

    def test_starting_paymaster_no_sender_sample_fires_and_sender_gated_control_is_silent(self) -> None:
        detector = _load_detector()
        vuln = detector.scan(_read(PAYMASTER_VULN), PAYMASTER_VULN.name)
        clean = detector.scan(_read(PAYMASTER_CLEAN), PAYMASTER_CLEAN.name)

        self.assertEqual(len(vuln), 1)
        self.assertEqual(vuln[0].function, "validatePaymasterUserOp")
        self.assertIn("without binding UserOperation.sender", vuln[0].message)
        self.assertEqual(clean, [])

    def test_adjacent_state_change_sources_are_not_folded_in(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.scan(_read(FEE_EQUALITY), FEE_EQUALITY.name), [])
        self.assertEqual(detector.scan(_read(LIDO_DESYNC), LIDO_DESYNC.name), [])

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
