from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO / "detectors" / "wave17" / "state_check_then_external_or_mutating_use_fire17.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "state_check_then_external_or_mutating_use_fire17.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "state_check_then_external_or_mutating_use_fire17.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "state-check-then-external-or-mutating-use-fire17"
PAYMASTER_NO_SENDER = (
    REPO / "patterns" / "fixtures" / "erc4337-paymaster-no-sender-validation_vuln.sol"
)
FEE_EQUALITY = (
    REPO / "patterns" / "fixtures" / "fx-v4core-swap-fee-equality-check_vuln.sol"
)
EC_FOT_VULN = REPO / "patterns" / "fixtures" / "ec-fot-token-in-non-fot-pool_vuln.sol"
EC_FOT_CLEAN = REPO / "patterns" / "fixtures" / "ec-fot-token-in-non-fot-pool_clean.sol"
CEI_VULN = REPO / "patterns" / "fixtures" / "cei_violation_strict_vuln.sol"


def _load_detector():
    module_name = "state_check_then_external_or_mutating_use_fire17"
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


class StateCheckThenExternalOrMutatingUseFire17Test(unittest.TestCase):
    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), POSITIVE.name)
        negative = detector.scan(_read(NEGATIVE), NEGATIVE.name)

        self.assertEqual(len(positive), 3)
        self.assertEqual({finding.detector for finding in positive}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in positive},
            {"swap", "validatePaymasterUserOp", "swapWithNominalAmount"},
        )
        self.assertEqual({finding.severity for finding in positive}, {"Medium"})
        self.assertEqual(negative, [])

        messages = "\n".join(finding.message for finding in positive)
        self.assertIn("checked feeBefore before external effect", messages)
        self.assertIn("checked userOp.sender, allowedSenders before external effect", messages)
        self.assertIn("used nominal amountIn reserve math", messages)

    def test_fixture_pair_contains_revalidation_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("require(feeBefore < MAX_SWAP_FEE", positive)
        self.assertIn("ISwapHookFire17(hook).beforeSwap", positive)
        self.assertIn("MAX_SWAP_FEE - feeBefore", positive)
        self.assertIn("policy.beforeSponsor(userOp.sender, maxCost);", positive)
        self.assertIn("uint256 quotedOut = amount0In * uint256(reserve1)", positive)
        self.assertNotIn("not sponsored after policy", positive)

        self.assertIn("uint24 feeAfter = dynamicFee;", negative)
        self.assertIn("MAX_SWAP_FEE - feeAfter", negative)
        self.assertIn("not sponsored after policy", negative)
        self.assertIn("uint256 actualReceived = balanceAfter - balanceBefore;", negative)

    def test_ec_fot_starting_sample_fires_and_clean_control_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(EC_FOT_VULN), EC_FOT_VULN.name)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].function, "swap")
        self.assertIn("nominal amountIn", findings[0].message)
        self.assertEqual(detector.scan(_read(EC_FOT_CLEAN), EC_FOT_CLEAN.name), [])

    def test_incompatible_starting_samples_are_not_silently_folded_in(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.scan(_read(PAYMASTER_NO_SENDER), PAYMASTER_NO_SENDER.name), [])
        self.assertEqual(detector.scan(_read(FEE_EQUALITY), FEE_EQUALITY.name), [])
        self.assertEqual(detector.scan(_read(CEI_VULN), CEI_VULN.name), [])

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
