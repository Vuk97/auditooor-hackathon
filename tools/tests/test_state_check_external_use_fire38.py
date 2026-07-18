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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "state_check_external_use_fire38.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "state_check_external_use_fire38.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "state_check_external_use_fire38.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
PATTERN_FIXTURES = REPO / "patterns" / "fixtures"
PAYMASTER_OPEN_FAUCET = PATTERN_FIXTURES / "erc4337-paymaster-no-sender-validation_vuln.sol"
FEE_EQUALITY = PATTERN_FIXTURES / "fx-v4core-swap-fee-equality-check_vuln.sol"
TOKEN_DELTA = PATTERN_FIXTURES / "state-change-between-check-and-use-token-delta-boundary_vuln.sol"
DETECTOR_NAME = "state-check-external-use-fire38"


def _load_detector():
    module_name = "state_check_external_use_fire38"
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


class StateCheckExternalUseFire38Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertFalse(detector.PROMOTION_ALLOWED)

    def test_positive_fixture_fires_on_four_stale_acceptance_boundaries(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 4, findings)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "validatePaymasterUserOp",
                "swapWithHookFee",
                "collectAfterBalanceCheck",
                "acceptInvariantAfterMutableFee",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("sender policy `userOp.sender`", messages)
        self.assertIn("fee/config `swapFee`", messages)
        self.assertIn("balance/reserve `balanceBefore`", messages)
        self.assertIn("invariant `invariantBefore`", messages)
        self.assertIn("external call", messages)
        self.assertIn("mutable state transition", messages)
        self.assertIn("final acceptance", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_negative_fixture_revalidates_or_reloads_before_acceptance(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        negative = _read(NEGATIVE)
        self.assertIn("require(allowedSenders[userOp.sender], \"not sponsored after policy\");", negative)
        self.assertIn("uint24 refreshedSwapFee = poolSwapFee[poolId];", negative)
        self.assertIn("uint256 balanceAfter = token.balanceOf(address(this));", negative)
        self.assertIn("uint256 invariantAfter = uint256(reserve0) * uint256(reserve1);", negative)
        self.assertIn("// hook.beforeCollect(receiver, balanceBefore);", negative)

    def test_source_seed_fixtures_are_boundaries_not_direct_positive_claims(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.scan(_read(PAYMASTER_OPEN_FAUCET), str(PAYMASTER_OPEN_FAUCET)), [])
        self.assertEqual(detector.scan(_read(FEE_EQUALITY), str(FEE_EQUALITY)), [])
        self.assertEqual(detector.scan(_read(TOKEN_DELTA), str(TOKEN_DELTA)), [])

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
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

    def test_source_refs_and_no_unicode_dashes_in_owned_sources(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        self.assertIn("reports/detector_lift_fire37_20260605/post_priorities_solidity.md", detector_text)
        self.assertIn(
            "reference/patterns.dsl/state-change-between-check-and-use-token-delta-boundary.yaml",
            detector_text,
        )
        self.assertIn("reference/patterns.dsl/erc4337-paymaster-no-sender-validation.yaml", detector_text)
        self.assertIn("reference/patterns.dsl/fx-v4core-swap-fee-equality-check.yaml", detector_text)
        self.assertIn("detectors/wave17/reentrancy_share_callback_midstate_fire37.py", detector_text)
        self.assertIn(".auditooor/memory_context_receipt.json", detector_text)
        self.assertIn("R37", detector_text)
        self.assertIn("R40", detector_text)
        self.assertIn("R76", detector_text)
        self.assertIn("R80", detector_text)

        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
