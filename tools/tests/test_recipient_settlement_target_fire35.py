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
DETECTOR_PATH = (
    REPO / "detectors" / "wave17" / "recipient_settlement_target_fire35.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "recipient_settlement_target_fire35.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "recipient_settlement_target_fire35.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "recipient-settlement-target-fire35"


def _load_detector():
    module_name = "recipient_settlement_target_fire35"
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


class RecipientSettlementTargetFire35Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 4)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {
                "settleCallerTarget",
                "fillOrder",
                "claimWithCallback",
                "withdrawToStoredSink",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("settlement target is not bound", messages)
        self.assertIn("hardcoded settlement sink is not bound", messages)
        self.assertIn("callback-return", messages)
        self.assertIn("`payoutTarget`", messages)
        self.assertIn("`order.receiver`", messages)
        self.assertIn("`callbackTarget`", messages)
        self.assertIn("`settlementSink`", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_target_authority_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("safeTransfer(payoutTarget, amount)", positive)
        self.assertIn("safeTransfer(order.receiver, order.amountOut)", positive)
        self.assertIn("safeTransfer(callbackTarget, payoutAmount)", positive)
        self.assertIn("safeTransfer(settlementSink, amount)", positive)
        self.assertNotIn("payoutTarget != owner", positive)

        self.assertIn("if (payoutTarget != owner) revert RecipientMismatch();", negative)
        self.assertIn("if (order.receiver != order.maker) revert RecipientMismatch();", negative)
        self.assertIn(
            "if (callbackTarget != claim.canonicalRecipient) revert RecipientMismatch();",
            negative,
        )
        self.assertIn("if (settlementSink != receiver) revert RecipientMismatch();", negative)
        self.assertIn("if (!authorizedRecipient[owner][payoutTarget]) revert NotAllowed();", negative)
        self.assertIn("external onlyOwner", negative)

    def test_detector_metadata_keeps_hits_candidate_only(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.PROMOTION_ALLOWED, False)
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertEqual(detector.VERIFICATION_TIER, "tier-3-synthetic-taxonomy-anchored")
        for ref in detector.SOURCE_REFS:
            self.assertTrue((REPO / ref).exists(), ref)
        self.assertIn(
            "reference/patterns.dsl/missing-recipient-validation-transfer-or-credit.yaml",
            detector.SOURCE_REFS,
        )
        self.assertIn(
            "detectors/go_wave1/go-bridge-transferout-recipient-binding-missing.py",
            detector.SOURCE_REFS,
        )

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
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


if __name__ == "__main__":
    unittest.main()
