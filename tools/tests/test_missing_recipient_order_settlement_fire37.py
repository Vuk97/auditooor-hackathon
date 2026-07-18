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
    REPO / "detectors" / "wave17" / "missing_recipient_order_settlement_fire37.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "missing_recipient_order_settlement_fire37.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "missing_recipient_order_settlement_fire37.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "missing-recipient-order-settlement-fire37"


def _load_detector():
    module_name = "missing_recipient_order_settlement_fire37"
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


class MissingRecipientOrderSettlementFire37Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 5)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {
                "fillSignedOrder",
                "claimToCalldataBeneficiary",
                "releaseEscrow",
                "settleToCaller",
                "settleHardcodedMaker",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("calldata settlement recipient is not bound", messages)
        self.assertIn("hardcoded settlement sink is not bound", messages)
        self.assertIn("signed order", messages)
        self.assertIn("claim proof", messages)
        self.assertIn("escrow owner", messages)
        self.assertIn("stored settlement target", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_false_positive_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("safeTransfer(recipient, order.amountOut)", positive)
        self.assertIn("safeTransfer(beneficiary, claim.claimAmount)", positive)
        self.assertIn("safeTransfer(payoutTo, escrow.amount)", positive)
        self.assertIn("safeTransfer(msg.sender, settlement.amount)", positive)
        self.assertIn("safeTransfer(order.maker, order.amountOut)", positive)
        self.assertNotIn("if (beneficiary != claim.beneficiary)", positive)
        self.assertNotIn("hashOrder(order, recipient)", positive)

        self.assertIn("bytes32 digest = hashOrder(order, recipient);", negative)
        self.assertIn("if (beneficiary != claim.beneficiary) revert RecipientMismatch();", negative)
        self.assertIn("if (payoutTo != escrow.owner) revert RecipientMismatch();", negative)
        self.assertIn("address target = settlement.settlementTarget;", negative)
        self.assertIn("if (!authorizedRecipient[order.recipient][payoutTo]) revert NotAllowed();", negative)
        self.assertIn("external onlyOwner", negative)

    def test_detector_metadata_keeps_hits_candidate_only(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.PROMOTION_ALLOWED, False)
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertEqual(detector.VERIFICATION_TIER, "tier-3-synthetic-taxonomy-anchored")
        for ref in detector.SOURCE_REFS:
            self.assertTrue((REPO / ref).exists(), ref)
        self.assertIn(
            "reports/detector_lift_fire36_20260605/post_priorities_solidity.md",
            detector.SOURCE_REFS,
        )
        self.assertIn(
            "detectors/wave17/missing_recipient_claim_sink_fire36.py",
            detector.SOURCE_REFS,
        )
        self.assertIn(
            "detectors/wave17/recipient_settlement_target_fire35.py",
            detector.SOURCE_REFS,
        )

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 5), (NEGATIVE, 0)):
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
