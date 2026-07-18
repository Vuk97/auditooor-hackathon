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
    REPO / "detectors" / "wave17" / "missing_recipient_claim_sink_fire36.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "missing_recipient_claim_sink_fire36.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "missing_recipient_claim_sink_fire36.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "missing-recipient-claim-sink-fire36"


def _load_detector():
    module_name = "missing_recipient_claim_sink_fire36"
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


class MissingRecipientClaimSinkFire36Test(unittest.TestCase):
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
                "claimIgnoredRecipient",
                "withdrawClaimSink",
                "redeemReplacedRecipient",
                "settleProofRecipientUnbound",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("user supplied recipient is ignored", messages)
        self.assertIn("recipient alias is overwritten", messages)
        self.assertIn("recipient sink is not bound to proof payload recipient", messages)
        self.assertIn("`msg.sender`", messages)
        self.assertIn("`claim.recipient`", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_claim_sink_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("safeTransfer(msg.sender, amount)", positive)
        self.assertIn("safeTransfer(claim.claimant, claim.amount)", positive)
        self.assertIn("payout = msg.sender;", positive)
        self.assertIn("safeTransfer(recipient, claim.amount)", positive)
        self.assertNotIn("recipient != claim.recipient", positive)

        self.assertIn("_verifyClaim(proof, msg.sender, recipient, amount)", negative)
        self.assertIn("if (recipient != msg.sender) revert RecipientMismatch();", negative)
        self.assertIn("if (recipient != claim.recipient) revert RecipientMismatch();", negative)
        self.assertIn("_verifyClaim(proof, claim.claimant, claim.recipient, claim.amount)", negative)
        self.assertIn("if (!allowedRecipient[msg.sender][recipient]) revert NotAllowed();", negative)
        self.assertIn("safeTransfer(msg.sender, refundAmount)", negative)
        self.assertIn("external onlyOwner", negative)

    def test_detector_metadata_keeps_hits_candidate_only(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.PROMOTION_ALLOWED, False)
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertEqual(detector.VERIFICATION_TIER, "tier-3-synthetic-taxonomy-anchored")
        for ref in detector.SOURCE_REFS:
            self.assertTrue((REPO / ref).exists(), ref)
        self.assertIn(
            "reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml",
            detector.SOURCE_REFS,
        )
        self.assertIn(
            "detectors/wave17/recipient_settlement_target_fire35.py",
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
