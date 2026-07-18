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
    REPO / "detectors" / "wave17" / "missing_recipient_transfer_args_fire31.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "missing_recipient_transfer_args_fire31.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "missing_recipient_transfer_args_fire31.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "missing-recipient-transfer-args-fire31"


def _load_detector():
    module_name = "missing_recipient_transfer_args_fire31"
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


class MissingRecipientTransferArgsFire31Test(unittest.TestCase):
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
            {"bridgeToken", "transferReward", "dispatchRemote", "releaseEscrow"},
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("caller-supplied token, amount, and recipient", messages)
        self.assertIn("validates `asset` against address(0)", messages)
        self.assertIn("never rejects zero recipient `receiver`", messages)
        self.assertIn("hardcodes outbound recipient", messages)
        self.assertIn("`msg.sender`", messages)
        self.assertIn("`owner`", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_fixture_pair_locks_transfer_arg_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("emit BridgeQueued(token, msg.sender, amount);", positive)
        self.assertIn("IERC20TransferArgsFire31Positive(asset).safeTransfer(receiver, amount);", positive)
        self.assertIn("_dispatchBridgeMessage(bridgeToken_, bridgeAmount, msg.sender);", positive)
        self.assertIn("IERC20TransferArgsFire31Positive(token).safeTransfer(owner, amount);", positive)

        self.assertIn("if (recipient == address(0)) revert InvalidRecipient();", negative)
        self.assertIn("emit BridgeQueued(token, recipient, amount);", negative)
        self.assertIn("_dispatchBridgeMessage(bridgeToken_, bridgeAmount, remoteRecipient);", negative)
        self.assertIn("if (recipient != msg.sender) revert RecipientMismatch();", negative)
        self.assertIn("IERC20TransferArgsFire31Negative(token).safeTransfer(msg.sender, refundAmount);", negative)

    def test_detector_metadata_keeps_hits_candidate_only(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.PROMOTION_ALLOWED, False)
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertIn(
            "reports/detector_lift_fire30_20260605/post_priorities_all.md",
            detector.SOURCE_REFS,
        )
        self.assertIn(
            "detectors/wave17/missing_recipient_param_order_fire30.py",
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
