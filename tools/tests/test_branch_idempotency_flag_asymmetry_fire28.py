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
    REPO / "detectors" / "wave17" / "branch_idempotency_flag_asymmetry_fire28.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "branch_idempotency_flag_asymmetry_fire28.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "branch_idempotency_flag_asymmetry_fire28.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "branch-idempotency-flag-asymmetry-fire28"


def _load_detector():
    module_name = "branch_idempotency_flag_asymmetry_fire28"
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


class BranchIdempotencyFlagAsymmetryFire28Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "completeQueuedBridgeMessage",
                "applyProfitLossSettlement",
                "settleRewardClaim",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("branch idempotency flag asymmetry", messages)
        self.assertIn("terminal flag, checkpoint, or index update", messages)
        self.assertIn("processed, claimed, settled, checkpoint", messages)
        self.assertIn("shared finalizer", messages)

    def test_fixture_pair_contains_semantic_contrasts(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("processed[messageId] = true;", positive)
        self.assertIn("yieldFactor = payloadYieldFactor;", positive)
        self.assertIn("globalRewardIndex += profit;", positive)
        self.assertIn("lastUpdate = block.timestamp;", positive)
        self.assertIn("settled[claimId] = true;", positive)
        self.assertIn("userRewardIndex[msg.sender] = globalRewardIndex;", positive)

        self.assertIn("_finalizeBridgeMessage(messageId);", negative)
        self.assertIn("_commonSettlementFinalizer(claimId, msg.sender);", negative)
        self.assertIn("processed[messageId] = true;", negative)
        self.assertIn("settled[claimId] = true;", negative)
        self.assertIn("lastUpdate = block.timestamp;", negative)

    def test_regex_runner_discovers_detector_for_fixture_pair(self) -> None:
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
