from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "paymaster_sender_validation_tocu_fire30.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "paymaster_sender_validation_tocu_fire30.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "paymaster_sender_validation_tocu_fire30.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "paymaster-sender-validation-tocu-fire30"
PAYMASTER_OPEN_FAUCET = (
    REPO / "patterns" / "fixtures" / "erc4337-paymaster-no-sender-validation_vuln.sol"
)
TOKEN_DELTA = (
    REPO / "patterns" / "fixtures" / "state-change-between-check-and-use-token-delta-boundary_vuln.sol"
)


def _load_detector():
    module_name = "paymaster_sender_validation_tocu_fire30"
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


class PaymasterSenderValidationTocuFire30Test(unittest.TestCase):
    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), POSITIVE.name)
        negative = detector.scan(_read(NEGATIVE), NEGATIVE.name)

        self.assertEqual(len(positive), 2)
        self.assertEqual({finding.detector for finding in positive}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in positive},
            {"validatePaymasterUserOp", "routeFor"},
        )
        self.assertEqual({finding.severity for finding in positive}, {"Medium"})
        self.assertEqual(negative, [])

        messages = "\n".join(finding.message for finding in positive)
        self.assertIn("sender validation check-use boundary", messages)
        self.assertIn("keyed to different actor msg.sender", messages)
        self.assertIn("before an AA, paymaster, or router effect boundary", messages)

    def test_fixture_pair_documents_the_actor_mismatch_boundary(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("require(sponsored[userOp.sender]", positive)
        self.assertIn("policy.beforeSponsor(userOp.sender, maxCost);", positive)
        self.assertIn("charged[msg.sender] += maxCost;", positive)
        self.assertIn("sponsored[msg.sender] = true;", positive)

        self.assertIn("charged[userOp.sender] += maxCost;", negative)
        self.assertIn("return (abi.encode(userOp.sender, maxCost), 0);", negative)
        self.assertIn("sponsored[account] = true;", negative)
        self.assertIn("charged[owner] += 1;", negative)

    def test_adjacent_state_change_shapes_are_not_folded_in(self) -> None:
        detector = _load_detector()

        self.assertEqual(detector.scan(_read(PAYMASTER_OPEN_FAUCET), PAYMASTER_OPEN_FAUCET.name), [])
        self.assertEqual(detector.scan(_read(TOKEN_DELTA), TOKEN_DELTA.name), [])

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 2), (NEGATIVE, 0)):
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
