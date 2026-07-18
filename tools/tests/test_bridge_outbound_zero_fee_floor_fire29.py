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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_outbound_zero_fee_floor_fire29.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "bridge_outbound_zero_fee_floor_fire29.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "bridge_outbound_zero_fee_floor_fire29.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-outbound-zero-fee-floor-fire29"


def _load_detector():
    module_name = "bridge_outbound_zero_fee_floor_fire29"
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


class BridgeOutboundZeroFeeFloorFire29Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("reference/patterns.dsl/bridge-outbound-no-fee-floor-zero-message-spam.yaml", detector_text)
        self.assertIn("reference/patterns.dsl/bridge-relayer-reward-paid-on-failed-dispatch.yaml", detector_text)
        self.assertIn("reference/patterns.dsl/two-hop-bridge-transfer-restriction-bypass.yaml", detector_text)
        self.assertIn("Candidate evidence only", detector_text)
        self.assertIn("_zero_fee_floor_result", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function sendOutboundMessage(", positive)
        self.assertIn("uint256 totalFee = executionFee + relayerFee;", positive)
        self.assertIn('require(msg.value >= totalFee, "native fee");', positive)
        self.assertIn("uint64 nonce = outboundNonce++;", positive)
        self.assertIn("outboundMessages[nonce] = OutboundMessage", positive)
        self.assertIn("emit OutboundMessageQueued", positive)
        self.assertNotIn("MIN_EXECUTION_FEE", positive)
        self.assertNotIn("EmptyMessage", positive)

        self.assertIn("uint256 public constant MIN_EXECUTION_FEE", negative)
        self.assertIn("uint256 public constant MIN_RELAYER_FEE", negative)
        self.assertIn("if (payload.length == 0 && assets.length == 0) revert EmptyMessage();", negative)
        self.assertIn("if (executionFee < MIN_EXECUTION_FEE) revert FeeTooLow();", negative)
        self.assertIn("if (relayerFee < MIN_RELAYER_FEE) revert FeeTooLow();", negative)
        self.assertIn('require(msg.value >= totalFee, "native fee");', negative)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "sendOutboundMessage")
        self.assertIn("no minimum outbound fee floor", positive[0].message)
        self.assertIn("Candidate evidence only", positive[0].message)

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
                self.assertNotIn("No custom detectors found", proc.stdout)
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)


if __name__ == "__main__":
    unittest.main()
