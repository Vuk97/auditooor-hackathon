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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_proof_snowbridge_adapter_fire25.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_proof_snowbridge_adapter_fire25.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_proof_snowbridge_adapter_fire25.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-proof-snowbridge-adapter-fire25"


def _load_detector():
    module_name = "bridge_proof_snowbridge_adapter_fire25"
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


class BridgeProofSnowbridgeAdapterFire25Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("_has_domain_bound_proof_before_sink", detector_text)
        self.assertIn("chain id, local adapter address, source bridge endpoint", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("sourceChainId", positive)
        self.assertIn("localAdapterAddress", positive)
        self.assertIn("sourceBridgeEndpoint", positive)
        self.assertIn("channelId", positive)
        self.assertIn("destinationBridgeEndpoint", positive)
        self.assertIn("verifier.verify(proofDigest, proof)", positive)
        self.assertIn("keccak256(abi.encode(messageRoot, nonce, payloadHash))", positive)
        self.assertIn("keccak256(abi.encode(messageRoot, nonce))", positive)
        self.assertIn("ISnowbridgeDestinationBridgeEndpointFire25(destinationBridgeEndpoint).dispatch(payload)", positive)
        self.assertNotIn("SNOWBRIDGE_ADAPTER_DOMAIN", positive)

        self.assertIn("SNOWBRIDGE_ADAPTER_DOMAIN", negative)
        self.assertIn("TRUSTED_SOURCE_CHAIN_ID", negative)
        self.assertIn("trustedSourceBridgeEndpoint", negative)
        self.assertIn("INBOUND_CHANNEL_ID", negative)
        self.assertIn("trustedDestinationBridgeEndpoint", negative)
        self.assertIn("localAdapterAddress,\n                sourceBridgeEndpoint", negative)
        self.assertIn("channelId,\n                destinationBridgeEndpoint", negative)
        self.assertIn("messageRoot,\n                nonce,\n                payloadHash", negative)
        self.assertLess(
            negative.index("bytes32 proofDigest = keccak256("),
            negative.index("verifier.verify(proofDigest, proof)"),
        )
        self.assertLess(
            negative.index("verifier.verify(proofDigest, proof)"),
            negative.index("consumedMessages[consumedKey] = true;"),
        )

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "consumeInboundSnowbridgeMessage")
        self.assertIn("chain_id", positive[0].message)
        self.assertIn("source_endpoint", positive[0].message)
        self.assertIn("destination_endpoint", positive[0].message)

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
