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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_proof_adapter_domain_fire32.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_proof_adapter_domain_fire32.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_proof_adapter_domain_fire32.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-proof-adapter-domain-fire32"


def _load_detector():
    module_name = "bridge_proof_adapter_domain_fire32"
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


class BridgeProofAdapterDomainFire32Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn('VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("bridge-proof-domain-bypass", detector_text)
        self.assertIn("bridge-proof-domain-bypass-umbrella", detector_text)
        self.assertIn("bridge-replay-key-omits-chain-domain", detector_text)
        self.assertIn("bridge-receiver-domain-omitted-from-proof-digest", detector_text)
        self.assertIn("adapter, endpoint, chain, lane, or application-domain", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function consumeAdapterProof(", positive)
        self.assertIn("sourceChainId", positive)
        self.assertIn("sourceBridgeEndpoint", positive)
        self.assertIn("localAdapterAddress", positive)
        self.assertIn("laneId", positive)
        self.assertIn("applicationDomain", positive)
        self.assertIn("destinationBridgeEndpoint", positive)
        self.assertIn("bytes32 consumedId = keccak256(abi.encode(proofRoot, nonce, payloadHash));", positive)
        self.assertIn("verifier.verify(consumedId, proof)", positive)
        self.assertIn("consumedMessageIds[consumedId] = true;", positive)
        self.assertNotIn("BRIDGE_ADAPTER_DOMAIN_FIRE32", positive)
        self.assertNotIn("destinationChainId", positive)

        self.assertIn("BRIDGE_ADAPTER_DOMAIN_FIRE32", negative)
        self.assertIn("destinationChainId == block.chainid", negative)
        self.assertIn("bytes32 consumedId = keccak256(", negative)
        self.assertIn("sourceChainId,\n                destinationChainId", negative)
        self.assertIn("sourceBridgeEndpoint,\n                localAdapterAddress", negative)
        self.assertIn("laneId,\n                applicationDomain", negative)
        self.assertIn("destinationBridgeEndpoint,\n                address(this)", negative)
        self.assertIn("proofRoot,\n                nonce,\n                payloadHash", negative)
        self.assertIn("consumedMessageIds[consumedId] = true;", negative)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].severity, "High")
        self.assertEqual(positive[0].function, "consumeAdapterProof")
        self.assertIn("source chain domain", positive[0].message)
        self.assertIn("source endpoint", positive[0].message)
        self.assertIn("destination endpoint", positive[0].message)
        self.assertIn("adapter address", positive[0].message)
        self.assertIn("lane or channel id", positive[0].message)
        self.assertIn("application domain", positive[0].message)
        self.assertIn("NOT_SUBMIT_READY", positive[0].message)

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
