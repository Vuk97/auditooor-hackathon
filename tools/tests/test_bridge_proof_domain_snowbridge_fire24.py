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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_proof_domain_snowbridge_fire24.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_proof_domain_snowbridge_fire24.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_proof_domain_snowbridge_fire24.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-proof-domain-snowbridge-fire24"
SNOWBRIDGE_VERIFICATION = (
    REPO
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_4855ace3_parent"
    / "contracts"
    / "src"
    / "Verification.sol"
)
SNOWBRIDGE_BEEFY = (
    REPO
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_ba20bc65_parent"
    / "contracts"
    / "src"
    / "BeefyClient.sol"
)


def _load_detector():
    module_name = "bridge_proof_domain_snowbridge_fire24"
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


class BridgeProofDomainSnowbridgeFire24Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("_has_domain_bound_proof_before_dispatch", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("sourceChainId", positive)
        self.assertIn("sourceBridgeInstance", positive)
        self.assertIn("channelId", positive)
        self.assertIn("parachainId", positive)
        self.assertIn("destinationAdapter", positive)
        self.assertIn("verifyMMRLeafProof", positive)
        self.assertIn("keccak256(abi.encode(messageCommitment, payloadHash))", positive)
        self.assertIn("ISnowbridgeDestinationAdapter(destinationAdapter).dispatch(payload)", positive)
        self.assertNotIn("SNOWBRIDGE_PROOF_DOMAIN", positive)
        self.assertNotIn("sourceBridgeInstance,\n                channelId", positive)

        self.assertIn("TRUSTED_SOURCE_CHAIN", negative)
        self.assertIn("trustedSourceBridge", negative)
        self.assertIn("INBOUND_CHANNEL", negative)
        self.assertIn("BRIDGE_HUB_PARACHAIN", negative)
        self.assertIn("localDestinationAdapter", negative)
        self.assertIn("SNOWBRIDGE_PROOF_DOMAIN", negative)
        self.assertIn("sourceChainId,\n                sourceBridgeInstance", negative)
        self.assertIn("channelId,\n                parachainId", negative)
        self.assertIn("destinationAdapter,\n                address(this)", negative)
        self.assertLess(
            negative.index("bytes32 proofLeaf = keccak256("),
            negative.index("SnowbridgeProofSafe.verifyMMRLeafProof"),
        )
        self.assertLess(
            negative.index("SnowbridgeProofSafe.verifyMMRLeafProof"),
            negative.index("ISnowbridgeDestinationAdapterSafe(destinationAdapter).dispatch(payload)"),
        )

    def test_snowbridge_source_evidence_is_real_and_scope_bounded(self) -> None:
        verification = _read(SNOWBRIDGE_VERIFICATION)
        beefy = _read(SNOWBRIDGE_BEEFY)

        self.assertIn("isCommitmentInHeaderDigest(commitment, proof.header, isV2)", verification)
        self.assertIn("createParachainHeaderMerkleLeaf(encodedParaID, proof.header)", verification)
        self.assertIn("verifyMMRLeafProof", verification)
        self.assertIn("ensureProvidesMMRRoot(commitment)", beefy)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "relaySnowbridgeMessage")
        self.assertIn("source chain", positive[0].message)
        self.assertIn("destination adapter", positive[0].message)

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
