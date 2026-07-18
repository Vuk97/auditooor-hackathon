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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_merkle_leaf_domain_fire26.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_merkle_leaf_domain_fire26.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_merkle_leaf_domain_fire26.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-merkle-leaf-domain-fire26"
SNOWBRIDGE_MMR = (
    REPO
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_4855ace3_parent"
    / "contracts"
    / "src"
    / "utils"
    / "MMRProof.sol"
)
SNOWBRIDGE_SUBSTRATE = (
    REPO
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_4855ace3_parent"
    / "contracts"
    / "src"
    / "utils"
    / "SubstrateMerkleProof.sol"
)
SNOWBRIDGE_GATEWAY = (
    REPO
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_4855ace3_parent"
    / "contracts"
    / "src"
    / "Gateway.sol"
)
SNOWBRIDGE_VERIFICATION = (
    REPO
    / "reports"
    / "external_recall_snapshots"
    / "snowbridge_4855ace3_parent"
    / "contracts"
    / "src"
    / "Verification.sol"
)


def _load_detector():
    module_name = "bridge_merkle_leaf_domain_fire26"
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


class BridgeMerkleLeafDomainFire26Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("_has_domain_bound_leaf_before_proof", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        for token in (
            "sourceChainId",
            "sourceBridgeEndpoint",
            "palletModuleId",
            "channelId",
            "messageNonce",
            "verifyLeafProof",
        ):
            self.assertIn(token, positive)
            self.assertIn(token, negative)

        self.assertIn("keccak256(abi.encode(messageRoot, payloadHash))", positive)
        self.assertIn(
            "IBridgeLeafDomainExecutorFire26(localBridgeExecutor).dispatch(payload)",
            positive,
        )
        self.assertNotIn("BRIDGE_LEAF_DOMAIN,", positive)

        self.assertIn("BRIDGE_LEAF_DOMAIN", negative)
        self.assertIn("TRUSTED_SOURCE_CHAIN_ID", negative)
        self.assertIn("trustedSourceBridgeEndpoint", negative)
        self.assertIn("OUTBOUND_QUEUE_PALLET_ID", negative)
        self.assertIn("INBOUND_CHANNEL_ID", negative)
        self.assertIn("sourceChainId,\n                sourceBridgeEndpoint", negative)
        self.assertIn("palletModuleId,\n                channelId,\n                messageNonce", negative)
        self.assertLess(
            negative.index("bytes32 leafHash = keccak256("),
            negative.index("SnowbridgeMerkleLeafDomainSafe.verifyLeafProof"),
        )

    def test_snowbridge_utility_samples_are_out_of_class_but_consumer_exists(self) -> None:
        detector = _load_detector()
        mmr = _read(SNOWBRIDGE_MMR)
        substrate = _read(SNOWBRIDGE_SUBSTRATE)
        gateway = _read(SNOWBRIDGE_GATEWAY)
        verification = _read(SNOWBRIDGE_VERIFICATION)

        self.assertIn("library MMRProof", mmr)
        self.assertIn("function verifyLeafProof", mmr)
        self.assertIn("library SubstrateMerkleProof", substrate)
        self.assertIn("function computeRoot", substrate)
        self.assertEqual(detector.scan(mmr, str(SNOWBRIDGE_MMR)), [])
        self.assertEqual(detector.scan(substrate, str(SNOWBRIDGE_SUBSTRATE)), [])

        self.assertIn("bytes32 leafHash = keccak256(abi.encode(message));", gateway)
        self.assertIn("MerkleProof.processProof(leafProof, leafHash)", gateway)
        self.assertIn("v2_dispatch(message)", gateway)
        self.assertIn("isCommitmentInHeaderDigest(commitment, proof.header, isV2)", verification)
        self.assertIn("SubstrateMerkleProof.computeRoot", verification)
        self.assertIn("createMMRLeaf(proof.leafPartial, parachainHeadsRoot)", verification)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "submitInboundBridgeMessage")
        self.assertIn("source_chain", positive[0].message)
        self.assertIn("bridge_endpoint", positive[0].message)
        self.assertIn("module_pallet", positive[0].message)
        self.assertIn("channel", positive[0].message)
        self.assertIn("message_nonce", positive[0].message)

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
