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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_beefy_validator_domain_fire35.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_beefy_validator_domain_fire35.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_beefy_validator_domain_fire35.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-beefy-validator-domain-fire35"


def _load_detector():
    module_name = "bridge_beefy_validator_domain_fire35"
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


class BridgeBeefyValidatorDomainFire35Test(unittest.TestCase):
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
        self.assertIn("bridge-proof-domain-bypass-verifier-digest-omits-domain", detector_text)
        self.assertIn("bridge-fiat-shamir-transcript-omits-validator-set-domain", detector_text)
        self.assertIn("bridge_beefy_commitment_domain_fire30.py", detector_text)
        self.assertIn("bridge_external_replay_domain_fire34.py", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        for token in (
            "function submitValidatorRoot(",
            "sourceChainId",
            "destinationDomain",
            "localAdapter",
            "validatorSetId",
            "commitmentRoot",
            "proofRoot",
            "beefyLightClient.verifyValidatorSetProof",
            "acceptedValidatorTranscripts[signedTranscript] = true;",
            "acceptedCommitmentRoot[validatorSetId] = commitmentRoot;",
            "IFire35Adapter",
        ):
            self.assertIn(token, positive)
            self.assertIn(token, negative)

        self.assertIn(
            "bytes32 signedTranscript = keccak256(abi.encode(proofRoot, payloadHash));",
            positive,
        )
        self.assertNotIn("BEEFY_VALIDATOR_DOMAIN_FIRE35", positive)
        self.assertNotIn("abi.encode(\n                BEEFY_VALIDATOR_DOMAIN_FIRE35", positive)

        self.assertIn("BEEFY_VALIDATOR_DOMAIN_FIRE35", negative)
        self.assertIn("localAdapter == address(this)", negative)
        self.assertIn("sourceChainId,\n                destinationDomain", negative)
        self.assertIn("block.chainid,\n                localAdapter", negative)
        self.assertIn("address(this),\n                validatorSetId", negative)
        self.assertIn("commitmentRoot,\n                proofRoot", negative)
        self.assertLess(
            negative.index("bytes32 signedTranscript = keccak256("),
            negative.index("beefyLightClient.verifyValidatorSetProof"),
        )

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].severity, "High")
        self.assertEqual(positive[0].function, "submitValidatorRoot")

        message = positive[0].message
        self.assertIn("BEEFY validator proof transcript omits replay domain", message)
        self.assertIn("validator-set id", message)
        self.assertIn("commitment root", message)
        self.assertIn("source chain", message)
        self.assertIn("destination domain", message)
        self.assertIn("adapter address", message)
        self.assertIn("NOT_SUBMIT_READY", message)

    def test_inline_domain_bound_hash_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        contract InlineClean {
            bytes32 private constant BEEFY_VALIDATOR_DOMAIN_FIRE35 = bytes32(uint256(7));
            mapping(bytes32 => bool) public acceptedValidatorTranscripts;
            function submitValidatorRoot(
                uint256 sourceChainId,
                bytes32 destinationDomain,
                address localAdapter,
                uint64 validatorSetId,
                bytes32 commitmentRoot,
                bytes32 proofRoot,
                bytes calldata proof
            ) external {
                require(verifyValidatorSetProof(
                    keccak256(abi.encode(
                        BEEFY_VALIDATOR_DOMAIN_FIRE35,
                        sourceChainId,
                        destinationDomain,
                        block.chainid,
                        localAdapter,
                        address(this),
                        validatorSetId,
                        commitmentRoot,
                        proofRoot
                    )),
                    proof
                ));
                acceptedValidatorTranscripts[commitmentRoot] = true;
            }
            function verifyValidatorSetProof(bytes32 digest, bytes calldata proof)
                internal
                pure
                returns (bool)
            {
                return digest != bytes32(0) && proof.length != 0;
            }
        }
        """
        self.assertEqual(detector.scan(source), [])

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
