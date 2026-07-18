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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_beefy_commitment_domain_fire30.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_beefy_commitment_domain_fire30.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_beefy_commitment_domain_fire30.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-beefy-commitment-domain-fire30"
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
    module_name = "bridge_beefy_commitment_domain_fire30"
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


class BridgeBeefyCommitmentDomainFire30Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn('VERIFICATION_TIER = "tier-2-verified-public-archive"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("_unsafe_acceptance", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("bytes32 destinationDomain", positive)
        self.assertIn("uint64 validatorSetId", positive)
        self.assertIn("bytes32 applicationChannel", positive)
        self.assertIn("bytes32 commitmentHash = keccak256(encodeCommitment(commitment));", positive)
        self.assertIn("verifyCommitment(commitmentHash, bitfield, currentValidatorSet, proofs)", positive)
        self.assertIn("acceptedCommitments[commitmentHash] = true;", positive)
        self.assertNotIn("BEEFY_COMMITMENT_DOMAIN", positive)
        self.assertNotIn("checkedCommitmentDigest", positive)

        self.assertIn("BEEFY_COMMITMENT_DOMAIN", negative)
        self.assertIn("bytes32 checkedCommitmentDigest = keccak256(", negative)
        self.assertIn("sourceChainId,\n                block.chainid", negative)
        self.assertIn("destinationDomain,\n                validatorSetId", negative)
        self.assertIn("applicationChannel,\n                address(this)", negative)
        self.assertIn("commitmentHash,\n                newMMRRoot", negative)
        self.assertIn("verifyCommitment(checkedCommitmentDigest", negative)
        self.assertIn("acceptedCommitments[checkedCommitmentDigest] = true;", negative)
        self.assertLess(
            negative.index("bytes32 checkedCommitmentDigest = keccak256("),
            negative.index("verifyCommitment(checkedCommitmentDigest"),
        )

    def test_snowbridge_source_evidence_is_real(self) -> None:
        source = _read(SNOWBRIDGE_BEEFY)

        self.assertIn("function submitFinal", source)
        self.assertIn("function submitFiatShamir", source)
        self.assertIn("bytes32 commitmentHash = keccak256(encodeCommitment(commitment))", source)
        self.assertIn("verifyCommitment(commitmentHash, ticketID, bitfield, vset, proofs)", source)
        self.assertIn("verifyFiatShamirCommitment(commitmentHash, bitfield, vset, proofs)", source)
        self.assertIn("function createFiatShamirHash(", source)
        self.assertIn("bytes32 validatorSetRoot", source)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].function, "submitFinal")
        self.assertIn("destination_domain", positive[0].message)
        self.assertIn("chain_id", positive[0].message)
        self.assertIn("validator_set_id", positive[0].message)
        self.assertIn("application_channel", positive[0].message)

    def test_snowbridge_prefix_source_fires_on_commitment_acceptance(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(SNOWBRIDGE_BEEFY), str(SNOWBRIDGE_BEEFY))

        functions = {finding.function for finding in findings}
        self.assertIn("submitFinal", functions)
        self.assertIn("submitFiatShamir", functions)
        for finding in findings:
            self.assertEqual(finding.detector, DETECTOR_NAME)
            self.assertIn("BEEFY commitment verification accepts", finding.message)

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
