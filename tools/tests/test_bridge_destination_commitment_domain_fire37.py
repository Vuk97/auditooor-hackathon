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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_destination_commitment_domain_fire37.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_destination_commitment_domain_fire37.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_destination_commitment_domain_fire37.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-destination-commitment-domain-fire37"


def _load_detector():
    module_name = "bridge_destination_commitment_domain_fire37"
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


class BridgeDestinationCommitmentDomainFire37Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn('VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("bridge-proof-domain-bypass", detector_text)
        self.assertIn("bridge-destination-settlement-unproven-source-commitment.yaml", detector_text)
        self.assertIn("bridge_proof_route_domain_fire36.py", detector_text)
        self.assertIn("bridge-destination-settlement-unproven-source-fire9.yaml", detector_text)
        self.assertIn("bridge_destination_settlement_unproven_source_commitment.py", detector_text)
        self.assertIn("source commitment, destination chain, receiver domain, route id, or adapter id", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        for token in (
            "function finalizeDestinationSettlement(",
            "acceptedRoot",
            "sourceCommitment",
            "destinationChainId",
            "receiverDomain",
            "routeId",
            "adapterId",
            "relayVerifier.verifySourceRoot(acceptedRoot, rootProof)",
            "settledCommitments[sourceCommitment] = true;",
            "mintedCredit[recipient] += amount;",
            "executeMessage(routeId, payload)",
        ):
            self.assertIn(token, positive)
            self.assertIn(token, negative)

        self.assertNotIn("BRIDGE_DESTINATION_COMMITMENT_DOMAIN_FIRE37", positive)
        self.assertNotIn("Fire37MerkleProof.verify", positive)

        self.assertIn("BRIDGE_DESTINATION_COMMITMENT_DOMAIN_FIRE37", negative)
        self.assertIn("destinationChainId,\n                receiverDomain", negative)
        self.assertIn("routeId,\n                adapterId", negative)
        self.assertIn("sourceCommitment,\n                destinationChainId", negative)
        self.assertIn("address(this),\n                recipient", negative)
        self.assertIn("Fire37MerkleProof.verify(settlementProof, acceptedRoot, settlementLeaf)", negative)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].severity, "High")
        self.assertEqual(positive[0].function, "finalizeDestinationSettlement")

        message = positive[0].message
        self.assertIn("Bridge destination settlement reaches consume marker", message)
        self.assertIn("source commitment", message)
        self.assertIn("destination chain", message)
        self.assertIn("receiver domain", message)
        self.assertIn("route id", message)
        self.assertIn("adapter id", message)
        self.assertIn("NOT_SUBMIT_READY", message)

    def test_source_commitment_proven_but_destination_domain_omitted_still_fires(self) -> None:
        detector = _load_detector()
        source = """
        contract SourceOnlyProof {
            mapping(bytes32 => bool) public acceptedRoots;
            mapping(bytes32 => bool) public settledCommitments;
            mapping(address => uint256) public credits;

            function settleFromSource(
                bytes32 acceptedRoot,
                bytes32 sourceCommitment,
                uint256 destinationChainId,
                bytes32 receiverDomain,
                uint64 routeId,
                uint32 adapterId,
                address recipient,
                uint256 amount,
                bytes32[] calldata proof
            ) external {
                require(acceptedRoots[acceptedRoot]);
                require(MerkleProof.verify(proof, acceptedRoot, sourceCommitment));
                require(destinationChainId == block.chainid);
                require(!settledCommitments[sourceCommitment]);
                settledCommitments[sourceCommitment] = true;
                credits[recipient] += amount;
                adapterId;
                routeId;
                receiverDomain;
            }
        }
        """
        findings = detector.scan(source)
        self.assertEqual(len(findings), 1)
        field_clause = findings[0].message.split("fields: ", 1)[1].split(".", 1)[0]
        self.assertNotIn("source commitment", field_clause)
        self.assertIn("destination chain", field_clause)
        self.assertIn("receiver domain", field_clause)
        self.assertIn("route id", field_clause)
        self.assertIn("adapter id", field_clause)

    def test_domain_bound_inline_settlement_leaf_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        contract InlineSafe {
            bytes32 public constant BRIDGE_DESTINATION_COMMITMENT_DOMAIN_FIRE37 =
                keccak256("BRIDGE_DESTINATION_COMMITMENT_DOMAIN_FIRE37");
            mapping(bytes32 => bool) public acceptedRoots;
            mapping(bytes32 => bool) public settledCommitments;
            mapping(address => uint256) public mintedCredit;

            function finalizeDestinationSettlement(
                bytes32 acceptedRoot,
                bytes32 sourceCommitment,
                uint256 destinationChainId,
                bytes32 receiverDomain,
                uint64 routeId,
                uint32 adapterId,
                address recipient,
                uint256 amount,
                bytes calldata payload,
                bytes32[] calldata settlementProof
            ) external {
                require(acceptedRoots[acceptedRoot]);
                bytes32 settlementLeaf = keccak256(abi.encode(
                    BRIDGE_DESTINATION_COMMITMENT_DOMAIN_FIRE37,
                    sourceCommitment,
                    destinationChainId,
                    receiverDomain,
                    routeId,
                    adapterId,
                    address(this),
                    recipient,
                    amount,
                    keccak256(payload)
                ));
                require(MerkleProof.verify(settlementProof, acceptedRoot, settlementLeaf));
                require(!settledCommitments[sourceCommitment]);
                settledCommitments[sourceCommitment] = true;
                mintedCredit[recipient] += amount;
            }
        }
        """
        self.assertEqual(detector.scan(source), [])

    def test_trusted_canonical_endpoint_path_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        contract EndpointReceiver {
            mapping(bytes32 => bool) public settledCommitments;
            mapping(address => uint256) public mintedCredit;
            address public endpoint;

            modifier onlyEndpoint() {
                require(msg.sender == endpoint);
                _;
            }

            function executeDestinationMessage(
                bytes32 sourceCommitment,
                uint256 destinationChainId,
                bytes32 receiverDomain,
                uint64 routeId,
                uint32 adapterId,
                address recipient,
                uint256 amount
            ) external onlyEndpoint {
                require(destinationChainId == block.chainid);
                require(!settledCommitments[sourceCommitment]);
                settledCommitments[sourceCommitment] = true;
                mintedCredit[recipient] += amount;
                routeId;
                adapterId;
                receiverDomain;
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
