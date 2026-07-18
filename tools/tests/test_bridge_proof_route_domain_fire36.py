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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_proof_route_domain_fire36.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_proof_route_domain_fire36.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_proof_route_domain_fire36.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-proof-route-domain-fire36"


def _load_detector():
    module_name = "bridge_proof_route_domain_fire36"
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


class BridgeProofRouteDomainFire36Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn('VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("bridge-proof-domain-bypass", detector_text)
        self.assertIn("bridge-proof-domain-bypass-verifier-digest-omits-domain", detector_text)
        self.assertIn("bridge-proof-domain-bypass-umbrella", detector_text)
        self.assertIn("bridge_external_replay_domain_fire34.py", detector_text)
        self.assertIn("bridge_beefy_validator_domain_fire35.py", detector_text)
        self.assertIn("route id, chain id, adapter, verifier address, or destination domain", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        for token in (
            "function submitBeefyRouteProof(",
            "routeId",
            "sourceChainId",
            "destinationChainId",
            "destinationDomain",
            "sourceAdapter",
            "destinationAdapter",
            "verifierAddress",
            "mmrRoot",
            "commitmentHash",
            "beefyRouteVerifier.verifyRouteProof(routeProofDigest, proof)",
            "processedRouteProofs[routeProofDigest] = true;",
            "IFire36RouteAdapter",
            "deliverRouteMessage(routeId, payload)",
        ):
            self.assertIn(token, positive)
            self.assertIn(token, negative)

        self.assertIn(
            "bytes32 routeProofDigest = keccak256(abi.encode(mmrRoot, commitmentHash, nonce, payloadHash));",
            positive,
        )
        self.assertNotIn("BRIDGE_PROOF_ROUTE_DOMAIN_FIRE36", positive)
        self.assertNotIn("abi.encode(\n                BRIDGE_PROOF_ROUTE_DOMAIN_FIRE36", positive)

        self.assertIn("BRIDGE_PROOF_ROUTE_DOMAIN_FIRE36", negative)
        self.assertIn("destinationChainId == block.chainid", negative)
        self.assertIn("destinationDomain == bytes32(uint256(block.chainid))", negative)
        self.assertIn("destinationAdapter == address(this)", negative)
        self.assertIn("routeId,\n                sourceChainId", negative)
        self.assertIn("destinationChainId,\n                destinationDomain", negative)
        self.assertIn("sourceAdapter,\n                destinationAdapter", negative)
        self.assertIn("address(this),\n                verifierAddress", negative)
        self.assertIn("mmrRoot,\n                commitmentHash", negative)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].severity, "High")
        self.assertEqual(positive[0].function, "submitBeefyRouteProof")

        message = positive[0].message
        self.assertIn("Bridge route proof authenticated digest omits route replay domain", message)
        self.assertIn("route id", message)
        self.assertIn("source chain id", message)
        self.assertIn("destination chain id", message)
        self.assertIn("destination domain", message)
        self.assertIn("adapter address", message)
        self.assertIn("verifier address", message)
        self.assertIn("NOT_SUBMIT_READY", message)

    def test_domain_bound_inline_route_digest_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        contract InlineClean {
            bytes32 private constant BRIDGE_PROOF_ROUTE_DOMAIN_FIRE36 = bytes32(uint256(36));
            mapping(bytes32 => bool) public processedRouteProofs;
            IFire36BeefyRouteVerifier public beefyRouteVerifier;

            function submitBeefyRouteProof(
                uint64 routeId,
                uint256 sourceChainId,
                uint256 destinationChainId,
                bytes32 destinationDomain,
                address sourceAdapter,
                address destinationAdapter,
                address verifierAddress,
                bytes32 mmrRoot,
                bytes32 commitmentHash,
                uint64 nonce,
                bytes calldata payload,
                bytes calldata proof
            ) external {
                bytes32 routeProofDigest = keccak256(abi.encode(
                    BRIDGE_PROOF_ROUTE_DOMAIN_FIRE36,
                    routeId,
                    sourceChainId,
                    destinationChainId,
                    destinationDomain,
                    sourceAdapter,
                    destinationAdapter,
                    address(this),
                    verifierAddress,
                    mmrRoot,
                    commitmentHash,
                    nonce,
                    keccak256(payload)
                ));
                require(beefyRouteVerifier.verifyRouteProof(routeProofDigest, proof));
                processedRouteProofs[routeProofDigest] = true;
                IFire36RouteAdapter(destinationAdapter).deliverRouteMessage(routeId, payload);
            }
        }
        """
        self.assertEqual(detector.scan(source), [])

    def test_route_id_bound_but_adapter_domain_omitted_still_fires(self) -> None:
        detector = _load_detector()
        source = """
        contract RouteBoundSecondaryMissing {
            IFire36BeefyRouteVerifier public beefyRouteVerifier;
            mapping(bytes32 => bool) public processedRouteProofs;

            function submitBeefyRouteProof(
                uint64 routeId,
                uint256 sourceChainId,
                uint256 destinationChainId,
                bytes32 destinationDomain,
                address destinationAdapter,
                address verifierAddress,
                bytes32 mmrRoot,
                bytes32 commitmentHash,
                uint64 nonce,
                bytes calldata payload,
                bytes calldata proof
            ) external {
                bytes32 routeProofDigest = keccak256(abi.encode(
                    routeId,
                    sourceChainId,
                    destinationChainId,
                    mmrRoot,
                    commitmentHash,
                    nonce,
                    keccak256(payload)
                ));
                require(beefyRouteVerifier.verifyRouteProof(routeProofDigest, proof));
                processedRouteProofs[routeProofDigest] = true;
                IFire36RouteAdapter(destinationAdapter).deliverRouteMessage(routeId, payload);
            }
        }
        """
        findings = detector.scan(source)
        self.assertEqual(len(findings), 1)
        self.assertIn("destination domain", findings[0].message)
        self.assertIn("adapter address", findings[0].message)
        self.assertIn("verifier address", findings[0].message)

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
