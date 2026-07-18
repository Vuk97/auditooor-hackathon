from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "initializer_address_symmetry_fire39.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "initializer_address_symmetry_fire39.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "initializer_address_symmetry_fire39.sol"
AA_SYMMETRY = REPO / "patterns" / "fixtures" / "cross-chain-aa-address-symmetry_vuln.sol"
PENDLE_ARRAY = REPO / "patterns" / "fixtures" / "fx-pendle-uninitialized-return-array_vuln.sol"
FIRE27_POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "initializer_cross_chain_account_symmetry_fire27.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "initializer-address-symmetry-fire39"


def _load_detector():
    module_name = "initializer_address_symmetry_fire39"
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


class InitializerAddressSymmetryFire39Test(unittest.TestCase):
    def test_detector_metadata_and_fixture_shape(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector_text)
        self.assertIn("attack_class: initializer-front-run", detector_text)
        self.assertIn("context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c", detector_text)
        self.assertIn("context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8", detector_text)
        self.assertIn("MCP receipt: .auditooor/memory_context_receipt.json", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("R40/R76/R80 caveat", detector_text)
        self.assertIn("_DOMAIN_OR_SYMMETRY_GUARD_RE", detector_text)
        self.assertIn("_STATE_RELOAD_OR_CONSUME_RE", detector_text)

        self.assertIn("destinationRecipient[dstEid] = addressToBytes32(msg.sender);", positive_text)
        self.assertIn("remoteAccountOf[localWallet][remoteChainId] = localWallet;", positive_text)
        self.assertIn("recipient: bytes32(uint256(uint160(msg.sender)))", positive_text)

        self.assertIn("external onlyFactory", negative_text)
        self.assertIn("dstEid == uint32(block.chainid)", negative_text)
        self.assertIn("explicitDestinationRecipient == bytes32(0)", negative_text)
        self.assertIn("localWallet == remoteWallet", negative_text)
        self.assertIn("routeCheckpoint", negative_text)
        self.assertIn("consumedRoute", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"initializeRemoteAccount", "setupRoute", "registerPeer"},
        )
        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("binds remote/destination address", messages)
        self.assertIn("address-symmetry assumption", messages)
        self.assertIn("explicit remote recipient", messages)

    def test_semantic_boundaries_stay_silent(self) -> None:
        detector = _load_detector()

        guarded_same_syntax = """
        contract GuardedRoute {
            mapping(uint32 => bytes32) public destinationRecipient;
            mapping(address => mapping(uint32 => address)) public remoteAccountOf;
            error SameChain();
            error SameAccount();
            error ZeroRecipient();

            function initializeRemoteAccount(uint32 dstEid, bytes32 explicitDestinationRecipient) external {
                if (dstEid == uint32(block.chainid)) revert SameChain();
                if (explicitDestinationRecipient == bytes32(0)) revert ZeroRecipient();
                destinationRecipient[dstEid] = explicitDestinationRecipient;
            }

            function setupRoute(address localWallet, address remoteWallet, uint32 remoteChainId) external {
                if (localWallet == remoteWallet) revert SameAccount();
                remoteAccountOf[localWallet][remoteChainId] = remoteWallet;
            }
        }
        """
        no_remote_write = """
        contract LocalInitializer {
            bool public initialized;
            address public owner;
            function initialize(address newOwner) external {
                require(!initialized, "already initialized");
                initialized = true;
                owner = newOwner;
            }
        }
        """

        self.assertEqual(detector.scan(guarded_same_syntax, "guarded.sol"), [])
        self.assertEqual(detector.scan(no_remote_write, "local.sol"), [])
        self.assertEqual(detector.scan(_read(AA_SYMMETRY), str(AA_SYMMETRY)), [])
        self.assertEqual(detector.scan(_read(PENDLE_ARRAY), str(PENDLE_ARRAY)), [])
        self.assertEqual(detector.scan(_read(FIRE27_POSITIVE), str(FIRE27_POSITIVE)), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire39_initializer_symmetry_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            positive_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(POSITIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(positive_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)

            negative_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(NEGATIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(negative_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 3)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
