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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_cross_chain_receiver_unvalidated_fire39.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_cross_chain_receiver_unvalidated_fire39.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_cross_chain_receiver_unvalidated_fire39.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-cross-chain-receiver-unvalidated-fire39"


def _load_detector():
    module_name = "admin_cross_chain_receiver_unvalidated_fire39"
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


class AdminCrossChainReceiverUnvalidatedFire39Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c", detector_text)
        self.assertIn("cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8", detector_text)
        self.assertIn("R40/R76/R80 caveat", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("ccip-receiver-and-chain-unvalidated.yaml", detector_text)

        self.assertIn("require(msg.sender == ccipRouter", positive_text)
        self.assertIn("message.sourceChainSelector == TRUSTED_SOURCE_CHAIN", positive_text)
        self.assertIn("sourceSender == TRUSTED_SOURCE_SENDER", positive_text)
        self.assertIn("address receiver", positive_text)
        self.assertIn("processedMessages[messageId] = true;", positive_text)
        self.assertIn("admins[newAdmin] = true;", positive_text)
        self.assertNotIn("receiver == address(this)", positive_text)

        self.assertIn("receiver == address(this)", negative_text)
        self.assertIn("abi.encodePacked(address(this)", negative_text)
        self.assertLess(
            negative_text.index("receiver == address(this)"),
            negative_text.index("admins[newAdmin] = true;"),
        )

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 1)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual({finding.function for finding in positive_findings}, {"ccipReceive"})

        message = positive_findings[0].message
        self.assertIn("source chain", message)
        self.assertIn("source sender", message)
        self.assertIn("decoded receiver material", message)
        self.assertIn("address(this)", message)
        self.assertIn("receiver-domain digest", message)
        self.assertIn("NOT_SUBMIT_READY", message)

    def test_missing_source_auth_is_left_to_sibling_detectors(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        library Client { struct Any2EVMMessage { uint64 sourceChainSelector; bytes sender; bytes data; } }
        contract MissingSourceAuth {
            mapping(address => bool) public admins;
            address public immutable ccipRouter;
            constructor(address router) { ccipRouter = router; }
            function ccipReceive(Client.Any2EVMMessage calldata message) external {
                require(msg.sender == ccipRouter, "router only");
                (bytes32 messageType, address receiver, address newAdmin) =
                    abi.decode(message.data, (bytes32, address, address));
                require(messageType == bytes32(uint256(0xA11CE)), "type");
                admins[newAdmin] = true;
                receiver;
            }
        }
        """
        self.assertEqual(detector.scan(source, "MissingSourceAuth.sol"), [])

    def test_receiver_domain_digest_guard_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        library Client { struct Any2EVMMessage { uint64 sourceChainSelector; bytes sender; bytes data; } }
        contract ReceiverDigestGuarded {
            mapping(address => bool) public admins;
            mapping(bytes32 => bool) public approvedDigests;
            address public immutable ccipRouter;
            uint64 public constant TRUSTED_SOURCE_CHAIN = 1;
            address public constant TRUSTED_SOURCE_SENDER = address(0xBEEF);
            constructor(address router) { ccipRouter = router; }
            function ccipReceive(Client.Any2EVMMessage calldata message) external {
                require(msg.sender == ccipRouter, "router only");
                require(message.sourceChainSelector == TRUSTED_SOURCE_CHAIN, "chain");
                address sourceSender = abi.decode(message.sender, (address));
                require(sourceSender == TRUSTED_SOURCE_SENDER, "sender");
                (bytes32 messageType, address receiver, address newAdmin) =
                    abi.decode(message.data, (bytes32, address, address));
                require(messageType == bytes32(uint256(0xA11CE)), "type");
                bytes32 digest = keccak256(
                    abi.encode(address(this), message.sourceChainSelector, sourceSender, receiver, newAdmin)
                );
                require(approvedDigests[digest], "receiver domain digest");
                admins[newAdmin] = true;
            }
        }
        """
        self.assertEqual(detector.scan(source, "ReceiverDigestGuarded.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire39_admin_receiver_") as tmp:
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

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 1)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual({Path(row["file"]).name for row in positive_data["findings"]}, {POSITIVE.name})
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
