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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_abi_packed_role_collision_fire36.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_abi_packed_role_collision_fire36.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_abi_packed_role_collision_fire36.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-abi-packed-role-collision-fire36"


def _load_detector():
    module_name = "admin_abi_packed_role_collision_fire36"
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


class AdminAbiPackedRoleCollisionFire36Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("abi-encode-packed-hash-collision.yaml", detector_text)
        self.assertIn("admin-bypass-umbrella.yaml", detector_text)
        self.assertIn("admin-bypass-wrong-domain-or-missing-guard.yaml", detector_text)
        self.assertIn("admin_external_authority_fire34.py", detector_text)
        self.assertIn("admin_zero_only_guard_fire35.py", detector_text)
        self.assertIn("role id, target, chain id, nonce", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("keccak256(abi.encodePacked(account, label))", positive_text)
        self.assertIn('keccak256(abi.encodePacked("EXEC", callData, signature))', positive_text)
        self.assertIn("roles[roleKey][msg.sender]", positive_text)
        self.assertIn("implementation = address", positive_text)

        self.assertIn("ADMIN_ACTION_TYPEHASH", negative_text)
        self.assertIn("abi.encode(", negative_text)
        self.assertIn("block.chainid", negative_text)
        self.assertIn("nonces[msg.sender]++", negative_text)
        self.assertIn("abi.encodePacked(role, target, address(this), block.chainid, nonce, dataHash)", negative_text)
        self.assertIn("external onlyOwner", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {
                "grantPackedRole",
                "executePackedAdmin",
                "configureAdapterByPackedRole",
                "upgradeWithPackedApproval",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("keccak256(abi.encodePacked(...))", messages)
        self.assertIn("role id or action discriminator", messages)
        self.assertIn("target or account binding", messages)
        self.assertIn("chain id or domain binding", messages)
        self.assertIn("nonce or replay guard", messages)
        self.assertIn("typed length boundaries for dynamic fields", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_plain_packed_hash_without_auth_or_admin_sink_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract UserHash {
            mapping(bytes32 => address) public aliases;
            function setAlias(bytes32 routeId, string calldata name) external {
                bytes32 key = keccak256(abi.encodePacked(routeId, name));
                aliases[key] = msg.sender;
            }
        }
        """
        self.assertEqual(detector.scan(source, "UserHash.sol"), [])

    def test_fully_bound_static_packed_transcript_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract FullyBoundPacked {
            mapping(bytes32 => mapping(address => bool)) public roles;
            mapping(address => uint256) public nonces;
            function hasRole(bytes32 role, address account) public view returns (bool) {
                return roles[role][account];
            }
            function execute(
                bytes32 role,
                address target,
                bytes32 dataHash,
                bytes calldata signature
            ) external {
                uint256 nonce = nonces[msg.sender]++;
                bytes32 digest = keccak256(
                    abi.encodePacked(role, target, address(this), block.chainid, nonce, dataHash)
                );
                address signer = recover(digest, signature);
                require(hasRole(role, signer), "role");
                target.call(abi.encodeWithSelector(bytes4(dataHash)));
            }
            function recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
                digest;
                signature;
                return address(1);
            }
        }
        """
        self.assertEqual(detector.scan(source, "FullyBoundPacked.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire36_admin_abi_packed_role_") as tmp:
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

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 4)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
