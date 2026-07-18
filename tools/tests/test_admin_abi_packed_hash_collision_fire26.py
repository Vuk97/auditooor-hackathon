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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_abi_packed_hash_collision_fire26.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "admin_abi_packed_hash_collision_fire26.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "admin_abi_packed_hash_collision_fire26.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-abi-packed-hash-collision-fire26"


def _load_detector():
    module_name = "admin_abi_packed_hash_collision_fire26"
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


class AdminAbiPackedHashCollisionFire26Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("abi-encode-packed-hash-collision", detector_text)
        self.assertIn("admin-bypass", detector_text)
        self.assertIn("admin-hash-domain-missing-fire25", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("keccak256(abi.encodePacked(actionName, adminPath, payload))", positive_text)
        self.assertIn("ECDSA.recover(adminHash, signature)", positive_text)
        self.assertIn("require(adminSigners[signer]", positive_text)
        self.assertIn("admins[newAdmin] = true;", positive_text)
        self.assertIn("roles[role] = true;", positive_text)
        self.assertIn("target = targetContract;", positive_text)

        self.assertIn("abi.encode(", negative_text)
        self.assertIn("ADMIN_MUTATION_TYPEHASH", negative_text)
        self.assertIn("block.chainid", negative_text)
        self.assertIn("address(this)", negative_text)
        self.assertIn("targetContract", negative_text)
        self.assertIn("functionSelector", negative_text)
        self.assertIn("role", negative_text)
        self.assertIn("nonce", negative_text)
        self.assertIn("keccak256(bytes(actionName))", negative_text)
        self.assertIn("keccak256(adminPath)", negative_text)
        self.assertIn("keccak256(payload)", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 1)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"executePackedAdminMutation"},
        )

        message = positive_findings[0].message
        self.assertIn("abi.encodePacked with multiple ambiguous field", message)
        self.assertIn("actionName", message)
        self.assertIn("adminPath", message)
        self.assertIn("payload", message)
        self.assertIn("chain id", message)
        self.assertIn("contract address", message)
        self.assertIn("nonce", message)
        self.assertIn("selector", message)
        self.assertIn("role", message)
        self.assertIn("target", message)

    def test_single_dynamic_domain_gap_does_not_fire(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        library ECDSA {
            function recover(bytes32 digest, bytes calldata) internal pure returns (address) {
                return address(uint160(uint256(digest)));
            }
        }
        contract SingleDynamicAdminDigest {
            mapping(address => bool) public adminSigners;
            mapping(address => bool) public admins;
            function grant(bytes calldata payload, address newAdmin, bytes calldata signature) external {
                bytes32 adminHash = keccak256(abi.encodePacked(payload, newAdmin));
                address signer = ECDSA.recover(adminHash, signature);
                require(adminSigners[signer], "bad signer");
                admins[newAdmin] = true;
            }
        }
        """
        self.assertEqual(detector.scan(source, "SingleDynamicAdminDigest.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire26_admin_packed_") as tmp:
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
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
