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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "abi_encode_packed_dynamic_collision_fire28.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "abi_encode_packed_dynamic_collision_fire28.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "abi_encode_packed_dynamic_collision_fire28.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "abi-encode-packed-dynamic-collision-fire28"


def _load_detector():
    module_name = "abi_encode_packed_dynamic_collision_fire28"
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


class AbiEncodePackedDynamicCollisionFire28Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("abi-encode-packed-hash-collision.yaml", detector_text)
        self.assertIn("glider-hash-collision-with-abiencode-packed", detector_text)
        self.assertIn("admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("abi.encodePacked(roleNamespace, claimPayload, merkleProof)", positive_text)
        self.assertIn("keccak256(bytes.concat(sourceRoute, messagePayload, bytes(memo)))", positive_text)
        self.assertIn("ECDSA.recover(claimDigest, signature)", positive_text)
        self.assertIn("require(!claimed[claimDigest]", positive_text)
        self.assertIn("require(!bridgedMessages[bridgeDigest]", positive_text)

        self.assertIn("abi.encode(", negative_text)
        self.assertIn("keccak256(bytes(roleNamespace))", negative_text)
        self.assertIn("keccak256(claimPayload)", negative_text)
        self.assertIn("keccak256(abi.encode(merkleProof))", negative_text)
        self.assertIn("keccak256(abi.encodePacked(claimPayload, role, nonce))", negative_text)
        self.assertIn("abi.encodePacked(keccak256(bytes(roleNamespace)), keccak256(claimPayload), address(this))", " ".join(negative_text.split()))
        self.assertIn("function cosmeticPackedHash", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 2)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"claimRoleWithPackedDigest", "consumeBridgePermit"},
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("multiple dynamic field(s)", messages)
        self.assertIn("roleNamespace", messages)
        self.assertIn("claimPayload", messages)
        self.assertIn("merkleProof", messages)
        self.assertIn("sourceRoute", messages)
        self.assertIn("messagePayload", messages)
        self.assertIn("memo", messages)
        self.assertIn("auth, role, claim, permit, bridge, or signature check", messages)

    def test_inline_single_dynamic_and_prehashed_cases_do_not_fire(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        library ECDSA {
            function recover(bytes32 digest, bytes calldata) internal pure returns (address) {
                return address(uint160(uint256(digest)));
            }
        }
        contract InlineNegative {
            mapping(address => bool) public authorizedSigners;
            mapping(bytes32 => bool) public roles;

            function grant(bytes calldata payload, bytes32 role, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encodePacked(payload, role));
                address signer = ECDSA.recover(digest, signature);
                require(authorizedSigners[signer], "bad signer");
                roles[role] = true;
            }

            function grantSafe(string calldata route, bytes calldata payload, bytes calldata signature) external {
                bytes32 digest = keccak256(abi.encodePacked(keccak256(bytes(route)), keccak256(payload)));
                address signer = ECDSA.recover(digest, signature);
                require(authorizedSigners[signer], "bad signer");
                roles[digest] = true;
            }
        }
        """
        self.assertEqual(detector.scan(source, "InlineNegative.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire28_abi_packed_") as tmp:
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

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 2)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
