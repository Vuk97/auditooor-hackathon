from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_message_domain_binding_fire28.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_message_domain_binding_fire28.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_message_domain_binding_fire28.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-message-domain-binding-fire28"


def _load_detector():
    module_name = "bridge_message_domain_binding_fire28"
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


class BridgeMessageDomainBindingFire28Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("bridge-proof-domain-bypass", detector_text)
        self.assertIn("bridge_proof_domain.json", detector_text)
        self.assertIn("bridge-receiver-domain-omitted-from-proof-digest", detector_text)
        self.assertIn("halborn-crosschain-bridge-message-not-chainscoped", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("source chain, destination chain, remote sender, and receiver", detector_text)

        self.assertIn("function receiveBridgeMessage(", positive_text)
        self.assertIn("sourceChainId", positive_text)
        self.assertIn("destinationChainId", positive_text)
        self.assertIn("sourceSender", positive_text)
        self.assertIn("receiver", positive_text)
        self.assertIn("keccak256(abi.encode(nonce, root, keccak256(payload)))", positive_text)
        self.assertNotIn("msg.sender == endpoint", positive_text)
        self.assertNotIn("trustedRemotes[sourceChainId][remoteSender]", positive_text)

        self.assertIn("require(msg.sender == endpoint", negative_text)
        self.assertIn("trustedRemotes[sourceChainId][remoteSender]", negative_text)
        self.assertIn("destinationChainId == uint32(block.chainid)", negative_text)
        self.assertIn("trustedReceivers[receiver]", negative_text)
        self.assertIn("BRIDGE_MESSAGE_DOMAIN", negative_text)
        self.assertIn("sourceChainId", negative_text)
        self.assertIn("destinationChainId", negative_text)
        self.assertIn("remoteSender", negative_text)
        self.assertIn("receiver", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 1)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual({finding.function for finding in positive_findings}, {"receiveBridgeMessage"})

        message = positive_findings[0].message
        self.assertIn("verified or replay digest omits", message)
        self.assertIn("source chain", message)
        self.assertIn("destination chain", message)
        self.assertIn("remote sender", message)
        self.assertIn("receiver", message)
        self.assertIn("trusted remote sender", message)
        self.assertIn("NOT_SUBMIT_READY", message)

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire28_bridge_message_domain_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            for fixture, manifest in ((POSITIVE, positive_manifest), (NEGATIVE, negative_manifest)):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(RUNNER),
                        str(fixture),
                        "--workspace",
                        tmp,
                        "--output",
                        str(manifest),
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
                self.assertEqual(proc.returncode, 0, proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 1)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])

    def test_runner_stdout_count_matches_fixture_expectation(self) -> None:
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
