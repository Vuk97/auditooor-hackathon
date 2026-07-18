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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "ccip_receiver_chain_source_unvalidated_fire27.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "ccip_receiver_chain_source_unvalidated_fire27.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "ccip_receiver_chain_source_unvalidated_fire27.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "ccip-receiver-chain-source-unvalidated-fire27"


def _load_detector():
    module_name = "ccip_receiver_chain_source_unvalidated_fire27"
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


class CcipReceiverChainSourceUnvalidatedFire27Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("ccip-receiver-and-chain-unvalidated", detector_text)
        self.assertIn("cross-chain-aa-address-symmetry", detector_text)
        self.assertIn("abi-encode-packed-hash-collision", detector_text)
        self.assertIn("admin-receiver-source-domain-fire26", detector_text)
        self.assertIn("receiver contract", detector_text)
        self.assertIn("target chain", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("require(msg.sender == ccipRouter", positive_text)
        self.assertIn("message.sourceChainSelector == TRUSTED_SOURCE_CHAIN", positive_text)
        self.assertIn("sourceSender == TRUSTED_SOURCE_SENDER", positive_text)
        self.assertIn("abi.decode(message.data", positive_text)
        self.assertIn("targetChainSelector", positive_text)
        self.assertIn("receiverContract", positive_text)
        self.assertIn("remoteAdmins[targetChainSelector][receiverContract] = newAdmin;", positive_text)
        self.assertNotIn("targetChainSelector == LOCAL_TARGET_CHAIN", positive_text)
        self.assertNotIn("receiverContract == CANONICAL_RECEIVER", positive_text)

        self.assertIn("require(msg.sender == ccipRouter", negative_text)
        self.assertIn("message.sourceChainSelector == TRUSTED_SOURCE_CHAIN", negative_text)
        self.assertIn("sourceSender == TRUSTED_SOURCE_SENDER", negative_text)
        self.assertIn("targetChainSelector == LOCAL_TARGET_CHAIN", negative_text)
        self.assertIn("receiverContract == CANONICAL_RECEIVER", negative_text)
        self.assertLess(
            negative_text.index("targetChainSelector == LOCAL_TARGET_CHAIN"),
            negative_text.index("remoteAdmins[targetChainSelector][receiverContract] = newAdmin;"),
        )
        self.assertLess(
            negative_text.index("receiverContract == CANONICAL_RECEIVER"),
            negative_text.index("remoteAdmins[targetChainSelector][receiverContract] = newAdmin;"),
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
        self.assertIn("receiver and target-chain admin payload", message)
        self.assertIn("receiver contract", message)
        self.assertIn("target chain", message)
        self.assertNotIn("source chain selector", message)
        self.assertNotIn("trusted sender", message)
        self.assertNotIn("allowed router", message)

    def test_source_domain_guarded_shape_remains_fire27_specific(self) -> None:
        detector = _load_detector()
        finding = detector.scan(_read(POSITIVE), str(POSITIVE))[0]

        self.assertIn("receiver contract", finding.message)
        self.assertIn("target chain", finding.message)
        self.assertNotIn("source chain selector", finding.message)
        self.assertNotIn("trusted sender", finding.message)

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire27_ccip_receiver_chain_") as tmp:
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
