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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_bypass_domain_auth_fire23.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "admin_bypass_domain_auth_fire23.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "admin_bypass_domain_auth_fire23.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-bypass-domain-auth-fire23"


def _load_detector():
    module_name = "admin_bypass_domain_auth_fire23"
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


class AdminBypassDomainAuthFire23Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("abi-encode-packed-hash-collision", detector_text)
        self.assertIn("ccip-receiver-and-chain-unvalidated", detector_text)
        self.assertIn("load-bearing domain fields", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("keccak256(abi.encodePacked(command, salt))", positive_text)
        self.assertIn("operators[newOperator] = true;", positive_text)
        self.assertIn("roles[role] = true;", positive_text)
        self.assertIn("admin = targetContract;", positive_text)

        self.assertIn("abi.encode(", negative_text)
        self.assertIn("block.chainid", negative_text)
        self.assertIn("address(this)", negative_text)
        self.assertIn("sourceChainSelector", negative_text)
        self.assertIn("receiver", negative_text)
        self.assertIn("targetContract", negative_text)
        self.assertIn("functionSelector", negative_text)
        self.assertIn("nonceScope", negative_text)
        self.assertIn("role", negative_text)
        self.assertIn("message.sourceChainSelector == TRUSTED_SOURCE_CHAIN", negative_text)
        self.assertIn("remoteSender == TRUSTED_SENDER", negative_text)
        self.assertIn("functionSelector == this.applyCcipAdmin.selector", negative_text)

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
            {"authorizeAdmin", "_ccipReceive"},
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("signed digest domain-auth gap", messages)
        self.assertIn("cross-chain receiver domain-auth gap", messages)
        self.assertIn("target contract", messages)
        self.assertIn("function selector", messages)
        self.assertIn("role", messages)

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire23_admin_domain_auth_") as tmp:
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
            self.assertEqual({Path(row["file"]).name for row in positive_data["findings"]}, {POSITIVE.name})
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
