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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_bypass_fire22.py"
POSITIVE = REPO / "detectors" / "test_fixtures" / "positive" / "admin_bypass_fire22.sol"
NEGATIVE = REPO / "detectors" / "test_fixtures" / "negative" / "admin_bypass_fire22.sol"
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-bypass-fire22"


def _load_detector():
    module_name = "admin_bypass_fire22"
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


class AdminBypassFire22Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("governance-only state mutation", detector_text)
        self.assertIn("Fire21", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("vault_cross_language_pattern_lift", detector_text)

        self.assertIn("function updateImpact(uint256 serviceId, uint256 newImpact) external", positive_text)
        self.assertIn("impactByService[serviceId] = newImpact;", positive_text)
        self.assertIn("function mintServiceNft(address receiver, uint256 serviceId) public", positive_text)
        self.assertIn("serviceMinted[serviceId] = true;", positive_text)
        self.assertIn("protocolParams[key] = value;", positive_text)
        self.assertIn("emissionRate = newEmissionRate;", positive_text)
        self.assertIn("governanceWeight[account] = weight;", positive_text)

        self.assertIn("external onlyGovernance", negative_text)
        self.assertIn("require(msg.sender == governance", negative_text)
        self.assertIn("hasRole(GOVERNANCE_ROLE, msg.sender)", negative_text)
        self.assertIn("external view returns", negative_text)
        self.assertIn("userImpact[msg.sender] = selfScore;", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 5)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {
                "updateImpact",
                "mintServiceNft",
                "setProtocolParam",
                "adjustEmission",
                "setGovernanceWeight",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("governance-only state mutation", messages)
        self.assertIn("authority guard", messages)

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire22_admin_bypass_") as tmp:
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

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 5)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual({Path(row["file"]).name for row in positive_data["findings"]}, {POSITIVE.name})
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
