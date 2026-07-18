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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_zero_only_guard_fire35.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_zero_only_guard_fire35.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_zero_only_guard_fire35.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-zero-only-guard-fire35"


def _load_detector():
    module_name = "admin_zero_only_guard_fire35"
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


class AdminZeroOnlyGuardFire35Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("admin-bypass-wrong-domain-or-missing-guard.yaml", detector_text)
        self.assertIn("admin_external_authority_fire34.py", detector_text)
        self.assertIn("input_missing_zero_address_check.py", detector_text)
        self.assertIn("zero-address check, array length", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("require(newOracle != address(0)", positive_text)
        self.assertIn("marketRouters[market] = newRouter;", positive_text)
        self.assertIn("marketAdapters[market] = newAdapter;", positive_text)
        self.assertIn("marketFees[market] = newFeeBps;", positive_text)
        self.assertIn("routeAdapters[routeIds[i]] = adapters[i];", positive_text)
        self.assertIn("feeRecipient = newFeeRecipient;", positive_text)

        self.assertIn("external onlyOwner", negative_text)
        self.assertIn("require(msg.sender == governor", negative_text)
        self.assertIn("require(msg.sender == timelock", negative_text)
        self.assertIn("external onlyFactory", negative_text)
        self.assertIn("accessManager.canCall(msg.sender", negative_text)
        self.assertIn("notificationRecipient[msg.sender] = recipient;", negative_text)

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
                "setOracle",
                "configureMarket",
                "updateRouteAdapters",
                "updateFeeRecipient",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("weak input validation", messages)
        self.assertIn("without an effective owner, role, governance, factory, or timelock", messages)
        self.assertIn("zero-address validation", messages)
        self.assertIn("array length validation", messages)
        self.assertIn("numeric bounds validation", messages)
        self.assertIn("feeRecipient", messages)
        self.assertIn("routeAdapters", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_generic_user_preference_zero_check_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract UserPreference {
            mapping(address => address) public notificationRecipient;
            function setNotificationRecipient(address recipient) external {
                require(recipient != address(0), "zero recipient");
                notificationRecipient[msg.sender] = recipient;
            }
        }
        """
        self.assertEqual(detector.scan(source, "UserPreference.sol"), [])

    def test_effective_authorization_guard_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract GovernedOracle {
            address public governor;
            address public oracle;
            function setOracle(address newOracle) external {
                require(msg.sender == governor, "governor");
                require(newOracle != address(0), "zero oracle");
                oracle = newOracle;
            }
        }
        """
        self.assertEqual(detector.scan(source, "GovernedOracle.sol"), [])

    def test_unguarded_privileged_write_without_weak_validation_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract BroadMissingOwner {
            address public oracle;
            function setOracle(address newOracle) external {
                oracle = newOracle;
            }
        }
        """
        self.assertEqual(detector.scan(source, "BroadMissingOwner.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire35_admin_zero_only_guard_") as tmp:
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
