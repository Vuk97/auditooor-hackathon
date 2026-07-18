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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_external_authority_fire34.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_external_authority_fire34.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_external_authority_fire34.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-external-authority-fire34"


def _load_detector():
    module_name = "admin_external_authority_fire34"
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


class AdminExternalAuthorityFire34Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("admin-bypass-wrong-domain-or-missing-guard.yaml", detector_text)
        self.assertIn("admin-bypass-umbrella.yaml", detector_text)
        self.assertIn("self-admin-grant-privilege-escalation.yaml", detector_text)
        self.assertIn("external authority guard", detector_text)
        self.assertIn("not a generic missing-onlyOwner detector", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("accountLimits[account] = newLimit;", positive_text)
        self.assertIn("routeAdapters[routeId] = adapter;", positive_text)
        self.assertIn("poolOracles[poolId] = oracle;", positive_text)
        self.assertIn("trustedFactories[msg.sender]", positive_text)
        self.assertIn("routeOperators[routeId][operator] = allowed;", positive_text)

        self.assertIn("external onlyOwner", negative_text)
        self.assertIn("routerPermission[account][msg.sender]", negative_text)
        self.assertIn("routeBridge[routeId] == msg.sender", negative_text)
        self.assertIn("isAuthorized(msg.sender, poolId)", negative_text)
        self.assertIn("factoryPermission[routeId][msg.sender]", negative_text)
        self.assertIn("routerLimits[msg.sender] = newLimit;", negative_text)

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
                "routeSetAccountLimit",
                "bridgeSetRouteAdapter",
                "authoritySetPoolOracle",
                "factoryGrantRouteOperator",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("external authority guard authenticates msg.sender", messages)
        self.assertIn("does not bind that caller to the modified resource", messages)
        self.assertIn("routeId", messages)
        self.assertIn("account", messages)
        self.assertIn("poolId", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_generic_missing_owner_without_external_authority_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract GenericMissingOwner {
            mapping(address => uint256) public accountLimits;
            function setAccountLimit(address account, uint256 newLimit) external {
                accountLimits[account] = newLimit;
            }
        }
        """
        self.assertEqual(detector.scan(source, "GenericMissingOwner.sol"), [])

    def test_resource_bound_external_authority_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract BoundExternalAuthority {
            address public router;
            mapping(address => mapping(address => bool)) public routerPermission;
            mapping(address => uint256) public accountLimits;
            modifier onlyRouter() { require(msg.sender == router, "router"); _; }
            function setAccountLimit(address account, uint256 newLimit) external onlyRouter {
                require(routerPermission[account][msg.sender], "account router");
                accountLimits[account] = newLimit;
            }
        }
        """
        self.assertEqual(detector.scan(source, "BoundExternalAuthority.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire34_admin_external_authority_") as tmp:
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
