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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_domain_authority_fire33.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_domain_authority_fire33.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_domain_authority_fire33.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-domain-authority-fire33"


def _load_detector():
    module_name = "admin_domain_authority_fire33"
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


class AdminDomainAuthorityFire33Test(unittest.TestCase):
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
        self.assertIn("caller-supplied authority contracts", detector_text)
        self.assertIn("router-only guards", detector_text)
        self.assertIn("same-sink mutation", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("IAdminDomainFire33(adminContract).isAdmin(msg.sender)", positive_text)
        self.assertIn("accountLimits[account] = newLimit;", positive_text)
        self.assertIn("roles[msg.sender][DEFAULT_ADMIN_ROLE] = true;", positive_text)
        self.assertIn("function setMarketOracle(bytes32 market, address oracle) external onlyOwner", positive_text)
        self.assertIn("function updateMarketOracle(bytes32 market, address oracle) external", positive_text)

        self.assertIn("IAdminDomainFire33Negative(governedAdminContract).isAdmin(msg.sender)", negative_text)
        self.assertIn("require(routerPermission[account][msg.sender]", negative_text)
        self.assertIn("userLimits[msg.sender] = newLimit;", negative_text)
        self.assertIn("external onlyRole(DEFAULT_ADMIN_ROLE)", negative_text)
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
                "setAdapterWithSuppliedAdmin",
                "routeSetAccountLimit",
                "grantMyselfDefaultAdmin",
                "updateMarketOracle",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("caller-supplied authority contract checks msg.sender", messages)
        self.assertIn("router-only guard not bound to controlled resource", messages)
        self.assertIn("self-admin grant or self-ownership effect", messages)
        self.assertIn("unguarded sibling mutates guarded authority sink", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_stored_authority_contract_is_not_caller_supplied(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        interface IAdmin { function isAdmin(address account) external view returns (bool); }
        contract StoredAuthority {
            address public governedAdminContract;
            mapping(bytes32 => address) public adapters;
            function setAdapter(bytes32 market, address adapter) external {
                require(IAdmin(governedAdminContract).isAdmin(msg.sender), "admin");
                adapters[market] = adapter;
            }
        }
        """
        self.assertEqual(detector.scan(source, "StoredAuthority.sol"), [])

    def test_router_resource_binding_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract BoundRouter {
            address public router;
            mapping(address => uint256) public accountLimits;
            mapping(address => mapping(address => bool)) public routerPermission;
            modifier onlyRouter() { require(msg.sender == router, "router"); _; }
            function routeSetAccountLimit(address account, uint256 newLimit) external onlyRouter {
                require(routerPermission[account][msg.sender], "account router");
                accountLimits[account] = newLimit;
            }
        }
        """
        self.assertEqual(detector.scan(source, "BoundRouter.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire33_admin_domain_") as tmp:
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
