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
DETECTOR_PATH = (
    REPO / "detectors" / "wave17" / "operator_management_missing_access_control_fire29.py"
)
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "operator_management_missing_access_control_fire29.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "operator_management_missing_access_control_fire29.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "operator-management-missing-access-control-fire29"


def _load_detector():
    module_name = "operator_management_missing_access_control_fire29"
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


class OperatorManagementMissingAccessControlFire29Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("admin-bypass-umbrella.yaml", detector_text)
        self.assertIn("admin-bypass-wrong-domain-or-missing-guard.yaml", detector_text)
        self.assertIn("onlyowneroradministrator-allows-either-role", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("function addOperator", positive_text)
        self.assertIn('require(newOperator != address(0), "zero");', positive_text)
        self.assertIn("operators[newOperator] = true;", positive_text)
        self.assertIn("guardians[oldGuardian] = false;", positive_text)
        self.assertIn("roleAdmins[role] = newAdminRole;", positive_text)

        self.assertIn("external onlyOwner", negative_text)
        self.assertIn("public onlyRole(GUARDIAN_ADMIN_ROLE)", negative_text)
        self.assertIn("require(msg.sender == admin", negative_text)
        self.assertIn("_checkRole(RELAYER_ADMIN_ROLE, msg.sender)", negative_text)
        self.assertIn("operatorApprovals[msg.sender][operator] = approved;", negative_text)
        self.assertIn("operators[msg.sender] = true;", negative_text)
        self.assertIn("onlyOwnerOrAdministrator", negative_text)

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
                "addOperator",
                "removeRelayer",
                "rotateGuardian",
                "setExecutorManager",
                "setRoleAdmin",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("operator management function", messages)
        self.assertIn("missing owner/admin/role guard", messages)
        self.assertIn("zero-address or input-validation check", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_tx_origin_and_zero_address_checks_do_not_count_as_auth(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract BadOriginGuard {
            address public owner;
            mapping(address => bool) public signers;
            function addSigner(address signer) external {
                require(tx.origin == owner, "origin");
                require(signer != address(0), "zero");
                signers[signer] = true;
            }
        }
        """
        findings = detector.scan(source, "BadOriginGuard.sol")
        self.assertEqual({finding.function for finding in findings}, {"addSigner"})

    def test_inline_sender_bound_role_guard_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract GoodInlineGuard {
            address public owner;
            mapping(address => bool) public executors;
            mapping(address => bool) public operators;
            function setExecutor(address executor, bool enabled) external {
                require(msg.sender == owner, "owner");
                executors[executor] = enabled;
            }
            function setOperator(address operator, bool enabled) external {
                require(operators[msg.sender], "operator");
                operators[operator] = enabled;
            }
        }
        """
        self.assertEqual(detector.scan(source, "GoodInlineGuard.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire29_operator_mgmt_") as tmp:
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
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
