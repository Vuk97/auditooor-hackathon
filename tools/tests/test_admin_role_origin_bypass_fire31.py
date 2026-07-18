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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_role_origin_bypass_fire31.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_role_origin_bypass_fire31.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_role_origin_bypass_fire31.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-role-origin-bypass-fire31"


def _load_detector():
    module_name = "admin_role_origin_bypass_fire31"
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


class AdminRoleOriginBypassFire31Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("operator_management_missing_access_control_fire29.py", detector_text)
        self.assertIn("role_grant_divergence.yaml", detector_text)
        self.assertIn("caller-supplied owner, admin", detector_text)
        self.assertIn("tx.origin", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("require(msg.sender == suppliedOwner", positive_text)
        self.assertIn("require(hasRole(DEFAULT_ADMIN_ROLE, claimedAdmin)", positive_text)
        self.assertIn("require(tx.origin == owner", positive_text)
        self.assertIn("require(cfg.admin == owner", positive_text)
        self.assertIn("treasury = newTreasury;", positive_text)
        self.assertIn("_grantRole(EMERGENCY_ROLE, account);", positive_text)
        self.assertIn("emergencyDelay = cfg.delay;", positive_text)

        self.assertIn("external onlyOwner", negative_text)
        self.assertIn("_checkRole(DEFAULT_ADMIN_ROLE, msg.sender)", negative_text)
        self.assertIn("require(msg.sender == owner", negative_text)
        self.assertIn("require(msg.sender == governance", negative_text)
        self.assertIn("require(operators[msg.sender]", negative_text)
        self.assertIn("external onlyRole(DEFAULT_ADMIN_ROLE)", negative_text)
        self.assertIn("require(tx.origin == msg.sender", negative_text)

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
                "setTreasury",
                "grantEmergencyRole",
                "sweepTokenWithOrigin",
                "setEmergencyConfig",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("non-sender-bound authorization shape", messages)
        self.assertIn("caller-supplied authority", messages)
        self.assertIn("tx.origin authorization", messages)
        self.assertIn("real owner, admin, governance, or role guard", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_inline_real_guard_suppresses_tx_origin_noise(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract GoodMixedGuard {
            address public owner;
            address public treasury;
            function setTreasury(address newTreasury) external {
                require(msg.sender == owner, "owner");
                require(tx.origin != address(0), "origin present");
                treasury = newTreasury;
            }
        }
        """
        self.assertEqual(detector.scan(source, "GoodMixedGuard.sol"), [])

    def test_param_authority_without_privileged_effect_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract SelfService {
            mapping(address => uint256) public balances;
            function claim(address suppliedOwner, uint256 amount) external {
                require(msg.sender == suppliedOwner, "owner");
                balances[msg.sender] += amount;
            }
        }
        """
        self.assertEqual(detector.scan(source, "SelfService.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire31_admin_role_origin_") as tmp:
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
