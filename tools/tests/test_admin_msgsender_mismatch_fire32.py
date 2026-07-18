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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_msgsender_mismatch_fire32.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_msgsender_mismatch_fire32.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_msgsender_mismatch_fire32.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-msgsender-mismatch-fire32"


def _load_detector():
    module_name = "admin_msgsender_mismatch_fire32"
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


class AdminMsgSenderMismatchFire32Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("reports/detector_lift_fire31_20260605/post_priorities_all.md", detector_text)
        self.assertIn("admin_role_origin_bypass_fire31.py", detector_text)
        self.assertIn("role_grant_divergence.yaml", detector_text)
        self.assertIn("admin-malicious-contract-injection.yaml", detector_text)
        self.assertIn("caller-supplied authority", detector_text)
        self.assertIn("sender-bound owner", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("require(hasRole(DEFAULT_ADMIN_ROLE, claimedAdmin)", positive_text)
        self.assertIn("_grantRole(OPERATOR_ROLE, msg.sender);", positive_text)
        self.assertIn("require(ticket.signer == trustedSigner", positive_text)
        self.assertIn("operators[msg.sender] = true;", positive_text)
        self.assertIn("require(suppliedOwner == owner", positive_text)
        self.assertIn("IERC20Fire32(token).transfer(", positive_text)
        self.assertIn("require(signers[suppliedPauser]", positive_text)
        self.assertIn("paused = true;", positive_text)
        self.assertIn("limits[msg.sender] = cfg.limit;", positive_text)

        self.assertIn("external onlyRole(DEFAULT_ADMIN_ROLE)", negative_text)
        self.assertIn("external onlyOwner", negative_text)
        self.assertIn("_checkRole(PAUSER_ROLE, msg.sender)", negative_text)
        self.assertIn("require(msg.sender == owner", negative_text)
        self.assertIn("userLimits[msg.sender] = amount;", negative_text)
        self.assertIn("checkedForeignSignerButNoPrivilegedEffect", negative_text)
        self.assertIn("checkedForeignSignerButExplicitRecipient", negative_text)

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
                "grantOperatorToCaller",
                "installCallerAsOperator",
                "sweepTokenToCaller",
                "pauseWithForeignPauser",
                "setCallerLimit",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("caller-supplied authority", messages)
        self.assertIn("msg.sender receives or triggers", messages)
        self.assertIn("role check applied to caller-supplied authority", messages)
        self.assertIn("authority mapping checked for caller-supplied authority", messages)
        self.assertIn("real sender-bound owner", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_sender_bound_guard_suppresses_foreign_signer_noise(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract GoodMixedGuard {
            address public owner;
            address public trustedSigner;
            mapping(address => bool) public operators;
            function install(address signer) external {
                require(signer == trustedSigner, "signer");
                require(msg.sender == owner, "owner");
                operators[msg.sender] = true;
            }
        }
        """
        self.assertEqual(detector.scan(source, "GoodMixedGuard.sol"), [])

    def test_self_service_msgsender_write_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract SelfService {
            mapping(address => uint256) public limits;
            function setLimit(uint256 amount) external {
                limits[msg.sender] = amount;
            }
        }
        """
        self.assertEqual(detector.scan(source, "SelfService.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire32_admin_msgsender_") as tmp:
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
