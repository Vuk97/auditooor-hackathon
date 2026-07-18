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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_payload_selector_bypass_fire37.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_payload_selector_bypass_fire37.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_payload_selector_bypass_fire37.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-payload-selector-bypass-fire37"


def _load_detector():
    module_name = "admin_payload_selector_bypass_fire37"
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


class AdminPayloadSelectorBypassFire37Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("post_priorities_solidity.md", detector_text)
        self.assertIn("admin-bypass-umbrella.yaml", detector_text)
        self.assertIn("admin-bypass-wrong-domain-or-missing-guard.yaml", detector_text)
        self.assertIn("admin_abi_packed_role_collision_fire36.py", detector_text)
        self.assertIn("admin_zero_only_guard_fire35.py", detector_text)
        self.assertIn("attack_class: admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("target.call(callData)", positive_text)
        self.assertIn("target.delegatecall(abi.encodeWithSelector(selector, params))", positive_text)
        self.assertIn("controller.call(", positive_text)
        self.assertIn("proxy.call(abi.encodeWithSelector(selector, newImplementation))", positive_text)

        self.assertIn("canExecute[msg.sender][target][selector]", negative_text)
        self.assertIn("accessManager.canCall(msg.sender, target, selector)", negative_text)
        self.assertIn("routeExecutors[routeId][msg.sender]", negative_text)
        self.assertIn("allowedRouteSelectors[routeId][selector]", negative_text)
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
                "executeAdminPayload",
                "dispatchRouteSelector",
                "relayRoleGrant",
                "upgradeThroughExecutor",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("generic executor authorization", messages)
        self.assertIn("target domain", messages)
        self.assertIn("selector or payload", messages)
        self.assertIn("role id", messages)
        self.assertIn("route domain", messages)
        self.assertIn("Bind executor permission to target, selector, role, route", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_plain_missing_onlyowner_setter_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract PlainMissingOwner {
            address public oracle;
            function setOracle(address newOracle) external {
                oracle = newOracle;
            }
        }
        """
        self.assertEqual(detector.scan(source, "PlainMissingOwner.sol"), [])

    def test_generic_executor_with_fully_bound_selector_and_target_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract FullyBoundExecutor {
            mapping(address => bool) public executors;
            mapping(address => mapping(address => mapping(bytes4 => bool))) public canExecute;
            modifier onlyExecutor() { require(executors[msg.sender], "executor"); _; }
            function execute(address target, bytes4 selector, bytes calldata params) external onlyExecutor {
                require(canExecute[msg.sender][target][selector], "bound");
                (bool ok,) = target.call(abi.encodeWithSelector(selector, params));
                require(ok, "call failed");
            }
        }
        """
        self.assertEqual(detector.scan(source, "FullyBoundExecutor.sol"), [])

    def test_admin_owner_guard_is_silent_even_with_raw_payload(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        contract OwnerExecutor {
            address public owner;
            function execute(address target, bytes calldata payload) external {
                require(msg.sender == owner, "owner");
                (bool ok,) = target.call(payload);
                require(ok, "call failed");
            }
        }
        """
        self.assertEqual(detector.scan(source, "OwnerExecutor.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire37_admin_payload_selector_") as tmp:
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
