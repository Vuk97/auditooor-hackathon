from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "control-plane-ready-preflight.py"
REAL_SUBPROCESS_RUN = subprocess.run


def _load_module():
    spec = importlib.util.spec_from_file_location("control_plane_ready_preflight", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


preflight = _load_module()


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["python3"], returncode=returncode, stdout=stdout, stderr="")


def _json_stdout(payload: dict) -> str:
    return "[vault-mcp-server] callable dispatch\n" + json.dumps(payload, sort_keys=True) + "\n"


class TestControlPlaneReadyPreflight(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="control-plane-ready-")
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_manifest(self, payload: dict[str, Any]) -> Path:
        manifest_path = self.workspace / ".auditooor" / "finalization" / "current_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        return manifest_path

    def _run_with_payloads(
        self,
        brain_payload: dict,
        bridge_payload: dict,
        *,
        self_test_ok: bool = True,
    ) -> dict:
        calls: list[list[str]] = []

        def fake_run(command, **kwargs):
            calls.append(list(command))
            if command[-1] == "--self-test":
                return _completed("SELF-TEST PASS: vault MCP server\n", 0) if self_test_ok else _completed("boom\n", 1)
            if "vault_brain_prime_context" in command:
                return _completed(_json_stdout(brain_payload), 0)
            if "vault_high_impact_execution_bridge_context" in command:
                return _completed(_json_stdout(bridge_payload), 0)
            if str(REPO_ROOT / "tools" / "finalization-manifest.py") in command or "tools/finalization-manifest.py" in command:
                manifest_path = Path(command[command.index("--manifest") + 1])
                proc = REAL_SUBPROCESS_RUN(
                    ["python3", str(REPO_ROOT / "tools" / "finalization-manifest.py"), "read", "--manifest", str(manifest_path), "--json"],
                    capture_output=True,
                    text=True,
                    cwd=REPO_ROOT,
                )
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                )
            raise AssertionError(f"unexpected command: {command}")

        with patch.object(preflight.subprocess, "run", side_effect=fake_run):
            report = preflight.build_report(self.workspace, REPO_ROOT, timeout=1)
        expected_calls = 4 if (self.workspace / ".auditooor" / "finalization" / "current_manifest.json").is_file() else 3
        self.assertEqual(len(calls), expected_calls)
        return report

    def test_ready_when_self_test_brain_prime_and_bridge_are_available(self) -> None:
        report = self._run_with_payloads(
            {
                "degraded": False,
                "dispatch_ready": True,
                "receipt_found": True,
                "lanes_returned": 3,
                "context_pack_id": "brain-ctx",
                "source_refs": ["workspace:.auditooor/brain_prime_receipt.json"],
            },
            {
                "degraded": False,
                "advisory_only": True,
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "summary": {"rows_returned": 2, "runnable_harness_rows": 1},
                "context_pack_id": "bridge-ctx",
                "source_refs": ["tools/high-impact-execution-bridge.py"],
            },
        )
        self.assertEqual(report["schema"], preflight.SCHEMA)
        self.assertEqual(report["status"], "ready")
        self.assertTrue(report["dispatch_ready"])
        self.assertFalse(report["strict_mode"])
        self.assertTrue(report["strict_ready"])
        self.assertEqual(report["submission_readiness"], "NOT_SUBMIT_READY")
        self.assertEqual(report["checks"]["mcp_self_test"]["status"], "pass")
        self.assertEqual(report["checks"]["brain_prime"]["status"], "ready")
        self.assertEqual(report["checks"]["high_impact_bridge"]["status"], "available")
        self.assertEqual(report["checks"]["finalization_manifest"]["status"], "missing")
        self.assertEqual(report["proof_readiness"], "incomplete")
        self.assertEqual(report["blockers"], [])

    def test_strict_mode_requires_finalization_manifest_pass(self) -> None:
        report = self._run_with_payloads(
            {"degraded": False, "dispatch_ready": True, "receipt_found": True},
            {"degraded": False, "summary": {}},
        )
        self.assertEqual(report["status"], "ready")
        self.assertTrue(report["strict_ready"])

        calls: list[list[str]] = []

        def fake_run(command, **kwargs):
            calls.append(list(command))
            if command[-1] == "--self-test":
                return _completed("SELF-TEST PASS: vault MCP server\n", 0)
            if "vault_brain_prime_context" in command:
                return _completed(_json_stdout({"degraded": False, "dispatch_ready": True, "receipt_found": True}), 0)
            if "vault_high_impact_execution_bridge_context" in command:
                return _completed(_json_stdout({"degraded": False, "summary": {}}), 0)
            raise AssertionError(f"unexpected command: {command}")

        with patch.object(preflight.subprocess, "run", side_effect=fake_run):
            strict_report = preflight.build_report(self.workspace, REPO_ROOT, timeout=1, strict=True)
        self.assertEqual(strict_report["status"], "blocked")
        self.assertFalse(strict_report["dispatch_ready"])
        self.assertTrue(strict_report["strict_mode"])
        self.assertFalse(strict_report["strict_ready"])
        self.assertIn("finalization_manifest_missing", strict_report["blockers"])

    def test_missing_brain_prime_and_bridge_block_dispatch_without_workspace_writes(self) -> None:
        report = self._run_with_payloads(
            {
                "degraded": True,
                "degraded_reason": "receipt_not_found",
                "error": "receipt_not_found",
                "dispatch_ready": False,
                "receipt_found": False,
            },
            {
                "degraded": True,
                "degraded_reason": "high_impact_execution_bridge_json_missing",
                "error": "high_impact_execution_bridge_json_missing",
                "promotion_allowed": False,
                "submission_posture": "NOT_SUBMIT_READY",
                "summary": {"rows_returned": 0},
            },
        )
        self.assertEqual(report["status"], "degraded")
        self.assertFalse(report["dispatch_ready"])
        self.assertIn("brain_prime_missing", report["blockers"])
        self.assertIn("high_impact_bridge_missing", report["blockers"])
        self.assertEqual(report["checks"]["finalization_manifest"]["status"], "missing")
        self.assertFalse((self.workspace / ".auditooor" / "control_plane_ready_preflight.json").exists())

    def test_self_test_failure_is_a_blocker(self) -> None:
        report = self._run_with_payloads(
            {"degraded": False, "dispatch_ready": True, "receipt_found": True},
            {"degraded": False, "summary": {}},
            self_test_ok=False,
        )
        self.assertEqual(report["checks"]["mcp_self_test"]["status"], "fail")
        self.assertIn("mcp_self_test_failed", report["blockers"])
        self.assertFalse(report["dispatch_ready"])

    def test_invalid_mcp_json_degrades_check(self) -> None:
        def fake_run(command, **kwargs):
            if command[-1] == "--self-test":
                return _completed("SELF-TEST PASS: vault MCP server\n", 0)
            if "vault_brain_prime_context" in command:
                return _completed("not json\n", 0)
            if "vault_high_impact_execution_bridge_context" in command:
                return _completed(_json_stdout({"degraded": False, "summary": {}}), 0)
            raise AssertionError(f"unexpected command: {command}")

        with patch.object(preflight.subprocess, "run", side_effect=fake_run):
            report = preflight.build_report(self.workspace, REPO_ROOT, timeout=1)
        self.assertEqual(report["checks"]["brain_prime"]["status"], "degraded")
        self.assertIn("brain_prime_degraded", report["blockers"])

    def test_finalization_manifest_pass_is_visible_without_blocking_dispatch(self) -> None:
        self._write_manifest(
            {
                "schema": "auditooor.finalization_manifest.v1",
                "schema_version": 1,
                "workspace_path": str(self.workspace),
                "generated_at_utc": "2026-05-17T10:00:00Z",
                "artifact_paths": ["tools/control-plane-ready-preflight.py"],
                "handoff_or_ledger_paths": ["reports/control_plane_ready_finalization_manifest_phase_b_2026-05-17.md"],
                "agent_output_paths": ["agent_outputs/finalization_slice.md"],
                "tests_or_logs": {"commands": ["python3 -m unittest -q"], "logs": []},
                "mcp_task_update_evidence": {"mcp_paths": [".auditooor/task_update.json"]},
            }
        )
        report = self._run_with_payloads(
            {"degraded": False, "dispatch_ready": True, "receipt_found": True},
            {"degraded": False, "summary": {}},
        )
        self.assertEqual(report["status"], "ready")
        self.assertTrue(report["dispatch_ready"])
        self.assertEqual(report["checks"]["finalization_manifest"]["status"], "pass")
        self.assertEqual(report["proof_readiness"], "pass")

    def test_finalization_manifest_fail_is_visible_but_advisory(self) -> None:
        self._write_manifest(
            {
                "schema": "auditooor.finalization_manifest.v1",
                "schema_version": 1,
                "workspace_path": str(self.workspace),
                "generated_at_utc": "2026-05-17T10:00:00Z",
                "artifact_paths": ["tools/control-plane-ready-preflight.py"],
                "agent_output_paths": ["agent_outputs/finalization_slice.md"],
                "tests_or_logs": {"commands": ["python3 -m unittest -q"], "logs": []},
                "mcp_task_update_evidence": {"mcp_paths": [".auditooor/task_update.json"]},
            }
        )
        report = self._run_with_payloads(
            {"degraded": False, "dispatch_ready": True, "receipt_found": True},
            {"degraded": False, "summary": {}},
        )
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["checks"]["finalization_manifest"]["status"], "fail")
        self.assertEqual(report["checks"]["finalization_manifest"]["validation_status"], "fail")
        self.assertEqual(report["proof_readiness"], "incomplete")
        self.assertIn(
            "handoff_or_ledger_paths must be a non-empty string list",
            report["checks"]["finalization_manifest"]["errors"],
        )

    def test_cli_json_prints_envelope(self) -> None:
        report = self._run_with_payloads(
            {"degraded": False, "dispatch_ready": True, "receipt_found": True},
            {"degraded": False, "summary": {}},
        )
        text = preflight.render_text(report)
        self.assertIn("Control-plane ready Phase A: ready", text)
        self.assertIn("Dispatch ready: true", text)
        self.assertIn("Strict mode: false", text)
        self.assertIn("Finalization manifest: missing", text)

    def test_cli_strict_returns_nonzero_when_not_ready(self) -> None:
        def fake_build_report(workspace, repo_root, timeout, *, strict=False):
            return {
                "schema": preflight.SCHEMA,
                "workspace_path": str(workspace),
                "status": "blocked",
                "dispatch_ready": False,
                "strict_mode": strict,
                "strict_ready": False,
                "proof_readiness": "incomplete",
                "checks": {
                    "mcp_self_test": {"status": "pass"},
                    "brain_prime": {"status": "ready"},
                    "high_impact_bridge": {"status": "available"},
                    "finalization_manifest": {"status": "missing"},
                },
                "blockers": ["finalization_manifest_missing"],
                "next_commands": [],
            }

        with patch.object(preflight, "build_report", side_effect=fake_build_report):
            self.assertEqual(preflight.main(["--workspace", str(self.workspace)]), 0)
            self.assertEqual(preflight.main(["--workspace", str(self.workspace), "--strict"]), 1)


if __name__ == "__main__":
    unittest.main()
