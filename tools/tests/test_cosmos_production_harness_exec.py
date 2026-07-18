"""Tests for cosmos-production-harness-exec."""

from __future__ import annotations

import importlib.util
import json
import os
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cosmos_production_harness_exec",
    ROOT / "tools" / "cosmos-production-harness-exec.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace(go_body: str) -> tuple[Path, Path]:
    workspace = Path(tempfile.mkdtemp(prefix="cosmos_harness_exec_ws_"))
    poc = workspace / "poc-tests" / "candidate"
    poc.mkdir(parents=True, exist_ok=True)
    (poc / "poc_test.go").write_text(go_body, encoding="utf-8")
    return workspace, poc


def _ready_workspace() -> tuple[Path, Path]:
    return _workspace(
        """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestProductionPath() {
    db, _ := dbm.NewGoLevelDB("app", t.TempDir())
    app.FinalizeBlock(req)
    app.Commit()
    db.Close()
    _, _ = dbm.NewGoLevelDB("app", t.TempDir())
}
"""
    )


def _ready_network_workspace() -> tuple[Path, Path]:
    return _workspace(
        """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestProductionNetworkPath() {
    cfg := struct{ NumValidators int }{NumValidators: 2}
    _ = cfg
    network.BroadcastTxSync(tx)
    db, _ := dbm.NewGoLevelDB("app", t.TempDir())
    app.FinalizeBlock(req)
    app.Commit()
    db.Close()
    _, _ = dbm.NewGoLevelDB("app", t.TempDir())
}
"""
    )


def _not_ready_workspace() -> tuple[Path, Path]:
    return _workspace(
        """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestWeakProfile() {
    db := dbm.NewMemDB()
    _ = db
}
"""
    )


def _marker(event: str, **fields) -> str:
    payload = {"schema": mod.RUNTIME_EVENT_SCHEMA, "event": event}
    payload.update(fields)
    return mod.RUNTIME_EVENT_PREFIX + json.dumps(payload, sort_keys=True)


def _base_runtime_markers() -> list[str]:
    return [
        _marker(
            "app_profile",
            app_chain="dydx",
            db_backend="GoLevelDB",
            data_dir="/tmp/dydx-production-harness",
            private_state_injection=False,
        ),
        _marker(
            "block_execution",
            height=42,
            finalize_block=True,
            commit=True,
            app_hash="0xabc123",
        ),
        _marker(
            "restart_check",
            restarted=True,
            same_data_dir=True,
            post_restart_assertion="position state survived restart",
        ),
        _marker(
            "impact_assertion",
            assertion="candidate invariant changes through production block path",
            observed="post-block state differed from expected invariant",
        ),
    ]


def _fake_go_bin(root: Path, marker_lines: list[str] | None = None) -> Path:
    bin_dir = root / "fake-bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    go_bin = bin_dir / "go"
    marker_script = "".join(f"echo {shlex.quote(line)}\n" for line in marker_lines or [])
    go_bin.write_text(
        (
            "#!/bin/sh\n"
            "if [ \"$1\" != \"test\" ]; then\n"
            "  echo \"unexpected command\" >&2\n"
            "  exit 9\n"
            "fi\n"
            "echo \"FAKE_GO $@\"\n"
            f"{marker_script}"
            "if [ \"$FAKE_GO_FAIL\" = \"1\" ]; then\n"
            "  echo \"simulated failure\" >&2\n"
            "  exit 7\n"
            "fi\n"
            "exit 0\n"
        ),
        encoding="utf-8",
    )
    go_bin.chmod(0o755)
    return bin_dir


class CosmosProductionHarnessExecTests(unittest.TestCase):
    def test_blocks_execution_when_preflight_not_ready(self):
        workspace, poc = _not_ready_workspace()
        payload, _path, code = mod.build_record(
            workspace=workspace,
            poc_dir=poc,
            candidate_id="lead-1",
            command="go test ./... -run TestWeakProfile -count=1",
            cwd=poc,
            claim_text="single-validator state-machine proof",
            network_claim=False,
            out_json=None,
        )
        self.assertEqual(code, 1)
        self.assertFalse(payload["preflight"]["execution_allowed"])
        self.assertEqual(payload["preflight"]["phase_a_verdict"], "needs_work")
        self.assertFalse(payload["execution"]["attempted"])
        self.assertEqual(payload["execution"]["status"], "blocked_preflight")
        self.assertEqual(payload["execution"]["stdout_path"], "")
        self.assertEqual(payload["execution"]["stderr_path"], "")
        self.assertFalse(payload["runtime_proof_claimed"])
        self.assertEqual(payload["runtime_observation_guard"]["status"], "skipped")

    def test_runs_ready_fixture_with_explicit_go_test(self):
        workspace, poc = _ready_workspace()
        fake_bin = _fake_go_bin(workspace)
        env_path = str(fake_bin) + os.pathsep + os.environ.get("PATH", "")
        with mock.patch.dict(os.environ, {"PATH": env_path}, clear=False):
            payload, _path, code = mod.build_record(
                workspace=workspace,
                poc_dir=poc,
                candidate_id="lead-2",
                command="go test ./... -run TestProductionPath -count=1",
                cwd=poc,
                claim_text="single-validator state-machine proof",
                network_claim=False,
                out_json=None,
            )
        self.assertEqual(code, 0)
        self.assertTrue(payload["preflight"]["execution_allowed"])
        self.assertTrue(payload["execution"]["attempted"])
        self.assertEqual(payload["execution"]["status"], "pass")
        self.assertEqual(payload["execution"]["exit_code"], 0)
        self.assertEqual(payload["execution"]["command"], "go test ./... -run TestProductionPath -count=1")
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["runtime_proof_claimed"])
        self.assertEqual(payload["runtime_observation_guard"]["status"], "skipped")
        stdout = Path(payload["execution"]["stdout_path"])
        stderr = Path(payload["execution"]["stderr_path"])
        self.assertTrue(stdout.is_file())
        self.assertTrue(stderr.is_file())
        self.assertIn("FAKE_GO test ./... -run TestProductionPath -count=1", stdout.read_text(encoding="utf-8"))

    def test_failed_go_test_is_recorded_as_fail_not_proof(self):
        workspace, poc = _ready_workspace()
        fake_bin = _fake_go_bin(workspace)
        env_path = str(fake_bin) + os.pathsep + os.environ.get("PATH", "")
        with mock.patch.dict(os.environ, {"PATH": env_path, "FAKE_GO_FAIL": "1"}, clear=False):
            payload, _path, code = mod.build_record(
                workspace=workspace,
                poc_dir=poc,
                candidate_id="lead-3",
                command="go test ./... -run TestProductionPath -count=1",
                cwd=poc,
                claim_text="single-validator state-machine proof",
                network_claim=False,
                out_json=None,
            )
        self.assertEqual(code, 1)
        self.assertTrue(payload["execution"]["attempted"])
        self.assertEqual(payload["execution"]["status"], "fail")
        self.assertEqual(payload["execution"]["exit_code"], 7)
        self.assertFalse(payload["runtime_proof_claimed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["runtime_observation_guard"]["status"], "skipped")

    def test_runtime_marker_guard_passes_with_required_observations(self):
        workspace, poc = _ready_workspace()
        fake_bin = _fake_go_bin(workspace, marker_lines=_base_runtime_markers())
        env_path = str(fake_bin) + os.pathsep + os.environ.get("PATH", "")
        with mock.patch.dict(os.environ, {"PATH": env_path}, clear=False):
            payload, _path, code = mod.build_record(
                workspace=workspace,
                poc_dir=poc,
                candidate_id="lead-guard-pass",
                command="go test ./... -run TestProductionPath -count=1",
                cwd=poc,
                claim_text="single-validator state-machine proof",
                network_claim=False,
                require_runtime_markers=True,
                target_app_chain="dydx",
                out_json=None,
            )
        self.assertEqual(code, 0)
        guard = payload["runtime_observation_guard"]
        self.assertTrue(guard["required"])
        self.assertEqual(guard["status"], "pass")
        self.assertEqual(guard["missing_events"], [])
        self.assertEqual(guard["invalid_events"], [])
        self.assertEqual(guard["required_events"], list(mod.BASE_RUNTIME_EVENTS))
        self.assertTrue(Path(guard["events_path"]).is_file())
        self.assertFalse(payload["runtime_proof_claimed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_runtime_marker_guard_fails_passed_command_without_markers(self):
        workspace, poc = _ready_workspace()
        fake_bin = _fake_go_bin(workspace)
        env_path = str(fake_bin) + os.pathsep + os.environ.get("PATH", "")
        with mock.patch.dict(os.environ, {"PATH": env_path}, clear=False):
            payload, _path, code = mod.build_record(
                workspace=workspace,
                poc_dir=poc,
                candidate_id="lead-guard-fail",
                command="go test ./... -run TestProductionPath -count=1",
                cwd=poc,
                claim_text="single-validator state-machine proof",
                network_claim=False,
                require_runtime_markers=True,
                target_app_chain="dydx",
                out_json=None,
            )
        self.assertEqual(code, 1)
        self.assertEqual(payload["execution"]["status"], "pass")
        guard = payload["runtime_observation_guard"]
        self.assertEqual(guard["status"], "fail")
        self.assertEqual(guard["missing_events"], list(mod.BASE_RUNTIME_EVENTS))
        self.assertTrue(Path(guard["events_path"]).is_file())
        self.assertFalse(payload["runtime_proof_claimed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_network_claim_runtime_guard_requires_network_profile_marker(self):
        workspace, poc = _ready_network_workspace()
        fake_bin = _fake_go_bin(workspace, marker_lines=_base_runtime_markers())
        env_path = str(fake_bin) + os.pathsep + os.environ.get("PATH", "")
        with mock.patch.dict(os.environ, {"PATH": env_path}, clear=False):
            payload, _path, code = mod.build_record(
                workspace=workspace,
                poc_dir=poc,
                candidate_id="lead-network-guard",
                command="go test ./... -run TestProductionNetworkPath -count=1",
                cwd=poc,
                claim_text="network-level consensus halt",
                network_claim=True,
                require_runtime_markers=True,
                target_app_chain="dydx",
                out_json=None,
            )
        self.assertEqual(code, 1)
        self.assertTrue(payload["preflight"]["execution_allowed"])
        guard = payload["runtime_observation_guard"]
        self.assertEqual(guard["status"], "fail")
        self.assertIn(mod.NETWORK_RUNTIME_EVENT, guard["required_events"])
        self.assertEqual(guard["missing_events"], [mod.NETWORK_RUNTIME_EVENT])
        self.assertFalse(payload["runtime_proof_claimed"])

    def test_rejects_non_go_test_command(self):
        workspace, poc = _ready_workspace()
        with self.assertRaisesRegex(ValueError, "go test"):
            mod.build_record(
                workspace=workspace,
                poc_dir=poc,
                candidate_id="lead-4",
                command="echo nope",
                cwd=poc,
                claim_text="single-validator state-machine proof",
                network_claim=False,
                out_json=None,
            )


if __name__ == "__main__":
    unittest.main()
