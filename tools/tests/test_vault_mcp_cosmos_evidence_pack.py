"""Tests for the Cosmos evidence-pack MCP summary callable."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "vault-mcp-server.py"


def _load_vault_module() -> Any:
    spec = importlib.util.spec_from_file_location("vault_mcp_cosmos_evidence_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_vault_module()


def _marker(event: str, **fields: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "auditooor.cosmos_production_harness_runtime_event.v1",
        "event": event,
    }
    payload.update(fields)
    return payload


def _write_exec_record(root: Path, *, complete: bool = True) -> Path:
    stdout = root / "stdout.log"
    stderr = root / "stderr.log"
    stdout.write_text("raw stdout body must not be returned\n", encoding="utf-8")
    stderr.write_text("raw stderr body must not be returned\n", encoding="utf-8")
    events = [
        _marker(
            "app_profile",
            db_backend="GoLevelDB",
            data_dir=str(root / "db"),
            private_state_injection=False,
        ),
        _marker("block_execution", height=7, finalize_block=True, commit=True, app_hash="abc"),
        _marker("restart_check", restarted=True, same_data_dir=True, post_restart_assertion="state survived"),
        _marker("impact_assertion", assertion="candidate invariant", observed="violated"),
    ]
    if not complete:
        events = [event for event in events if event["event"] != "restart_check"]
    required_events = ["app_profile", "block_execution", "restart_check", "impact_assertion"]
    events_path = root / "runtime_observation_events.json"
    events_path.write_text(
        json.dumps(
            {
                "schema": "auditooor.cosmos_production_harness_runtime_events.v1",
                "events": events,
                "required_events": required_events,
                "missing_events": [] if complete else ["restart_check"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    record = {
        "schema": "auditooor.cosmos_production_harness_exec.v1",
        "candidate_id": "lead-runtime",
        "workspace": str(root),
        "workspace_commit": "abc123",
        "runtime_proof_claimed": False,
        "preflight": {"phase_a_ready": True, "execution_allowed": True},
        "execution": {
            "status": "pass",
            "command": "go test ./... -run TestRuntime -count=1",
            "cwd": str(root),
            "stdout_path": str(stdout),
            "stderr_path": str(stderr),
        },
        "runtime_observation_guard": {
            "status": "pass" if complete else "fail",
            "required_events": required_events,
            "events_path": str(events_path),
        },
    }
    record_path = root / "cosmos_production_harness_exec.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record_path


class VaultCosmosEvidencePackContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-cosmos-evidence-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, ROOT)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_complete_exec_record_returns_bounded_summary(self) -> None:
        record_path = _write_exec_record(self.root)
        result = self.vault.vault_cosmos_evidence_pack_context(
            exec_record_path=str(record_path),
            limit=3,
        )

        self.assertEqual(result["schema"], vault_mcp_server.COSMOS_EVIDENCE_PACK_CONTEXT_SCHEMA)
        self.assertTrue(result["context_pack_id"].startswith(vault_mcp_server.COSMOS_EVIDENCE_PACK_CONTEXT_SCHEMA))
        self.assertFalse(result["degraded"])
        self.assertEqual(result["verdict"], "complete_runtime_marker_pack")
        self.assertEqual(result["builder_exit_code"], 0)
        self.assertEqual(result["summary"]["triager_rows_total"], 8)
        self.assertEqual(result["summary"]["triager_rows_returned"], 3)
        self.assertEqual(result["summary"]["pass_count"], 7)
        self.assertEqual(result["summary"]["not_applicable_count"], 1)
        self.assertTrue(result["privacy_guards"]["raw_stdout_stderr_not_returned"])
        self.assertEqual(result["triager_rows"][0]["id"], "real_backend")

        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("raw stdout body", encoded)
        self.assertNotIn("raw stderr body", encoded)

    def test_incomplete_exec_record_surfaces_failed_rows(self) -> None:
        record_path = _write_exec_record(self.root, complete=False)
        result = self.vault.call(
            "vault_cosmos_evidence_pack_context",
            {"exec_record_path": str(record_path), "limit": 12},
        )

        self.assertEqual(result["verdict"], "incomplete")
        self.assertEqual(result["builder_exit_code"], 1)
        self.assertIn("restart_behavior", result["failed_required_rows"])
        self.assertIn("runtime_guard", result["failed_required_rows"])
        self.assertGreaterEqual(result["summary"]["missing_count"], 2)

    def test_missing_exec_record_degrades(self) -> None:
        result = self.vault.vault_cosmos_evidence_pack_context(
            exec_record_path=str(self.root / "missing.json")
        )

        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "exec_record_not_found")
        self.assertEqual(result["triager_rows"], [])

    def test_tool_schema_lists_callable(self) -> None:
        tools = vault_mcp_server.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )["result"]["tools"]

        names = {tool["name"] for tool in tools}
        self.assertIn("vault_cosmos_evidence_pack_context", names)


if __name__ == "__main__":
    unittest.main()
