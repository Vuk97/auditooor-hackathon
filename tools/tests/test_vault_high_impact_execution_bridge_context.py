from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
EXPECTED_SCHEMA = "auditooor.vault_high_impact_execution_bridge_context.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_high_impact_execution_bridge",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class VaultHighImpactExecutionBridgeContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-hi-exec-bridge-context-")
        self.base = Path(self.tmp.name)
        self.vault_dir = self.base / "vault"
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        self.vault_dir.mkdir()
        self.repo.mkdir()
        self.ws.mkdir()
        self.bridge_path = self.ws / ".auditooor" / "high_impact_execution_bridge.json"
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(self.vault_dir, repo_root=self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_bridge_payload(self) -> None:
        _write_json(
            self.bridge_path,
            {
                "schema_version": "auditooor.high_impact_execution_bridge.v1",
                "workspace": str(self.ws),
                "ledger_generated_at": "2026-05-13T00:00:00Z",
                "high_impact_missing": 2,
                "processed_rows": 2,
                "proof_boundary": (
                    "Bridge output is execution-readiness evidence only. "
                    "Scaffold attempts, handoff briefs, and next commands are not exploit proof."
                ),
                "submission_posture": "NOT_SUBMIT_READY",
                "promotion_allowed": False,
                "queue_next_commands": [
                    f"make harness-plan WS={self.ws}",
                    f"make high-impact-execution-bridge WS={self.ws}",
                ],
                "summary": {
                    "scaffold_attempts": 1,
                    "runnable_harness_rows": 1,
                    "blocked_missing_impact_contract": 1,
                    "blocked_other": 0,
                },
                "rows": [
                    {
                        "row_id": "BASE-DLT-I01",
                        "queue_item_id": "high-impact:base-dlt-withdrawals-root",
                        "harness_family": "BASE-DLT-WITHDRAWALS-ROOT",
                        "severity": "High",
                        "invariant_family": "withdrawals-root",
                        "compile_command": "cargo test -p tree withdrawals_root_rejects_divergence",
                        "proof_boundary": "readiness only, not exploit proof",
                        "impact_contract_status": "complete",
                        "bridge_status": "scaffolded_ready_for_execution_record",
                        "runnable_harness": True,
                        "attempt_status": "scaffolded_unverified",
                        "attempt_manifest": str(
                            self.ws / "poc-tests" / "base_dlt_i01" / "attempt_manifest.json"
                        ),
                        "scaffold_dir": str(self.ws / "poc-tests" / "base_dlt_i01"),
                        "handoff_brief": str(
                            self.ws
                            / ".auditooor"
                            / "high_impact_execution_bridge"
                            / "briefs"
                            / "base-dlt-i01.md"
                        ),
                        "poc_execution_record_command": (
                            f"make poc-execution-record WS={self.ws} "
                            f"BRIEF={self.ws}/.auditooor/high_impact_execution_bridge/briefs/base-dlt-i01.md "
                            "CANDIDATE_ID=base-dlt-i01 CMD='cargo test -p tree withdrawals_root_rejects_divergence' "
                            "RESULT=needs_human IMPACT=unknown"
                        ),
                        "impact_contract_command": "",
                        "impact_contract_skeleton_command": "",
                        "impact_contract_skeleton_path": "",
                    },
                    {
                        "row_id": "BASE-SC-I01",
                        "queue_item_id": "high-impact:base-sc-proof-domain",
                        "harness_family": "BASE-SC-PROOF-DOMAIN",
                        "severity": "Critical",
                        "invariant_family": "proof-domain",
                        "compile_command": "",
                        "proof_boundary": "blocked until exact impact contract exists",
                        "impact_contract_status": "missing",
                        "bridge_status": "blocked_missing_impact_contract",
                        "runnable_harness": False,
                        "attempt_status": "",
                        "attempt_manifest": "",
                        "scaffold_dir": "",
                        "handoff_brief": "",
                        "poc_execution_record_command": "",
                        "impact_contract_command": f"make impact-contract-check WS={self.ws} ROW=BASE-SC-I01",
                        "impact_contract_skeleton_command": (
                            f"make high-impact-impact-contract-skeletons WS={self.ws} ROW=BASE-SC-I01"
                        ),
                        "impact_contract_skeleton_path": str(
                            self.ws
                            / ".auditooor"
                            / "high_impact_impact_contract_skeletons"
                            / "skeletons"
                            / "base-sc-i01.json"
                        ),
                    },
                ],
            },
        )

    def test_happy_path_returns_runnable_and_blocked_rows_with_scrubbed_paths(self) -> None:
        self._write_bridge_payload()
        self.assertTrue(
            hasattr(self.vault, "vault_high_impact_execution_bridge_context"),
            "VaultQuery must expose vault_high_impact_execution_bridge_context",
        )

        result = self.vault.vault_high_impact_execution_bridge_context(
            workspace_path=str(self.ws),
            limit=4,
        )

        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["kind"], "high_impact_execution_bridge_context")
        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["claim_scope"], "execution_readiness_only")
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(result["promotion_allowed"])
        self.assertIn("not exploit proof", result["proof_boundary"])
        self.assertEqual(result["summary"]["runnable_harness_rows"], 1)
        self.assertEqual(result["summary"]["blocked_missing_impact_contract"], 1)
        self.assertEqual(len(result["rows"]), 2)
        self.assertTrue(result["context_pack_id"].startswith(EXPECTED_SCHEMA))
        self.assertTrue(result["privacy_guards"]["workspace_relative_refs_only"])
        self.assertTrue(result["privacy_guards"]["absolute_local_paths_blocked"])

        runnable = result["rows"][0]
        blocked = result["rows"][1]
        self.assertEqual(runnable["row_id"], "BASE-DLT-I01")
        self.assertTrue(runnable["runnable_harness"])
        self.assertIn("poc_execution_record_command", runnable)
        self.assertEqual(blocked["row_id"], "BASE-SC-I01")
        self.assertFalse(blocked["runnable_harness"])
        self.assertEqual(blocked["bridge_status"], "blocked_missing_impact_contract")
        self.assertEqual(blocked.get("poc_execution_record_command", ""), "")
        self.assertIn("impact-contract-check", blocked["impact_contract_command"])

        payload = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn("/private/", payload)
        self.assertNotIn("/Users/", payload)
        self.assertNotIn(str(self.ws), payload)
        self.assertNotEqual(result["submission_posture"], "SUBMIT_READY")

    def test_missing_workspace_or_bridge_file_returns_valid_not_submit_ready_envelope(self) -> None:
        self.assertTrue(
            hasattr(self.vault, "vault_high_impact_execution_bridge_context"),
            "VaultQuery must expose vault_high_impact_execution_bridge_context",
        )

        missing_workspace = self.vault.vault_high_impact_execution_bridge_context(
            workspace_path=str(self.base / "missing-workspace"),
        )
        self.assertEqual(missing_workspace["schema"], EXPECTED_SCHEMA)
        self.assertTrue(missing_workspace["degraded"])
        self.assertTrue(missing_workspace["advisory_only"])
        self.assertEqual(missing_workspace["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(missing_workspace["promotion_allowed"])
        self.assertEqual(missing_workspace["rows"], [])
        self.assertNotIn(str(self.base), json.dumps(missing_workspace, sort_keys=True))

        missing_file = self.vault.vault_high_impact_execution_bridge_context(workspace_path=str(self.ws))
        self.assertEqual(missing_file["schema"], EXPECTED_SCHEMA)
        self.assertTrue(missing_file["degraded"])
        self.assertTrue(missing_file["advisory_only"])
        self.assertEqual(missing_file["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(missing_file["promotion_allowed"])
        self.assertEqual(missing_file["rows"], [])
        self.assertIn("high_impact_execution_bridge", missing_file.get("degraded_reason", ""))
        self.assertNotIn(str(self.base), json.dumps(missing_file, sort_keys=True))

    def test_tools_list_and_call_register_high_impact_execution_bridge_context(self) -> None:
        self._write_bridge_payload()

        listed = self.vault_mcp.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        by_name = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertTrue(
            "vault_high_impact_execution_bridge_context" in by_name,
            "vault_high_impact_execution_bridge_context missing from tools/list; "
            f"registered vault tools: {sorted(by_name)}",
        )
        props = by_name["vault_high_impact_execution_bridge_context"]["inputSchema"]["properties"]
        self.assertIn("workspace_path", props)
        self.assertIn("limit", props)
        self.assertIn("bridge_path", props)

        response = self.vault_mcp.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "vault_high_impact_execution_bridge_context",
                    "arguments": {"workspace_path": str(self.ws), "limit": 1},
                },
            },
        )
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["schema"], EXPECTED_SCHEMA)
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(len(payload["rows"]), 1)
        self.assertNotIn(str(self.base), json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
