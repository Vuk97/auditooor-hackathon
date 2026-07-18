from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
EXPECTED_SCHEMA = "auditooor.vault_poc_execution_record_context.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_poc_execution_record_context",
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


def _manifest(
    workspace: Path,
    candidate_id: str,
    *,
    final_result: str,
    impact_assertion: str,
    evidence_class: str,
    commands_attempted: object | None = None,
) -> dict[str, object]:
    if commands_attempted is None:
        commands_attempted = [
            {
                "command": "forge test --match-test testExploitImpact",
                "cwd": str(workspace),
                "exit_code": 0 if final_result == "proved" else 1,
                "status": "pass" if final_result == "proved" else "fail",
                "stdout_path": str(workspace / "poc_execution" / candidate_id / "command_001.stdout.log"),
                "stderr_path": str(workspace / "poc_execution" / candidate_id / "command_001.stderr.log"),
            }
        ]
    return {
        "schema_version": "auditooor.poc_execution_manifest.v1",
        "candidate_id": candidate_id,
        "workspace": str(workspace),
        "brief_path": str(workspace / "source_mining" / "run" / "poc_task_briefs" / f"{candidate_id}.md"),
        "proof_task_id": "POQ-001",
        "detector_slug": "withdraw-reentrancy-no-guard",
        "detector_obligation": "P-001",
        "detector_action_graph": ".auditooor/detector_action_graphs/hit_000_withdraw.json",
        "detector_action_graph_sha256": "def456",
        "commands_attempted": commands_attempted,
        "artifact_paths": [
            str(workspace / "poc_execution" / candidate_id / "command_001.stdout.log"),
            "/Users/wolf/private/source-file.sol",
            "/private/tmp/secret-output.log",
        ],
        "impact_assertion": impact_assertion,
        "final_result": final_result,
        "evidence_class": evidence_class,
    }


class VaultPocExecutionRecordContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-poc-exec-record-context-")
        self.base = Path(self.tmp.name)
        self.vault_dir = self.base / "vault"
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        self.vault_dir.mkdir()
        self.repo.mkdir()
        self.ws.mkdir()
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(self.vault_dir, repo_root=self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_reads_workspace_local_records_scrubs_paths_and_fails_closed_without_proved_impact(self) -> None:
        # Only workspace-local manifests should be considered.
        _write_json(
            self.ws / "poc_execution" / "case-blocked" / "execution_manifest.json",
            _manifest(
                self.ws,
                "case-blocked",
                final_result="blocked_path",
                impact_assertion="not_demonstrated",
                evidence_class="executed_with_manifest",
            ),
        )
        _write_json(
            self.ws / "poc_execution" / "case-setup-only" / "execution_manifest.json",
            _manifest(
                self.ws,
                "case-setup-only",
                final_result="proved",
                impact_assertion="setup_or_branch_only",
                evidence_class="executed_with_manifest",
            ),
        )
        # Out-of-workspace manifest must be ignored even if it is "proved".
        other_ws = self.base / "other-workspace"
        other_ws.mkdir()
        _write_json(
            other_ws / "poc_execution" / "case-foreign" / "execution_manifest.json",
            _manifest(
                other_ws,
                "case-foreign",
                final_result="proved",
                impact_assertion="exploit_impact",
                evidence_class="executed_with_manifest",
            ),
        )

        self.assertTrue(
            hasattr(self.vault, "vault_poc_execution_record_context"),
            "VaultQuery must expose vault_poc_execution_record_context",
        )
        result = self.vault.vault_poc_execution_record_context(
            workspace_path=str(self.ws),
            limit=8,
        )

        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["kind"], "poc_execution_record_context")
        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(result["promotion_allowed"])
        self.assertEqual(result["summary"]["records_returned"], 2)
        self.assertEqual(result["summary"]["proved_exploit_impact_count"], 0)
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual(result["records"][0]["proof_task_id"], "POQ-001")
        self.assertEqual(result["records"][0]["detector_slug"], "withdraw-reentrancy-no-guard")
        self.assertEqual(result["records"][0]["detector_obligation"], "P-001")
        self.assertEqual(
            result["records"][0]["detector_action_graph"],
            ".auditooor/detector_action_graphs/hit_000_withdraw.json",
        )
        self.assertTrue(result["privacy_guards"]["workspace_relative_refs_only"])
        self.assertTrue(result["privacy_guards"]["absolute_local_paths_blocked"])
        self.assertTrue(result["context_pack_id"].startswith(EXPECTED_SCHEMA))
        self.assertRegex(result["context_pack_hash"], r"^[0-9a-f]{64}$")

        payload = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn(str(self.ws), payload)
        self.assertNotIn("/Users/", payload)
        self.assertNotIn("/private/", payload)
        self.assertNotEqual(result["submission_posture"], "SUBMIT_READY")

    def test_proved_exploit_manifest_with_structured_pass_exit_zero_counts_as_proof(self) -> None:
        _write_json(
            self.ws / "poc_execution" / "case-proved" / "execution_manifest.json",
            _manifest(
                self.ws,
                "case-proved",
                final_result="proved",
                impact_assertion="exploit_impact",
                evidence_class="executed_with_manifest",
            ),
        )

        result = self.vault.vault_poc_execution_record_context(
            workspace_path=str(self.ws),
            proof_only=True,
        )

        self.assertEqual(result["summary"]["records_returned"], 1)
        self.assertEqual(result["summary"]["proved_exploit_impact_count"], 1)
        self.assertEqual(result["summary"]["proof_status_counts"]["proved_impact_evidence"], 1)
        record = result["records"][0]
        self.assertEqual(record["proof_status"], "proved_impact_evidence")
        self.assertTrue(record["proof_counted"])
        self.assertEqual(record["command_status_counts"], {"pass": 1})
        self.assertEqual(record["structured_command_count"], 1)
        self.assertEqual(record["passing_command_count"], 1)
        self.assertNotIn("proof_blockers", record)

    def test_proved_exploit_manifest_with_string_exit_zero_counts_as_proof(self) -> None:
        _write_json(
            self.ws / "poc_execution" / "case-string-zero" / "execution_manifest.json",
            _manifest(
                self.ws,
                "case-string-zero",
                final_result="proved",
                impact_assertion="exploit_impact",
                evidence_class="executed_with_manifest",
                commands_attempted=[
                    {
                        "command": "forge test --match-test testExploitImpact",
                        "cwd": str(self.ws),
                        "exit_code": "0",
                        "status": "pass",
                    }
                ],
            ),
        )

        result = self.vault.vault_poc_execution_record_context(
            workspace_path=str(self.ws),
            proof_only=True,
        )

        self.assertEqual(result["summary"]["records_returned"], 1)
        self.assertEqual(result["records"][0]["passing_command_count"], 1)
        self.assertTrue(result["records"][0]["proof_counted"])

    def test_proved_exploit_manifest_with_legacy_command_string_is_not_counted_as_proof(self) -> None:
        _write_json(
            self.ws / "poc_execution" / "case-legacy-command" / "execution_manifest.json",
            _manifest(
                self.ws,
                "case-legacy-command",
                final_result="proved",
                impact_assertion="exploit_impact",
                evidence_class="executed_with_manifest",
                commands_attempted=["forge test --match-test testExploitImpact"],
            ),
        )

        result = self.vault.vault_poc_execution_record_context(workspace_path=str(self.ws))

        self.assertEqual(result["summary"]["proved_exploit_impact_count"], 0)
        record = result["records"][0]
        self.assertEqual(record["commands"][0]["status"], "legacy_recorded_command")
        self.assertEqual(record["proof_status"], "claimed_proved_missing_execution_evidence")
        self.assertFalse(record["proof_counted"])
        self.assertEqual(record["structured_command_count"], 0)
        self.assertEqual(record["passing_command_count"], 0)
        self.assertIn("commands_attempted_structured", record["proof_blockers"])
        self.assertIn("commands_attempted_pass_exit_0", record["proof_blockers"])

        proof_only = self.vault.vault_poc_execution_record_context(
            workspace_path=str(self.ws),
            proof_only=True,
        )
        self.assertEqual(proof_only["summary"]["records_returned"], 0)

    def test_proved_exploit_manifest_with_structured_failed_command_is_not_counted_as_proof(self) -> None:
        _write_json(
            self.ws / "poc_execution" / "case-failed-command" / "execution_manifest.json",
            _manifest(
                self.ws,
                "case-failed-command",
                final_result="proved",
                impact_assertion="exploit_impact",
                evidence_class="executed_with_manifest",
                commands_attempted=[
                    {
                        "command": "forge test --match-test testExploitImpact",
                        "cwd": str(self.ws),
                        "exit_code": 1,
                        "status": "fail",
                    }
                ],
            ),
        )

        result = self.vault.vault_poc_execution_record_context(workspace_path=str(self.ws))

        self.assertEqual(result["summary"]["proved_exploit_impact_count"], 0)
        record = result["records"][0]
        self.assertEqual(record["command_status_counts"], {"fail": 1})
        self.assertEqual(record["proof_status"], "claimed_proved_missing_execution_evidence")
        self.assertFalse(record["proof_counted"])
        self.assertEqual(record["structured_command_count"], 1)
        self.assertEqual(record["passing_command_count"], 0)
        self.assertIn("commands_attempted_pass_exit_0", record["proof_blockers"])

    def test_proved_exploit_manifest_with_noncanonical_evidence_class_is_not_counted_as_proof(self) -> None:
        _write_json(
            self.ws / "poc_execution" / "case-recorded-only" / "execution_manifest.json",
            _manifest(
                self.ws,
                "case-recorded-only",
                final_result="proved",
                impact_assertion="exploit_impact",
                evidence_class="recorded_without_execution",
            ),
        )

        result = self.vault.vault_poc_execution_record_context(workspace_path=str(self.ws))

        self.assertEqual(result["summary"]["proved_exploit_impact_count"], 0)
        record = result["records"][0]
        self.assertEqual(record["proof_status"], "claimed_proved_missing_execution_evidence")
        self.assertFalse(record["proof_counted"])
        self.assertIn("evidence_class_not_executed_with_manifest", record["proof_blockers"])

    def test_duplicate_explicit_proof_task_linkage_blocks_strict_proof_counting(self) -> None:
        first = _manifest(
            self.ws,
            "case-one",
            final_result="proved",
            impact_assertion="exploit_impact",
            evidence_class="executed_with_manifest",
        )
        second = _manifest(
            self.ws,
            "case-two",
            final_result="proved",
            impact_assertion="exploit_impact",
            evidence_class="executed_with_manifest",
        )
        first["proof_task_id"] = "POQ-DUPLICATE"
        second["proof_task_id"] = "POQ-DUPLICATE"
        first["detector_obligation"] = "P-DUPLICATE"
        second["detector_obligation"] = "P-DUPLICATE"
        _write_json(self.ws / "poc_execution" / "case-one" / "execution_manifest.json", first)
        _write_json(self.ws / "poc_execution" / "case-two" / "execution_manifest.json", second)

        result = self.vault.vault_poc_execution_record_context(workspace_path=str(self.ws))

        self.assertEqual(result["summary"]["records_returned"], 2)
        self.assertEqual(result["summary"]["proved_exploit_impact_count"], 0)
        for record in result["records"]:
            self.assertEqual(record["proof_status"], "claimed_proved_missing_execution_evidence")
            self.assertFalse(record["proof_counted"])
            self.assertIn("ambiguous_proof_task_manifest_linkage", record["proof_blockers"])
            self.assertIn("ambiguous_detector_obligation_manifest_linkage", record["proof_blockers"])

        proof_only = self.vault.vault_poc_execution_record_context(
            workspace_path=str(self.ws),
            proof_only=True,
        )
        self.assertEqual(proof_only["summary"]["records_returned"], 0)

    def test_missing_workspace_or_missing_records_is_degraded_and_not_submit_ready(self) -> None:
        self.assertTrue(
            hasattr(self.vault, "vault_poc_execution_record_context"),
            "VaultQuery must expose vault_poc_execution_record_context",
        )

        missing_workspace = self.vault.vault_poc_execution_record_context(
            workspace_path=str(self.base / "missing-workspace"),
        )
        self.assertEqual(missing_workspace["schema"], EXPECTED_SCHEMA)
        self.assertTrue(missing_workspace["degraded"])
        self.assertTrue(missing_workspace["advisory_only"])
        self.assertEqual(missing_workspace["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(missing_workspace["promotion_allowed"])
        self.assertEqual(missing_workspace["records"], [])
        self.assertNotIn(str(self.base), json.dumps(missing_workspace, sort_keys=True))

        missing_records = self.vault.vault_poc_execution_record_context(workspace_path=str(self.ws))
        self.assertEqual(missing_records["schema"], EXPECTED_SCHEMA)
        self.assertTrue(missing_records["degraded"])
        self.assertTrue(missing_records["advisory_only"])
        self.assertEqual(missing_records["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(missing_records["promotion_allowed"])
        self.assertEqual(missing_records["records"], [])
        self.assertNotIn(str(self.base), json.dumps(missing_records, sort_keys=True))

    def test_tools_list_and_call_register_poc_execution_record_context(self) -> None:
        _write_json(
            self.ws / "poc_execution" / "case-proved" / "execution_manifest.json",
            _manifest(
                self.ws,
                "case-proved",
                final_result="proved",
                impact_assertion="exploit_impact",
                evidence_class="executed_with_manifest",
            ),
        )

        listed = self.vault_mcp.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        by_name = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertIn(
            "vault_poc_execution_record_context",
            by_name,
            "vault_poc_execution_record_context missing from tools/list",
        )
        props = by_name["vault_poc_execution_record_context"]["inputSchema"]["properties"]
        self.assertIn("workspace_path", props)
        self.assertIn("limit", props)

        response = self.vault_mcp.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "vault_poc_execution_record_context",
                    "arguments": {"workspace_path": str(self.ws), "limit": 4},
                },
            },
        )
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["schema"], EXPECTED_SCHEMA)
        self.assertTrue(payload["advisory_only"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])
        self.assertNotIn(str(self.base), json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
