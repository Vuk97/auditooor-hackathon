"""Tests for tools/loop-finalization-check.py."""

from __future__ import annotations

import json
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "loop-finalization-check.py"


def _base_manifest() -> dict[str, object]:
    return {
        "changed_artifacts": [
            "tools/loop-finalization-check.py",
            "tools/tests/test_loop_finalization_check.py",
        ],
        "handoff_or_ledger_updated": {
            "paths": ["docs/LOOP_FINALIZATION_CHECK.md"],
            "note": "Loop finalization handoff doc updated for this slice.",
        },
        "agent_outputs_collected": {
            "paths": ["agent_outputs/loop_finalization_check_2026-05-14.md"],
        },
        "tests_or_logs_linked": {
            "commands": ["python3 -m pytest tools/tests/test_loop_finalization_check.py -q"],
            "logs": ["agent_outputs/loop_finalization_check_2026-05-14.md"],
        },
        "mcp_memory_updated_when_relevant": {
            "relevant": False,
        },
    }


def _write_agent_cycle_log(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "schema": "auditooor.agent_cycle_log.v1",
                        "ts": "2026-05-17T00:00:00Z",
                        "event": "spawn",
                        "agent": "codex",
                        "task": "loop-finalization",
                        "workspace": "/tmp/workspace",
                    }
                ),
                json.dumps(
                    {
                        "schema": "auditooor.agent_cycle_log.v1",
                        "ts": "2026-05-17T00:10:00Z",
                        "event": "verify",
                        "agent": "codex",
                        "task": "loop-finalization",
                        "workspace": "/tmp/workspace",
                    }
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )


def _write_open_hacker_obligation(ws: Path, *, state: str = "open") -> None:
    path = ws / ".auditooor" / "hacker_question_obligations.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "schema": "auditooor.hacker_question_obligation.v1",
        "obligation_id": "hqtest000001",
        "workspace": str(ws),
        "file": "src/Vault.sol",
        "function_signature": "function withdraw(uint256 amount) external",
        "function_name": "withdraw",
        "attack_class": "reentrancy",
        "question": "Can withdraw re-enter before accounting is finalized?",
        "state": state,
    }
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")


def _write_source_read_receipt(ws: Path, rel_path: str) -> None:
    source_path = ws / rel_path
    path = ws / ".auditooor" / "source_read_receipts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "schema": "auditooor.source_read_receipt.v1",
        "receipt_id": "srtest000001",
        "workspace": str(ws),
        "file": rel_path,
        "absolute_file_path": str(source_path),
        "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "functions_analyzed": 1,
        "hacker_question_count": 1,
        "context_pack_id": "auditooor.test.context",
        "context_pack_hash": "a" * 64,
        "created_at_utc": "2026-05-21T00:00:00Z",
    }
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")


def _run_manifest(manifest: object, *args: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="loop-finalization-check-test-") as td:
        manifest_path = Path(td) / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return subprocess.run(
            ["python3", str(TOOL), "--manifest", str(manifest_path), *args],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )


class LoopFinalizationCheckCliTest(unittest.TestCase):
    def test_pass_manifest_returns_zero(self) -> None:
        proc = _run_manifest(_base_manifest(), "--json")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "pass")
        self.assertTrue(payload["passed"])

    def test_missing_artifact_and_reason_returns_policy_fail(self) -> None:
        manifest = _base_manifest()
        manifest.pop("changed_artifacts")

        proc = _run_manifest(manifest)

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("changed_artifacts or no_artifact_reason is required", proc.stdout)

    def test_missing_tests_or_logs_returns_policy_fail(self) -> None:
        manifest = _base_manifest()
        manifest["tests_or_logs_linked"] = {}

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "policy_fail")
        self.assertIn("tests_or_logs_linked must contain non-empty evidence", payload["policy_failures"])

    def test_workspace_manifest_requires_linked_logs_to_exist(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-check-logs-") as raw:
            workspace = Path(raw) / "ws"
            workspace.mkdir()
            manifest = _base_manifest()
            manifest["workspace_path"] = str(workspace)
            manifest["tests_or_logs_linked"] = {
                "commands": ["python3 -m unittest example"],
                "logs": ["reports/missing.log"],
            }

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "policy_fail")
            self.assertTrue(
                any(
                    failure.startswith("tests_or_logs_linked.logs must exist")
                    for failure in payload["policy_failures"]
                )
            )

    def test_workspace_manifest_accepts_existing_linked_logs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-check-logs-") as raw:
            workspace = Path(raw) / "ws"
            log_path = workspace / "reports" / "run.log"
            log_path.parent.mkdir(parents=True)
            log_path.write_text("PASS\n", encoding="utf-8")
            manifest = _base_manifest()
            manifest["workspace_path"] = str(workspace)
            manifest["tests_or_logs_linked"] = {
                "commands": ["python3 -m unittest example"],
                "logs": ["reports/run.log"],
            }

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["checks"]["tests_or_logs_linked"]["ok"], True)

    def test_mcp_context_evidence_rejects_tbd_placeholders(self) -> None:
        manifest = _base_manifest()
        manifest["mcp_context_evidence"] = {
            "context_pack_id": "TBD",
            "context_pack_hash": "TBD",
            "source_refs": ["obsidian-vault/current.md"],
        }

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "policy_fail")
        self.assertIn(
            "mcp_context_evidence contains missing or placeholder fields: context_pack_id, context_pack_hash",
            payload["policy_failures"],
        )

    def test_mcp_context_evidence_rejects_expanded_placeholders(self) -> None:
        manifest = _base_manifest()
        manifest["mcp_context_evidence"] = {
            "context_pack_id": "unknown",
            "context_pack_hash": "???",
            "source_refs": ["obsidian-vault/current.md"],
        }

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "policy_fail")
        self.assertIn(
            "mcp_context_evidence contains missing or placeholder fields: context_pack_id, context_pack_hash",
            payload["policy_failures"],
        )

    def test_mcp_relevant_but_missing_update_returns_policy_fail(self) -> None:
        manifest = _base_manifest()
        manifest["mcp_memory_updated_when_relevant"] = {
            "relevant": True,
            "updated": False,
        }

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "policy_fail")
        self.assertIn("mcp memory was relevant but not updated", payload["policy_failures"])

    def test_malformed_manifest_returns_error(self) -> None:
        proc = _run_manifest(["not", "an", "object"], "--json")

        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "malformed_input")
        self.assertIn("manifest root must be a JSON object", payload["malformed_reasons"])

    def test_allow_no_artifact_accepts_reason(self) -> None:
        manifest = _base_manifest()
        manifest.pop("changed_artifacts")
        manifest["no_artifact_reason"] = "This slice only reviewed and updated handoff state."

        proc = _run_manifest(manifest, "--allow-no-artifact", "--json")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["checks"]["artifact_evidence"]["mode"], "no_artifact_reason")

    def test_agent_cycle_log_is_advisory_only_when_missing(self) -> None:
        proc = _run_manifest(_base_manifest(), "--json")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["advisory_checks"]["agent_cycle_log"]["status"], "missing")

    def test_agent_cycle_log_summary_is_reported_when_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-check-log-") as raw:
            workspace = Path(raw) / "ws"
            workspace.mkdir()
            cycle_log_path = workspace / ".auditooor" / "agent_cycle_log.jsonl"
            _write_agent_cycle_log(cycle_log_path)

            manifest = _base_manifest()
            manifest["agent_cycle_log"] = {
                "path": str(cycle_log_path),
            }

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            advisory = payload["advisory_checks"]["agent_cycle_log"]
            self.assertEqual(advisory["status"], "present")
            self.assertEqual(advisory["rows"], 2)
            self.assertEqual(advisory["malformed_rows"], 0)
            self.assertEqual(advisory["by_event"], {"spawn": 1, "verify": 1})
            self.assertEqual(advisory["by_agent"], {"codex": 2})
            self.assertEqual(advisory["by_task"], {"loop-finalization": 2})

    def test_source_review_requires_hacker_questions_artifact(self) -> None:
        manifest = _base_manifest()
        manifest["changed_artifacts"] = [
            "external/v4-chain/protocol/x/clob/keeper/matches.go",
        ]

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "policy_fail")
        self.assertIn(
            "source-review slices require hacker_questions.artifacts or NO_HACKER_QUESTIONS reason",
            payload["policy_failures"],
        )
        self.assertTrue(payload["checks"]["hacker_questions"]["inferred_from_changed_artifacts"])

    def test_config_artifacts_require_hacker_questions_artifact(self) -> None:
        manifest = _base_manifest()
        manifest["changed_artifacts"] = [
            "deployments/mainnet/vault-config.yaml",
        ]

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "policy_fail")
        self.assertIn(
            "source-review slices require hacker_questions.artifacts or NO_HACKER_QUESTIONS reason",
            payload["policy_failures"],
        )
        self.assertTrue(payload["checks"]["hacker_questions"]["inferred_from_changed_artifacts"])

    def test_report_json_does_not_trigger_source_review(self) -> None:
        manifest = _base_manifest()
        manifest["changed_artifacts"] = [
            "reports/v3_roadmap_progress_report.json",
        ]

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertFalse(payload["checks"]["hacker_questions"]["relevant"])

    def test_source_review_accepts_hacker_questions_artifact(self) -> None:
        manifest = _base_manifest()
        manifest["changed_artifacts"] = [
            "external/v4-chain/protocol/x/clob/keeper/matches.go",
        ]
        manifest["hacker_questions"] = {
            "artifacts": ["agent_outputs/pre_source_read_injection.json"],
            "schemas": ["auditooor.hacker_question.v1"],
        }

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["checks"]["hacker_questions"]["mode"], "artifact")

    def test_explicit_source_review_accepts_no_hacker_questions_reason(self) -> None:
        manifest = _base_manifest()
        manifest["hacker_questions"] = {
            "source_review_relevant": True,
            "no_hacker_questions_reason": (
                "NO_HACKER_QUESTIONS: source hook unavailable for generated fixture cleanup."
            ),
        }

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["checks"]["hacker_questions"]["mode"], "no_hacker_questions_reason")

    def test_no_hacker_questions_reason_requires_marker(self) -> None:
        manifest = _base_manifest()
        manifest["hacker_questions"] = {
            "source_review_relevant": True,
            "no_hacker_questions_reason": "docs-only slice",
        }

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn(
            "hacker_questions.no_hacker_questions_reason must include NO_HACKER_QUESTIONS",
            payload["policy_failures"],
        )

    def test_high_draft_with_open_hacker_obligation_fails_finalization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-hq-") as raw:
            ws = Path(raw) / "ws"
            draft = ws / "submissions" / "staging" / "hq.md"
            log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
            draft.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            draft.write_text(
                "# Finding\n\nSeverity: Critical\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            log.write_text("ok\n", encoding="utf-8")
            _write_open_hacker_obligation(ws)
            manifest = _base_manifest()
            manifest["workspace_path"] = str(ws)
            manifest["changed_artifacts"] = ["submissions/staging/hq.md"]

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "policy_fail")
            gate = payload["checks"]["hacker_question_obligations"]
            self.assertEqual(gate["mode"], "blocking_open_obligations")
            self.assertEqual(gate["blocking_count"], 1)

    def test_high_draft_with_answered_hacker_obligation_passes_finalization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-hq-") as raw:
            ws = Path(raw) / "ws"
            draft = ws / "submissions" / "staging" / "hq.md"
            log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
            draft.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            draft.write_text(
                "# Finding\n\nSeverity: High\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            log.write_text("ok\n", encoding="utf-8")
            _write_open_hacker_obligation(ws, state="answered")
            manifest = _base_manifest()
            manifest["workspace_path"] = str(ws)
            manifest["changed_artifacts"] = ["submissions/staging/hq.md"]

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            gate = payload["checks"]["hacker_question_obligations"]
            self.assertEqual(gate["mode"], "no_matching_open_obligations")

    def test_medium_draft_with_open_hacker_obligation_does_not_fail_finalization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-hq-") as raw:
            ws = Path(raw) / "ws"
            draft = ws / "submissions" / "staging" / "hq.md"
            log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
            draft.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            draft.write_text(
                "# Finding\n\nSeverity: Medium\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            log.write_text("ok\n", encoding="utf-8")
            _write_open_hacker_obligation(ws)
            manifest = _base_manifest()
            manifest["workspace_path"] = str(ws)
            manifest["changed_artifacts"] = ["submissions/staging/hq.md"]

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            gate = payload["checks"]["hacker_question_obligations"]
            self.assertEqual(gate["mode"], "no_high_critical_drafts")

    def test_high_draft_missing_source_read_receipt_fails_finalization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-srr-") as raw:
            ws = Path(raw) / "ws"
            source = ws / "src" / "Vault.sol"
            draft = ws / "submissions" / "staging" / "source.md"
            log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
            source.parent.mkdir(parents=True)
            draft.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            source.write_text("contract Vault { function withdraw() external {} }\n", encoding="utf-8")
            draft.write_text(
                "# Finding\n\nSeverity: High\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            log.write_text("ok\n", encoding="utf-8")
            manifest = _base_manifest()
            manifest["workspace_path"] = str(ws)
            manifest["changed_artifacts"] = ["submissions/staging/source.md"]

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            gate = payload["checks"]["source_read_receipts"]
            self.assertEqual(gate["status"], "fail")
            self.assertEqual(gate["mode"], "blocking_missing_or_stale_receipts")
            self.assertEqual(gate["missing_receipts"], [{"draft_path": str(draft), "file": "src/Vault.sol"}])

    def test_high_draft_with_matching_source_read_receipt_passes_finalization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-srr-") as raw:
            ws = Path(raw) / "ws"
            source = ws / "src" / "Vault.sol"
            draft = ws / "submissions" / "staging" / "source.md"
            log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
            source.parent.mkdir(parents=True)
            draft.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            source.write_text("contract Vault { function withdraw() external {} }\n", encoding="utf-8")
            _write_source_read_receipt(ws, "src/Vault.sol")
            draft.write_text(
                "# Finding\n\nSeverity: Critical\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            log.write_text("ok\n", encoding="utf-8")
            manifest = _base_manifest()
            manifest["workspace_path"] = str(ws)
            manifest["changed_artifacts"] = ["submissions/staging/source.md"]

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            gate = payload["checks"]["source_read_receipts"]
            self.assertEqual(gate["status"], "pass")
            self.assertEqual(gate["mode"], "all_cited_sources_have_receipts")
            self.assertEqual(gate["draft_results"][0]["counts"]["with_receipts"], 1)

    def test_high_draft_with_stale_source_read_receipt_fails_finalization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-srr-") as raw:
            ws = Path(raw) / "ws"
            source = ws / "src" / "Vault.sol"
            draft = ws / "submissions" / "staging" / "source.md"
            log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
            source.parent.mkdir(parents=True)
            draft.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            source.write_text("contract Vault { function withdraw() external {} }\n", encoding="utf-8")
            _write_source_read_receipt(ws, "src/Vault.sol")
            source.write_text("contract Vault { function withdraw(uint256) external {} }\n", encoding="utf-8")
            draft.write_text(
                "# Finding\n\nSeverity: High\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            log.write_text("ok\n", encoding="utf-8")
            manifest = _base_manifest()
            manifest["workspace_path"] = str(ws)
            manifest["changed_artifacts"] = ["submissions/staging/source.md"]

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            gate = payload["checks"]["source_read_receipts"]
            self.assertEqual(gate["status"], "fail")
            self.assertEqual(gate["stale_receipts"], [{"draft_path": str(draft), "file": "src/Vault.sol"}])

    def test_high_draft_touched_source_without_citation_requires_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-srr-") as raw:
            ws = Path(raw) / "ws"
            source = ws / "src" / "Vault.sol"
            draft = ws / "submissions" / "staging" / "source.md"
            log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
            source.parent.mkdir(parents=True)
            draft.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            source.write_text("contract Vault { function withdraw() external {} }\n", encoding="utf-8")
            draft.write_text(
                "# Finding\n\nSeverity: Critical\n\nThe withdrawal path is reachable.\n",
                encoding="utf-8",
            )
            log.write_text("ok\n", encoding="utf-8")
            manifest = _base_manifest()
            manifest["workspace_path"] = str(ws)
            manifest["changed_artifacts"] = ["submissions/staging/source.md", "src/Vault.sol"]
            manifest["hacker_questions"] = {
                "artifacts": ["agent_outputs/pre_source_read_injection.json"],
                "schemas": ["auditooor.hacker_question.v1"],
            }

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            gate = payload["checks"]["source_read_receipts"]
            self.assertEqual(gate["status"], "fail")
            self.assertEqual(gate["changed_source_files"], ["src/Vault.sol"])
            self.assertEqual(gate["missing_receipts"], [{"draft_path": str(draft), "file": "src/Vault.sol"}])

    def test_medium_draft_missing_source_read_receipt_does_not_fail_finalization(self) -> None:
        with tempfile.TemporaryDirectory(prefix="loop-finalization-srr-") as raw:
            ws = Path(raw) / "ws"
            source = ws / "src" / "Vault.sol"
            draft = ws / "submissions" / "staging" / "source.md"
            log = ws / "agent_outputs" / "loop_finalization_check_2026-05-14.md"
            source.parent.mkdir(parents=True)
            draft.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            source.write_text("contract Vault { function withdraw() external {} }\n", encoding="utf-8")
            draft.write_text(
                "# Finding\n\nSeverity: Medium\n\nsrc/Vault.sol withdraw is reachable.\n",
                encoding="utf-8",
            )
            log.write_text("ok\n", encoding="utf-8")
            manifest = _base_manifest()
            manifest["workspace_path"] = str(ws)
            manifest["changed_artifacts"] = ["submissions/staging/source.md"]

            proc = _run_manifest(manifest, "--json")

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            gate = payload["checks"]["source_read_receipts"]
            self.assertEqual(gate["status"], "pass")
            self.assertEqual(gate["mode"], "no_high_critical_drafts")

    def test_hacker_questions_schema_must_match_shared_renderer(self) -> None:
        manifest = _base_manifest()
        manifest["hacker_questions"] = {
            "source_review_relevant": True,
            "artifacts": ["agent_outputs/pre_source_read_injection.json"],
            "schemas": ["old.schema.v1"],
        }

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn(
            "hacker_questions.schemas must include auditooor.hacker_question.v1",
            payload["policy_failures"],
        )

    def test_hacker_questions_artifact_requires_schema_evidence(self) -> None:
        manifest = _base_manifest()
        manifest["hacker_questions"] = {
            "source_review_relevant": True,
            "artifacts": ["agent_outputs/pre_source_read_injection.json"],
        }

        proc = _run_manifest(manifest, "--json")

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIn(
            "hacker_questions.schemas must include auditooor.hacker_question.v1",
            payload["policy_failures"],
        )


if __name__ == "__main__":
    unittest.main()
