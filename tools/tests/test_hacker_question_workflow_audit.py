from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hacker-question-workflow-audit.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("hacker_question_workflow_audit", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load hacker-question-workflow-audit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_obligations(ws: Path, *rows: dict[str, object]) -> None:
    path = ws / ".auditooor" / "hacker_question_obligations.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _write_receipts(ws: Path, *rows: dict[str, object]) -> None:
    path = ws / ".auditooor" / "source_read_receipts.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _receipt(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema": "auditooor.source_read_receipt.v1",
        "receipt_id": "receipt123456",
        "workspace": "<workspace>",
        "file": "src/Vault.sol",
        "absolute_file_path": "/tmp/src/Vault.sol",
        "target_repo": "owner/repo",
        "language": "solidity",
        "functions_analyzed": 1,
        "function_names": ["withdraw"],
        "hacker_question_count": 7,
        "hacker_question_counts_by_source": {"corpus-derived": 2, "curated-library": 5},
        "corpus_backed_hypothesis_count": 2,
        "no_questions_reason": "",
        "context_pack_id": "test-pack",
        "context_pack_hash": "test-hash",
        "source_injection_schema": "auditooor.pre_source_read_injection.v1",
        "skipped_reasons": [],
        "created_at_utc": "2026-05-20T00:00:00Z",
    }
    row.update(overrides)
    return row


def _obligation(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema": "auditooor.hacker_question_obligation.v1",
        "obligation_id": "abc123def456",
        "workspace": "<workspace>",
        "file": "src/Vault.sol",
        "function_signature": "function withdraw(uint256 amount) external",
        "function_name": "withdraw",
        "attack_class": "reentrancy",
        "question": "Can withdraw re-enter before accounting is finalized?",
        "question_source": "corpus-derived",
        "corpus_provenance": "record-1",
        "state": "open",
        "source_refs": ["record-1"],
        "local_verification_cmd": "grep -n 'withdraw' src/Vault.sol",
        "operator_notes": "",
        "created_at_utc": "2026-05-20T00:00:00Z",
        "updated_at_utc": "2026-05-20T00:00:00Z",
        "context_pack_id": "test-pack",
    }
    row.update(overrides)
    return row


def _repo_with_gate_evidence(root: Path, *, include_pre_submit_gate: bool = True) -> Path:
    (root / "tools").mkdir(parents=True, exist_ok=True)
    (root / "Makefile").write_text(
        "\n".join(
            [
                "help:",
                "\t@echo \"bash tools/pre-submit-check.sh <draft.md>\"",
                "",
                "proof-obligation-queue:",
                "\tpython3 tools/proof-obligation-queue.py --workspace \"$(WS)\"",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    pre_submit = (
        "echo '78. HACKER-QUESTION-ANSWERS'\n"
        "python3 tools/hacker-question-obligations.py --json gate-draft \"$WS\" \"$SUB\"\n"
        if include_pre_submit_gate
        else "echo 'no hacker question gate here'\n"
    )
    (root / "tools" / "pre-submit-check.sh").write_text(pre_submit, encoding="utf-8")
    return root


class HackerQuestionWorkflowAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="hqaudit-")
        self.base = Path(self.tmp.name)
        self.ws = self.base / "workspace"
        self.ws.mkdir()
        self.repo = _repo_with_gate_evidence(self.base / "repo")
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_no_obligations_fails_with_generation_commands(self) -> None:
        result = self.tool.audit_workspace(self.ws, repo_root=self.repo)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["checks"]["obligations"]["status"], "fail")
        self.assertIn("hacker_question_obligations.jsonl", result["checks"]["obligations"]["summary"])
        self.assertTrue(
            any("hacker-question-obligations.py --json ingest-injection" in command for command in result["next_commands"])
        )

    def test_receipt_only_workspace_passes_and_reports_question_counts(self) -> None:
        _write_receipts(self.ws, _receipt())

        result = self.tool.audit_workspace(self.ws, repo_root=self.repo)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["checks"]["obligations"]["status"], "pass")
        self.assertEqual(result["checks"]["source_read_receipts"]["total"], 1)
        self.assertEqual(result["summary"]["hacker_question_count"], 7)
        self.assertEqual(result["summary"]["corpus_backed_hypothesis_count"], 2)
        self.assertFalse(
            any("hacker-question-obligations.py --json ingest-injection" in command for command in result["next_commands"])
        )

    def test_open_obligation_matching_staged_draft_fails_and_surfaces_gate_command(self) -> None:
        _write_obligations(self.ws, _obligation())
        draft = self.ws / "submissions" / "staging" / "withdraw.md"
        draft.parent.mkdir(parents=True, exist_ok=True)
        draft.write_text(
            "Root cause reaches src/Vault.sol where withdraw can re-enter.\n",
            encoding="utf-8",
        )
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            {
                "schema": "auditooor.proof_obligation_queue.v1",
                "tasks": [
                    {
                        "task_id": "POQ-001",
                        "proof_needed": "Answer abc123def456 for src/Vault.sol withdraw",
                    }
                ],
            },
        )

        result = self.tool.audit_workspace(self.ws, repo_root=self.repo)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["checks"]["staged_drafts"]["status"], "fail")
        self.assertEqual(result["summary"]["matching_drafts"], 1)
        match = result["checks"]["staged_drafts"]["matching_drafts"][0]["obligations"][0]
        self.assertIn("file_and_function_name", match["match_reasons"])
        self.assertTrue(any("gate-draft" in command and "withdraw.md" in command for command in result["next_commands"]))

    def test_closed_obligations_pass_when_gates_are_wired(self) -> None:
        _write_obligations(
            self.ws,
            _obligation(obligation_id="ans1", state="answered"),
            _obligation(obligation_id="kill1", state="killed"),
            _obligation(obligation_id="poc1", state="promoted_to_poc"),
        )

        result = self.tool.audit_workspace(self.ws, repo_root=self.repo)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["checks"]["obligations"]["by_state"]["answered"], 1)
        self.assertEqual(result["checks"]["obligations"]["by_state"]["killed"], 1)
        self.assertEqual(result["checks"]["obligations"]["by_state"]["promoted_to_poc"], 1)
        self.assertEqual(result["next_commands"], [])

    def test_makefile_and_pre_submit_evidence_is_reported(self) -> None:
        _write_obligations(self.ws, _obligation(state="answered"))

        result = self.tool.audit_workspace(self.ws, repo_root=self.repo)
        gate = result["checks"]["gate_references"]

        self.assertEqual(gate["status"], "pass")
        self.assertTrue(gate["evidence"]["makefile"]["checks"]["proof_obligation_queue_target"]["present"])
        self.assertTrue(gate["evidence"]["makefile"]["checks"]["pre_submit_reference"]["present"])
        self.assertTrue(gate["evidence"]["pre_submit"]["checks"]["obligation_tool_reference"]["present"])
        self.assertTrue(gate["evidence"]["pre_submit"]["checks"]["gate_draft_call"]["present"])

    def test_missing_pre_submit_gate_reference_fails(self) -> None:
        repo = _repo_with_gate_evidence(self.base / "repo-missing-gate", include_pre_submit_gate=False)
        _write_obligations(self.ws, _obligation(state="answered"))

        result = self.tool.audit_workspace(self.ws, repo_root=repo)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["checks"]["gate_references"]["status"], "fail")
        self.assertIn("pre_submit.gate_draft_call", result["checks"]["gate_references"]["missing"])

    def test_cli_strict_fails_on_open_obligation_warns(self) -> None:
        _write_obligations(self.ws, _obligation())
        _write_json(
            self.ws / ".auditooor" / "proof_obligation_queue.json",
            {
                "schema": "auditooor.proof_obligation_queue.v1",
                "tasks": [{"task_id": "POQ-001", "proof_needed": "Answer abc123def456"}],
            },
        )

        rc = self.tool.main(
            [
                "--workspace",
                str(self.ws),
                "--repo-root",
                str(self.repo),
                "--strict",
            ]
        )

        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
