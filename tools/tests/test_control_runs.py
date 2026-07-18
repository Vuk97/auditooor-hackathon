from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.control import runs
from tools.control.runs import discover_run_rows, summarize_runs


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class ControlRunsTests(unittest.TestCase):
    def test_missing_workspace_reports_missing_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "does-not-exist"
            summary = summarize_runs(missing)

        self.assertEqual(summary["artifact_count"], 1)
        self.assertEqual(summary["counts_by_execution_state"], {"missing_workspace": 1})
        self.assertEqual(summary["proof_counted"], {"true": 0, "false": 1})
        self.assertEqual(summary["rows"][0]["blockers"], ["workspace_missing"])

    def test_partial_audit_deep_manifest_is_not_counted_as_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_json(
                ws / ".audit_logs" / "audit_deep_all_manifest.json",
                {
                    "schema": "auditooor.audit_deep_all.v1",
                    "profiles": [
                        {"profile": "default", "status": "success", "exit_code": 0},
                        {"profile": "math", "status": "skipped_budget", "exit_code": 0},
                    ],
                },
            )

            rows = discover_run_rows(ws)
            summary = summarize_runs(ws)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tool"], "audit-deep")
        self.assertEqual(rows[0]["execution_state"], "partial")
        self.assertFalse(rows[0]["proof_counted"])
        self.assertIn("audit_deep_manifest_partial", rows[0]["warnings"])
        self.assertEqual(summary["counts_by_execution_state"], {"partial": 1})

    def test_blocked_poc_execution_manifest_is_blocked_not_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_json(
                ws / "poc_execution" / "blocked-case" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "blocked-case",
                    "final_result": "blocked_path",
                    "impact_assertion": "not_demonstrated",
                },
            )

            summary = summarize_runs(ws)

        self.assertEqual(summary["counts_by_execution_state"], {"blocked": 1})
        self.assertEqual(summary["proof_counted"], {"true": 0, "false": 1})
        row = summary["rows"][0]
        self.assertEqual(row["tool"], "poc-execution")
        self.assertFalse(row["proof_counted"])
        self.assertIn("final_result_blocked_path", row["blockers"])
        self.assertIn("impact_assertion_not_demonstrated", row["blockers"])

    def test_proved_poc_execution_manifest_with_legacy_command_is_not_counted_as_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_json(
                ws / "poc_execution" / "proved-case" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "proved-case",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": ["forge test --match-test testExploit"],
                },
            )

            summary = summarize_runs(ws)

        self.assertEqual(summary["counts_by_execution_state"], {"executed": 1})
        self.assertEqual(summary["proof_counted"], {"true": 0, "false": 1})
        row = summary["rows"][0]
        self.assertEqual(row["artifact_path"], "poc_execution/proved-case/execution_manifest.json")
        self.assertFalse(row["proof_counted"])
        self.assertIn("commands_attempted_structured", row["blockers"])
        self.assertIn("commands_attempted_pass_exit_0", row["blockers"])

    def test_proved_poc_execution_manifest_counts_as_proof_with_strict_command_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_json(
                ws / "poc_execution" / "proved-case" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "proved-case",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {
                            "command": "forge test --match-test testExploit",
                            "status": "pass",
                            "exit_code": "0",
                        }
                    ],
                },
            )

            summary = summarize_runs(ws)

        self.assertEqual(summary["counts_by_execution_state"], {"executed": 1})
        self.assertEqual(summary["proof_counted"], {"true": 1, "false": 0})
        row = summary["rows"][0]
        self.assertTrue(row["proof_counted"])
        self.assertEqual(row["blockers"], [])

    def test_proved_poc_execution_manifest_requires_evidence_class_for_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_json(
                ws / "poc_execution" / "proved-case" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "proved-case",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "commands_attempted": [
                        {
                            "command": "forge test --match-test testExploit",
                            "status": "pass",
                            "exit_code": 0,
                        }
                    ],
                },
            )

            summary = summarize_runs(ws)

        self.assertEqual(summary["proof_counted"], {"true": 0, "false": 1})
        row = summary["rows"][0]
        self.assertFalse(row["proof_counted"])
        self.assertIn("evidence_class_not_executed_with_manifest", row["blockers"])

    def test_proved_poc_execution_manifest_rejects_bool_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_json(
                ws / "poc_execution" / "proved-case" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "proved-case",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {
                            "command": "forge test --match-test testExploit",
                            "status": "pass",
                            "exit_code": True,
                        }
                    ],
                },
            )

            summary = summarize_runs(ws)

        self.assertEqual(summary["proof_counted"], {"true": 0, "false": 1})
        row = summary["rows"][0]
        self.assertFalse(row["proof_counted"])
        self.assertIn("commands_attempted_pass_exit_0", row["blockers"])
        self.assertIn("command_exit_code_bool", row["blockers"])

    def test_proved_poc_execution_manifest_rejects_empty_command_text(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_json(
                ws / "poc_execution" / "proved-case" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "proved-case",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {
                            "command": "   ",
                            "status": "pass",
                            "exit_code": 0,
                        }
                    ],
                },
            )

            summary = summarize_runs(ws)

        self.assertEqual(summary["proof_counted"], {"true": 0, "false": 1})
        row = summary["rows"][0]
        self.assertFalse(row["proof_counted"])
        self.assertIn("commands_attempted_nonempty_command", row["blockers"])
        self.assertIn("commands_attempted_pass_exit_0", row["blockers"])

    def test_invalid_nonempty_bound_sources_cannot_count_as_proof(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write_json(
                ws / "poc_execution" / "bound-case" / "execution_manifest.json",
                {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "bound-case",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                    "bound_sources": [{"path": "src/Target.sol"}],
                },
            )

            with patch.object(
                runs._execution_manifest_proof,
                "bound_source_validation",
                return_value={
                    "supplied": True,
                    "valid": False,
                    "entries": [],
                    "errors": ["bound_source_sha256_mismatch"],
                },
                create=True,
            ):
                row = discover_run_rows(ws)[0]

        self.assertFalse(row["proof_counted"])
        self.assertIn("bound_source_sha256_mismatch", row["blockers"])

    def test_missing_and_empty_bound_sources_remain_compatible(self) -> None:
        for bound_sources in (None, []):
            with self.subTest(bound_sources=bound_sources), tempfile.TemporaryDirectory() as td:
                ws = Path(td)
                manifest = {
                    "schema_version": "auditooor.poc_execution_manifest.v1",
                    "candidate_id": "legacy-case",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [{"command": "forge test", "status": "pass", "exit_code": 0}],
                }
                if bound_sources is not None:
                    manifest["bound_sources"] = bound_sources
                _write_json(ws / "poc_execution" / "legacy-case" / "execution_manifest.json", manifest)

                row = discover_run_rows(ws)[0]

            self.assertTrue(row["proof_counted"])


if __name__ == "__main__":
    unittest.main()
