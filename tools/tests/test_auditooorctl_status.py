#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "auditooorctl.py"
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from control.status import collect_status, render_human  # noqa: E402


def _write(path: Path, text: str = "ready\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _finalization_row(task_id: str, gap_id: str, slot_id: str, status: str, closed_at: str) -> dict:
    return {
        "schema": "auditooor.task_finalization.v1",
        "task_id": task_id,
        "gap_id": gap_id,
        "slot_id": slot_id,
        "status": status,
        "finalization_row_kind": "merged_pr" if status == "landed" else "operator_deferred",
        "owner": "codex",
        "dispatch_source": "vault://NEXT_LOOP.md#G8",
        "source_manifest": "obsidian-vault/dispatch/next_dispatch_manifest.json",
        "terminal_artifact": "https://github.com/Vuk97/auditooor/pull/605",
        "changed_files": ["docs/TASK_FINALIZATION_LEDGER.md"] if status == "landed" else [],
        "verification": {
            "commands": [{"command": "make task-finalization-test", "exit_code": 0}],
            "passed": status == "landed",
        },
        "open_followups": [],
        "docs_updated": True,
        "readme_updated": False,
        "frontdoor_updated": False,
        "outcome_or_calibration_updated": False,
        "memory_updates": ["docs/TASK_FINALIZATION_LEDGER.md"],
        "blocked_by": "operator gate" if status == "blocked" else None,
        "closed_at": closed_at,
    }


class TestAuditooorctlStatus(unittest.TestCase):
    def test_collect_status_reports_ready_rows_and_artifacts(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            ws.mkdir()
            _write(ws / "SCOPE.md", "# Scope\ncontracts in scope\n")
            _write(ws / "SEVERITY.md", "# Severity\nHigh: fund loss\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nmapped\n")
            _write(ws / "OOS_CHECKLIST.md", "# OOS\nchecked\n")
            _write(ws / "engage_report.md")
            _write(ws / "scan_report.md")
            _write(ws / "static-analysis-summary.md")
            _write(ws / ".auditooor" / "semantic_graph.json", "{}\n")
            _write(ws / ".auditooor" / "invariant_ledger.json", "{}\n")
            _write(ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json", "{}\n")
            _write(ws / ".audit_logs" / "audit_deep_all_manifest.json", "{}\n")
            _write(
                ws / "reports" / "task_finalization.jsonl",
                json.dumps(_finalization_row(
                    "g8-001-slot-1-landed", "G8-001", "slot-1", "landed",
                    "2026-05-05T01:00:00+02:00")) + "\n" +
                json.dumps(_finalization_row(
                    "g8-002-slot-2-blocked", "G8-002", "slot-2", "blocked",
                    "2026-05-04T23:30:00Z")) + "\n",
            )
            (ws / "submissions").mkdir()

            snap = collect_status(ws)

            self.assertEqual(snap["schema"], "auditooor.control.status.v1")
            self.assertEqual(snap["readiness"]["scope"]["status"], "ready")
            self.assertEqual(snap["readiness"]["severity"]["status"], "ready")
            self.assertEqual(snap["readiness"]["oos"]["status"], "ready")
            self.assertEqual(snap["artifacts"]["semantic_graph"]["status"], "present")
            self.assertEqual(snap["artifacts"]["audit_deep_manifest"]["status"], "executed_unknown")
            self.assertEqual(snap["artifacts"]["task_finalization_ledger"]["status"], "present")
            self.assertEqual(snap["artifacts"]["task_finalization_ledger"]["row_count"], 2)
            self.assertEqual(
                snap["artifacts"]["task_finalization_ledger"]["status_counts"],
                {"blocked": 1, "landed": 1},
            )
            self.assertEqual(
                snap["artifacts"]["task_finalization_ledger"]["latest_task_id"],
                "g8-002-slot-2-blocked",
            )
            self.assertEqual(snap["artifacts"]["submissions"]["kind"], "directory")

    def test_missing_and_placeholder_inputs_fail_closed(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "sparse"
            ws.mkdir()
            _write(ws / "SCOPE.md", "TODO placeholder\n")
            _write(ws / "SEVERITY_SMART_CONTRACTS.md", "High impact\n")
            _write(ws / "reports" / "task_finalization.jsonl", '{"schema": "bad"}\n')

            snap = collect_status(ws)

            self.assertEqual(snap["readiness"]["scope"]["status"], "blocked_unknown")
            self.assertEqual(snap["readiness"]["severity"]["status"], "blocked_unknown")
            self.assertEqual(snap["readiness"]["oos"]["status"], "missing")
            self.assertEqual(snap["artifacts"]["scan_report"]["status"], "missing")
            self.assertEqual(snap["artifacts"]["task_finalization_ledger"]["status"], "blocked_unknown")
            self.assertEqual(snap["artifacts"]["task_finalization_ledger"]["row_count"], 0)
            self.assertIn("summary_error", snap["artifacts"]["task_finalization_ledger"])

    def test_invalid_task_finalization_row_fails_closed(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "invalid-ledger"
            ws.mkdir()
            _write(
                ws / "reports" / "task_finalization.jsonl",
                json.dumps({
                    "schema": "auditooor.task_finalization.v1",
                    "task_id": "g8-001-slot-1-landed",
                    "gap_id": "G8-001",
                    "slot_id": "slot-1",
                    "status": "landed",
                    "finalization_row_kind": "merged_pr",
                    "owner": "codex",
                    "terminal_artifact": "https://github.com/Vuk97/auditooor/pull/605",
                    "closed_at": "2026-05-05T00:00:00+00:00",
                }) + "\n",
            )

            snap = collect_status(ws)

            ledger = snap["artifacts"]["task_finalization_ledger"]
            self.assertEqual(ledger["status"], "blocked_unknown")
            self.assertEqual(ledger["row_count"], 0)
            self.assertIn("landed rows require at least one changed file", ledger["summary_error"])

    def test_mixed_task_finalization_rows_preserve_valid_counts_but_fail_closed(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "mixed-ledger"
            ws.mkdir()
            _write(
                ws / "reports" / "task_finalization.jsonl",
                json.dumps(_finalization_row(
                    "g8-001-slot-1-landed", "G8-001", "slot-1", "landed",
                    "2026-05-05T00:00:00+00:00")) + "\n" +
                json.dumps({
                    "schema": "auditooor.task_finalization.v1",
                    "task_id": "g8-002-slot-1-landed",
                    "gap_id": "G8-002",
                    "slot_id": "slot-1",
                    "status": "landed",
                    "finalization_row_kind": "merged_pr",
                    "owner": "codex",
                    "closed_at": "2026-05-05T01:00:00+00:00",
                }) + "\n",
            )

            snap = collect_status(ws)

            ledger = snap["artifacts"]["task_finalization_ledger"]
            self.assertEqual(ledger["status"], "blocked_unknown")
            self.assertEqual(ledger["row_count"], 1)
            self.assertEqual(ledger["total_rows"], 2)
            self.assertEqual(ledger["invalid_row_count"], 1)
            self.assertEqual(ledger["status_counts"], {"landed": 1})
            self.assertIn("invalid task finalization row", ledger["summary_error"])

    def test_cli_json_and_human_output(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "cli"
            ws.mkdir()
            _write(ws / "SCOPE.md", "# Scope\nready\n")
            _write(ws / "SEVERITY.md", "# Severity\nready\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Rubric\nready\n")
            _write(ws / "OOS_PASTED.md", "# OOS\nready\n")
            _write(
                ws / "reports" / "task_finalization.jsonl",
                json.dumps(_finalization_row(
                    "g8-001-slot-1-landed", "G8-001", "slot-1", "landed",
                    "2026-05-05T00:00:00+00:00")) + "\n",
            )

            json_run = subprocess.run(
                [sys.executable, str(SCRIPT), "status", str(ws), "--json"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            payload = json.loads(json_run.stdout)
            self.assertEqual(payload["schema"], "auditooor.control.status.v1")
            self.assertEqual(payload["readiness"]["severity"]["status"], "ready")
            self.assertEqual(payload["artifacts"]["task_finalization_ledger"]["status_counts"]["landed"], 1)

            human_run = subprocess.run(
                [sys.executable, str(SCRIPT), "status", str(ws)],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertIn("scope", human_run.stdout)
            self.assertIn("ready", human_run.stdout)
            self.assertIn("semantic_graph", human_run.stdout)
            self.assertIn("task_finalization_ledger", human_run.stdout)
            self.assertIn("rows=1", human_run.stdout)
            self.assertIn("status", render_human(payload))


if __name__ == "__main__":
    unittest.main()
