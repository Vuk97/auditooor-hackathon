#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.open_state import SCHEMA, collect_open_state, write_open_state


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    _write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


class ControlOpenStateTests(unittest.TestCase):
    def test_collect_open_state_summarizes_control_inputs_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            _seed_candidate_workspace(ws)
            durable_path = ws / ".auditooor" / "control" / "state.json"

            payload = collect_open_state(ws, generated_at="2026-05-03T00:00:00Z", cwd=ws)

            self.assertFalse(durable_path.exists())

        self.assertEqual(payload["schema"], SCHEMA)
        self.assertEqual(payload["generated_at"], "2026-05-03T00:00:00Z")
        self.assertEqual(payload["target_name"], "demo")
        self.assertEqual(payload["snapshot_summary"]["candidate_count"], 1)
        self.assertEqual(payload["snapshot_summary"]["readiness"]["scope"], "ready")
        self.assertGreaterEqual(payload["gap_summary"]["counts_by_priority"]["P0"], 1)
        self.assertGreater(payload["provider_task_summary"]["task_count"], 0)
        self.assertIn("kimi", payload["provider_task_summary"]["by_provider"])
        self.assertTrue(payload["command_plan_summary"]["dry_run"])
        self.assertFalse(payload["command_plan_summary"]["would_execute"])
        self.assertGreater(payload["command_plan_summary"]["command_count"], 0)
        self.assertIn("Provider output", payload["proof_boundary"])

    def test_write_open_state_creates_default_durable_path_only_when_called(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            _seed_ready_workspace(ws)
            durable_path = ws / ".auditooor" / "control" / "state.json"
            self.assertFalse(durable_path.exists())

            result = write_open_state(ws, generated_at="2026-05-03T00:00:00Z", cwd=ws)
            written = json.loads(durable_path.read_text(encoding="utf-8"))

        self.assertEqual(result["path"], durable_path.resolve().as_posix())
        self.assertEqual(result["state"], written)
        self.assertEqual(written["schema"], SCHEMA)
        self.assertEqual(written["workspace"], ws.resolve().as_posix())
        self.assertEqual(written["snapshot_summary"]["readiness_status"], "ready_for_codex_gate")
        self.assertEqual(written["gap_summary"]["gap_count"], 0)
        self.assertGreaterEqual(written["provider_task_summary"]["task_count"], 0)
        self.assertIsInstance(written["provider_task_summary"]["by_provider"], dict)
        self.assertTrue(written["command_plan_summary"]["dry_run"])
        self.assertFalse(written["command_plan_summary"]["would_execute"])

    def test_write_open_state_is_idempotent_for_unchanged_workspace_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            _seed_ready_workspace(ws)

            first = write_open_state(ws, generated_at="2026-05-03T00:00:00Z", cwd=ws)
            second = write_open_state(ws, generated_at="2099-01-01T00:00:00Z", cwd=ws)
            path = Path(second["path"])

            self.assertEqual(first["state"], second["state"])
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), first["state"])


def _seed_candidate_workspace(ws: Path) -> None:
    ws.mkdir(parents=True)
    _write(ws / "SCOPE.md", "# Scope\nsrc only\n")
    _write(ws / "OOS_PASTED.md", "# OOS\nfrontend\n")
    _write(ws / "SEVERITY.md", "# Severity\nHigh: permanent funds locked\n")
    _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nmapped\n")
    _write_json(
        ws / ".auditooor" / "control" / "candidates" / "oracle-stale.json",
        {
            "id": "oracle-stale",
            "title": "oracle stale price path",
            "status": "candidate",
            "severity": "High",
            "impact": "permanent funds locked",
            "proof_state": "planned",
            "source_paths": ["src/Oracle.sol", "provider-packets/kimi/oracle-stale.md"],
        },
    )


def _seed_ready_workspace(ws: Path) -> None:
    ws.mkdir(parents=True)
    _write(ws / "SCOPE.md", "# Scope\nsrc only\n")
    _write(ws / "OOS_PASTED.md", "# OOS\nfrontend\n")
    _write(ws / "SEVERITY.md", "# Severity\nMedium: pool liveness\n")
    _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nmapped\n")
    _write(ws / "scan_report.md", "DONE\n")
    _write(ws / "static-analysis-summary.md", "DONE\n")
    _write_json(ws / ".auditooor" / "semantic_graph.json", {})
    _write_json(
        ws / ".auditooor" / "control" / "candidates" / "ready.json",
        {
            "id": "ready",
            "title": "ready lane",
            "status": "submitted",
            "severity": "Medium",
            "likelihood": "Medium",
            "impact": "pool liveness failure",
            "inline_poc_ready": True,
            "poc_command": "forge test --match-test testReady",
            "poc_result": "PASS",
            "oos_checked": True,
            "recommended_fix": "validate inputs",
        },
    )
    _write_json(
        ws / "poc_execution" / "ready" / "execution_manifest.json",
        {
            "candidate_id": "ready",
            "final_result": "proved",
            "impact_assertion": "exploit_impact",
            "evidence_class": "executed_with_manifest",
            "commands_attempted": [
                {
                    "command": "forge test --match-test testReady",
                    "status": "pass",
                    "exit_code": 0,
                }
            ],
        },
    )


if __name__ == "__main__":
    unittest.main()
