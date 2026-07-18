#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.state import SCHEMA, collect_state, write_state


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ControlStateTests(unittest.TestCase):
    def test_collect_state_combines_status_candidates_runs_and_actions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            ws.mkdir()
            _write(ws / "SCOPE.md", "# Scope\nsrc only\n")
            _write(ws / "OOS_PASTED.md", "# OOS\nfrontend\n")
            _write(ws / "SEVERITY.md", "# Severity\nMedium: pool liveness\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nmapped\n")
            _write(ws / ".auditooor" / "semantic_graph.json", "{}\n")
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
                    "dispatch_source": "vault://NEXT_LOOP.md#G8-001",
                    "source_manifest": "obsidian-vault/dispatch/next_dispatch_manifest.json",
                    "terminal_artifact": "https://github.com/Vuk97/auditooor/pull/605",
                    "changed_files": ["docs/TASK_FINALIZATION_LEDGER.md"],
                    "verification": {
                        "commands": [{"command": "make task-finalization-test", "exit_code": 0}],
                        "passed": True,
                    },
                    "open_followups": [],
                    "docs_updated": True,
                    "readme_updated": False,
                    "frontdoor_updated": False,
                    "outcome_or_calibration_updated": False,
                    "memory_updates": ["docs/TASK_FINALIZATION_LEDGER.md"],
                    "blocked_by": None,
                    "closed_at": "2026-05-05T00:00:00+00:00",
                }) + "\n",
            )
            _write(
                ws / ".auditooor" / "control" / "candidates" / "amp-zero.json",
                json.dumps(
                    {
                        "id": "amp-zero",
                        "title": "zero amp blocks swaps",
                        "status": "candidate",
                        "severity": "Medium",
                        "impact": "pool liveness failure",
                    }
                ),
            )
            _write(
                ws / "poc_execution" / "amp-zero" / "execution_manifest.json",
                json.dumps(
                    {
                        "candidate_id": "amp-zero",
                        "final_result": "blocked_path",
                        "impact_assertion": "not_demonstrated",
                    }
                ),
            )

            snapshot = collect_state(ws)

        self.assertEqual(snapshot["schema"], SCHEMA)
        self.assertEqual(snapshot["status"]["schema"], "auditooor.control.status.v1")
        self.assertEqual(snapshot["status"]["artifacts"]["task_finalization_ledger"]["row_count"], 1)
        self.assertEqual(
            snapshot["status"]["artifacts"]["task_finalization_ledger"]["status_counts"]["landed"],
            1,
        )
        self.assertEqual(snapshot["candidates"][0]["id"], "amp-zero")
        self.assertIn("missing_likelihood", snapshot["candidates"][0]["paste_ready_blockers"])
        self.assertIn("missing_inline_poc", snapshot["candidates"][0]["paste_ready_blockers"])
        self.assertEqual(snapshot["runs"]["counts_by_execution_state"], {"blocked": 1})
        reasons = [row["reason"] for row in snapshot["next_actions"]]
        self.assertIn("candidate amp-zero is missing per-finding OOS clearance", reasons)
        self.assertIn("candidate amp-zero is missing an inline PoC", reasons)

    def test_write_state_requires_explicit_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "state" / "snapshot.json"
            path = write_state({"schema": SCHEMA, "workspace": "demo"}, out)

            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema"], SCHEMA)
        self.assertEqual(path.name, "snapshot.json")


if __name__ == "__main__":
    unittest.main()
