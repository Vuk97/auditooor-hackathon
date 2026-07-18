from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.control.next_actions import rank_next_actions


class ControlNextActionsTest(unittest.TestCase):
    def test_ranks_intake_and_workspace_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            status = {
                "artifacts": {
                    "SCOPE.md": False,
                    "OOS.md": False,
                    "SEVERITY.md": False,
                    "RUBRIC_COVERAGE.md": False,
                    ".auditooor/semantic_graph.json": False,
                },
                "high_impact_workspace": True,
                "rust_workspace": True,
                "audit_deep": {"state": "partial"},
            }
            rows = rank_next_actions(ws, status)
            reasons = [row["reason"] for row in rows]
            self.assertIn("scope text is missing", reasons)
            self.assertIn("OOS text is missing", reasons)
            self.assertIn("severity rubric is missing", reasons)
            self.assertIn("rubric coverage is missing", reasons)
            self.assertIn("semantic graph is missing", reasons)
            self.assertIn("high-impact workspace is missing an invariant ledger", reasons)
            self.assertIn(
                "Rust/DLT workspace is missing the canonical Rust scan summary",
                reasons,
            )
            self.assertIn("audit-deep has partial, blocked, or skipped execution lanes", reasons)
            self.assertEqual([row["priority"] for row in rows], sorted(row["priority"] for row in rows))
            for row in rows:
                self.assertEqual(
                    set(row),
                    {
                        "priority",
                        "reason",
                        "command",
                        "artifact",
                        "stop_condition",
                        "proof_boundary",
                    },
                )

    def test_candidate_missing_submission_gates_produce_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("scope\n", encoding="utf-8")
            (ws / "OOS.md").write_text("oos\n", encoding="utf-8")
            (ws / "SEVERITY.md").write_text("severity\n", encoding="utf-8")
            (ws / "RUBRIC_COVERAGE.md").write_text("coverage\n", encoding="utf-8")
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "semantic_graph.json").write_text("{}", encoding="utf-8")
            candidates = [
                {
                    "id": "C-1",
                    "severity": "High",
                    "draft_path": str(ws / "submissions" / "draft.md"),
                    "oos_checked": False,
                    "inline_poc": False,
                    "test_output": False,
                }
            ]
            rows = rank_next_actions(ws, {"high_impact_workspace": False}, candidates)
            reasons = [row["reason"] for row in rows]
            self.assertIn("candidate C-1 is missing per-finding OOS clearance", reasons)
            self.assertIn("candidate C-1 is missing an inline PoC", reasons)
            self.assertIn("candidate C-1 is missing executed test output", reasons)
            self.assertTrue(any("per-finding-oos-check.py" in row["command"] for row in rows))
            self.assertTrue(any("poc-execution-record" in row["command"] for row in rows))

    def test_no_blockers_returns_mining_priority_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            for name in ("SCOPE.md", "OOS_PASTED.md", "SEVERITY.md", "RUBRIC_COVERAGE.md"):
                (ws / name).write_text("ok\n", encoding="utf-8")
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "semantic_graph.json").write_text("{}", encoding="utf-8")
            rows = rank_next_actions(ws, {"high_impact_workspace": False})
            self.assertEqual(len(rows), 1)
            self.assertEqual(
                rows[0]["reason"],
                "no structural blockers detected in the supplied status packet",
            )


if __name__ == "__main__":
    unittest.main()

