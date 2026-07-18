from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.control.handoff import render_handoff
from tools.control.next_actions import rank_next_actions


class ControlHandoffTest(unittest.TestCase):
    def test_handoff_renders_concise_markdown_without_unrelated_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "sample-audit"
            ws.mkdir()
            status = {
                "stage": "scan-partial",
                "blockers": [f"manual note in {ws}/notes/private.md", "/Users/operator/secret.txt"],
                "artifacts": {
                    "SCOPE.md": True,
                    "OOS.md": False,
                    "SEVERITY.md": True,
                    "RUBRIC_COVERAGE.md": True,
                    ".auditooor/semantic_graph.json": False,
                },
            }
            candidates = [
                {
                    "id": "C-7",
                    "severity": "Medium",
                    "status": "draft",
                    "oos_checked": False,
                    "inline_poc": True,
                    "test_output": False,
                    "draft_path": str(ws / "submissions" / "C-7.md"),
                }
            ]
            runs = [
                {
                    "name": "audit-deep",
                    "state": "partial",
                    "artifact": "/private/other/audit-deep.log",
                }
            ]
            actions = rank_next_actions(ws, status, candidates, runs)
            markdown = render_handoff(ws, status, candidates, runs, actions)
            self.assertIn("# Auditooor Handoff: sample-audit", markdown)
            self.assertIn("Audience: claude", markdown)
            self.assertIn("Workspace: " + str(ws), markdown)
            self.assertIn("C-7: Medium, draft; missing OOS, test output", markdown)
            self.assertIn("## Next Actions", markdown)
            self.assertIn("Boundary:", markdown)
            self.assertIn("<workspace>/notes/private.md", markdown)
            self.assertNotIn(str(ws / "submissions" / "C-7.md"), markdown)
            self.assertNotIn("/Users/operator/secret.txt", markdown)
            self.assertNotIn("/private/other/audit-deep.log", markdown)

    def test_handoff_handles_empty_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            markdown = render_handoff(ws, {}, [], [], [])
            self.assertIn("Stage: unknown", markdown)
            self.assertIn("- none recorded", markdown)
            self.assertIn("- none ranked", markdown)


if __name__ == "__main__":
    unittest.main()
