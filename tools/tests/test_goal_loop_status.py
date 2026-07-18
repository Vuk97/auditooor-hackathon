from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_module():
    spec = importlib.util.spec_from_file_location("goal_loop_status", TOOLS / "goal-loop-status.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


goal_loop_status = _load_module()


class GoalLoopStatusTests(unittest.TestCase):
    def test_goal_policy_keeps_global_loop_open(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            status = goal_loop_status.build_status(root)

        self.assertEqual(status["goal_policy"]["status"], "active_continuous_loop")
        self.assertFalse(status["goal_policy"]["terminal_completion_allowed"])
        self.assertEqual(status["goal_policy"]["loop_back_phase"], "recall_memory")
        self.assertEqual(status["loop_phases"][-1], "loop_back_to_recall_memory")

    def test_artifact_coverage_records_present_and_missing_memory_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "docs").mkdir()
            (root / "reports").mkdir()
            (root / "docs" / "CURRENT_STATE.md").write_text("# state\n", encoding="utf-8")
            (root / "reports" / "scanner_wiring_truth_inventory_2026-05-05.json").write_text(
                json.dumps({"items": [{"scanner_id": "s1"}]}),
                encoding="utf-8",
            )

            status = goal_loop_status.build_status(root)

        coverage = status["artifact_coverage"]
        self.assertGreaterEqual(coverage["present_count"], 2)
        self.assertIn("docs/CURRENT_STATE.md", coverage["present_paths"])
        self.assertIn(
            "reports/known_limitations_burndown_queue_2026-05-05.json",
            coverage["missing_paths"],
        )
        scanner_signal = {
            row["queue"]: row for row in status["queue_signals"]
        }["scanner_truth"]
        self.assertEqual(scanner_signal["item_count"], 1)
        self.assertTrue(scanner_signal["usable_for_dispatch"])

    def test_markdown_renders_handoff_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            status = goal_loop_status.build_status(Path(td))

        md = goal_loop_status.render_markdown(status)

        self.assertIn("Goal Loop Status", md)
        self.assertIn("controlled_new_audit_workspace", md)
        self.assertIn("200-250+", md)

    def test_latest_queue_report_is_used_when_default_filename_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "docs").mkdir()
            (root / "reports").mkdir()
            (root / "docs" / "CURRENT_STATE.md").write_text("# state\n", encoding="utf-8")
            (root / "docs" / "TOOL_STATUS.md").write_text("# tools\n", encoding="utf-8")
            (root / "reports" / "known_limitations_burndown_queue_2026-05-06.json").write_text(
                json.dumps({"rows": [{"id": "KLBQ-001"}]}),
                encoding="utf-8",
            )
            (root / "reports" / "scanner_wiring_truth_inventory_2026-05-06.json").write_text(
                json.dumps({"items": [{"scanner_id": "s1"}]}),
                encoding="utf-8",
            )

            status = goal_loop_status.build_status(root)

        coverage = status["artifact_coverage"]
        self.assertIn("reports/known_limitations_burndown_queue_2026-05-06.json", coverage["present_paths"])
        self.assertNotIn("reports/known_limitations_burndown_queue_2026-05-05.json", coverage["missing_paths"])
        scanner_signal = {row["queue"]: row for row in status["queue_signals"]}["scanner_truth"]
        self.assertEqual(scanner_signal["source_path"], "reports/scanner_wiring_truth_inventory_2026-05-06.json")
        self.assertEqual(scanner_signal["item_count"], 1)
        self.assertTrue(scanner_signal["usable_for_dispatch"])


if __name__ == "__main__":
    unittest.main()
