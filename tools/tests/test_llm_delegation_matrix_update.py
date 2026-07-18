"""Tests for llm-delegation-matrix-update.py (PR #658 deferred item #2)."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "llm-delegation-matrix-update.py"
sys.path.insert(0, str(REPO / "tools"))

import importlib.util
spec = importlib.util.spec_from_file_location("llm_delegation_matrix_update", TOOL)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


SAMPLE_ROWS = [
    {"provider": "kimi", "task_type": "pr-review", "verdict": "TRUE", "ts": "2026-04-22T10:00:00Z"},
    {"provider": "kimi", "task_type": "pr-review", "verdict": "TRUE", "ts": "2026-04-22T10:05:00Z"},
    {"provider": "kimi", "task_type": "pr-review", "verdict": "FALSE", "ts": "2026-04-22T11:00:00Z"},
    {"provider": "minimax", "task_type": "adversarial-kill", "verdict": "TRUE", "ts": "2026-05-01T10:00:00Z"},
]


class TestAggregate(unittest.TestCase):
    def test_aggregate_counts(self):
        stats = mod.aggregate(SAMPLE_ROWS)
        kimi = stats[("kimi", "pr-review")]
        self.assertEqual(kimi["total"], 3)
        self.assertEqual(kimi["true"], 2)
        self.assertEqual(kimi["false"], 1)
        minimax = stats[("minimax", "adversarial-kill")]
        self.assertEqual(minimax["total"], 1)

    def test_other_verdict_classified(self):
        rows = [{"provider": "claude", "task_type": "x", "verdict": "PENDING", "ts": "2026-01-01T00:00:00Z"}]
        stats = mod.aggregate(rows)
        self.assertEqual(stats[("claude", "x")]["other"], 1)


class TestRenderTable(unittest.TestCase):
    def test_empty_stats(self):
        result = mod.render_table({})
        self.assertIn("calibration log empty", result)

    def test_table_columns_present(self):
        stats = mod.aggregate(SAMPLE_ROWS)
        table = mod.render_table(stats)
        for col in ["Provider", "Task type", "Total", "TP-rate", "Recommended", "Last seen"]:
            self.assertIn(col, table)

    def test_recommended_marker(self):
        # 10 TRUE + 1 FALSE = 91% TP, n=11 decided -> ✓
        rows = [{"provider": "kimi", "task_type": "x", "verdict": "TRUE", "ts": "2026-01-01T00:00:00Z"}] * 10
        rows.append({"provider": "kimi", "task_type": "x", "verdict": "FALSE", "ts": "2026-01-01T00:00:00Z"})
        stats = mod.aggregate(rows)
        table = mod.render_table(stats)
        self.assertIn("✓", table)

    def test_low_rate_no_recommended(self):
        rows = [{"provider": "kimi", "task_type": "x", "verdict": "FALSE", "ts": "2026-01-01T00:00:00Z"}] * 10
        rows.append({"provider": "kimi", "task_type": "x", "verdict": "TRUE", "ts": "2026-01-01T00:00:00Z"})
        stats = mod.aggregate(rows)
        table = mod.render_table(stats)
        # Should NOT have ✓ since TP-rate is ~9%
        # Check for the recommended column being empty
        lines = table.split("\n")
        data_line = [l for l in lines if "kimi" in l and "x" in l][0]
        # The Recommended column is the 8th cell (between two |)
        cells = [c.strip() for c in data_line.split("|")]
        # Recommended is index 8 (0-indexed: empty, Provider, Task type, Total, TP, FP, Other, TP-rate, Recommended, Last)
        self.assertNotEqual(cells[8], "✓")


class TestCLI(unittest.TestCase):
    def test_dry_run_does_not_modify(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_doc = pathlib.Path(tmp) / "matrix.md"
            tmp_doc.write_text("# Matrix\n\n<!-- AUDITOOOR_AUTO:delegation-matrix-table -->\nold content\n<!-- /AUDITOOOR_AUTO:delegation-matrix-table -->\n")
            original = mod.DOC_PATH
            try:
                mod.DOC_PATH = tmp_doc
                changed, reason = mod.update_doc("new content", dry_run=True)
                # File unchanged
                self.assertIn("old content", tmp_doc.read_text())
            finally:
                mod.DOC_PATH = original

    def test_no_markers_no_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_doc = pathlib.Path(tmp) / "matrix.md"
            tmp_doc.write_text("# Matrix\n\nNo markers here.\n")
            original = mod.DOC_PATH
            try:
                mod.DOC_PATH = tmp_doc
                changed, reason = mod.update_doc("new content")
                self.assertFalse(changed)
                self.assertIn("markers not present", reason)
            finally:
                mod.DOC_PATH = original

    def test_update_replaces_marker_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_doc = pathlib.Path(tmp) / "matrix.md"
            tmp_doc.write_text(
                "# Matrix\n\n<!-- AUDITOOOR_AUTO:delegation-matrix-table -->\n"
                "OLD\n<!-- /AUDITOOOR_AUTO:delegation-matrix-table -->\n"
                "## Other section\n"
            )
            original = mod.DOC_PATH
            try:
                mod.DOC_PATH = tmp_doc
                changed, reason = mod.update_doc("NEW TABLE CONTENT")
                self.assertTrue(changed)
                final = tmp_doc.read_text()
                self.assertIn("NEW TABLE CONTENT", final)
                self.assertNotIn("\nOLD\n", final)
                self.assertIn("Other section", final)  # outside markers preserved
            finally:
                mod.DOC_PATH = original

    def test_cli_runs_against_real_calibration_log(self):
        proc = subprocess.run(
            ["python3", str(TOOL), "--dry-run"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("calibration rows", proc.stdout)


if __name__ == "__main__":
    unittest.main()
