"""Tests for readme-render.py (PR #658 commit 6)."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "readme-render.py"
sys.path.insert(0, str(REPO / "tools"))

import importlib.util
spec = importlib.util.spec_from_file_location("readme_render", TOOL)
readme_render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readme_render)


class TestReadmeRender(unittest.TestCase):
    def test_render_status_block_returns_string(self):
        # Should not crash even with no gh / vault / outcomes
        content = readme_render.render_status_block()
        self.assertIsInstance(content, str)
        self.assertIn("GitHub PRs", content)
        self.assertIn("Vault freshness", content)
        self.assertIn("Filed-finding outcomes", content)

    def test_render_includes_active_l_rules_reference(self):
        content = readme_render.render_status_block()
        self.assertIn("CODIFIED_DISCIPLINE_RULES", content)

    def test_render_includes_attacker_frames_reference(self):
        content = readme_render.render_status_block()
        self.assertIn("attacker mental frames", content.lower())
        self.assertIn("AMF-001", content)

    def test_outcomes_summary_handles_real_ledger(self):
        result = readme_render._outcomes_summary()
        # Real ledger should have rows and not crash
        if "error" not in result:
            self.assertIn("total_rows", result)
            self.assertIsInstance(result["by_status"], dict)
            self.assertIsInstance(result["by_workspace"], dict)

    def test_status_doc_writeable(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = pathlib.Path(tmp) / "status.md"
            # Patch STATUS_DOC
            original = readme_render.STATUS_DOC
            try:
                readme_render.STATUS_DOC = tmp_p
                content = "test content"
                path = readme_render.write_status_doc(content)
                self.assertEqual(path, tmp_p)
                self.assertTrue(tmp_p.is_file())
                self.assertIn("test content", tmp_p.read_text())
                self.assertIn("Auditooor — Current Status", tmp_p.read_text())
            finally:
                readme_render.STATUS_DOC = original

    def test_update_readme_idempotent_when_no_markers(self):
        # If README has no markers, update_readme returns False
        with tempfile.TemporaryDirectory() as tmp:
            tmp_readme = pathlib.Path(tmp) / "README.md"
            tmp_readme.write_text("# README\n\nNo markers here.\n")
            original = readme_render.README
            try:
                readme_render.README = tmp_readme
                result = readme_render.update_readme("new content")
                self.assertFalse(result)
                self.assertIn("No markers here", tmp_readme.read_text())
            finally:
                readme_render.README = original

    def test_update_readme_replaces_marker_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_readme = pathlib.Path(tmp) / "README.md"
            tmp_readme.write_text(
                "# Title\n\n"
                + readme_render.MARKER_START + "\n"
                "OLD CONTENT\n"
                + readme_render.MARKER_END + "\n"
                "## Other section\n"
            )
            original = readme_render.README
            try:
                readme_render.README = tmp_readme
                result = readme_render.update_readme("NEW CONTENT")
                self.assertTrue(result)
                final = tmp_readme.read_text()
                self.assertIn("NEW CONTENT", final)
                self.assertNotIn("OLD CONTENT", final)
                self.assertIn("Other section", final)  # preserved
            finally:
                readme_render.README = original


class TestReadmeRenderCLI(unittest.TestCase):
    def test_cli_default_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Just verify CLI doesn't crash
            proc = subprocess.run(
                ["python3", str(TOOL), "--no-status-doc", "--quiet"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)

    def test_cli_check_mode(self):
        # --check should exit 0 or 1 cleanly
        proc = subprocess.run(
            ["python3", str(TOOL), "--check"],
            capture_output=True, text=True,
        )
        self.assertIn(proc.returncode, (0, 1))


if __name__ == "__main__":
    unittest.main()
