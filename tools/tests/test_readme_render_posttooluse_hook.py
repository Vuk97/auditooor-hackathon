"""Tests for tools/hooks/readme-render-posttooluse.sh.

Coverage:
  1. bash -n syntax check
  2. tool_name=Read → exits 0, no render invoked
  3. tool_name=Edit + unrelated file_path → exits 0, no render invoked
  4. tool_name=Edit + tracked dep (outcomes.jsonl) → dry-run shows would-run
  5. tool_name=Write + tracked dep (README.md) → dry-run shows would-run
  6. tool_name=NotebookEdit + tracked dep → dry-run shows would-run
  7. Missing file_path field → exits 0, no render invoked
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
HOOK = REPO / "tools" / "hooks" / "readme-render-posttooluse.sh"

# Tracked deps (absolute paths the hook watches)
OUTCOMES = str(REPO / "reference" / "outcomes.jsonl")
README = str(REPO / "README.md")
UNRELATED = str(REPO / "tools" / "readme-render.py")


def _run_hook(payload: dict, *, dry_run: bool = True) -> subprocess.CompletedProcess:
    """Run the hook with a JSON payload on stdin."""
    env = os.environ.copy()
    if dry_run:
        env["DRY_RUN"] = "1"
    return subprocess.run(
        ["bash", str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
    )


class TestHookSyntax(unittest.TestCase):
    def test_bash_syntax_valid(self):
        """Hook script must pass bash -n (no syntax errors)."""
        result = subprocess.run(
            ["bash", "-n", str(HOOK)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)


class TestHookPassThrough(unittest.TestCase):
    """Cases where hook should exit 0 without running render."""

    def test_read_tool_exits_silently(self):
        """tool_name=Read is not in the trigger set — exits 0, no output."""
        payload = {"tool_name": "Read", "tool_input": {"file_path": OUTCOMES}}
        r = _run_hook(payload)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("would-run", r.stdout)

    def test_unrelated_file_exits_silently(self):
        """tool_name=Edit but file_path is not a tracked dep — exits 0, no render."""
        payload = {"tool_name": "Edit", "tool_input": {"file_path": UNRELATED}}
        r = _run_hook(payload)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("would-run", r.stdout)

    def test_missing_file_path_exits_silently(self):
        """tool_input with no file_path key — exits 0, no render."""
        payload = {"tool_name": "Edit", "tool_input": {}}
        r = _run_hook(payload)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("would-run", r.stdout)

    def test_bash_tool_exits_silently(self):
        """tool_name=Bash — exits 0, no render."""
        payload = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        r = _run_hook(payload)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("would-run", r.stdout)


class TestHookTriggers(unittest.TestCase):
    """Cases where hook should trigger readme-render (dry-run mode)."""

    def test_edit_outcomes_jsonl_triggers_render(self):
        """Edit on reference/outcomes.jsonl must produce would-run output."""
        payload = {"tool_name": "Edit", "tool_input": {"file_path": OUTCOMES}}
        r = _run_hook(payload)
        self.assertEqual(r.returncode, 0)
        self.assertIn("would-run", r.stdout)
        self.assertIn("readme-render.py", r.stdout)

    def test_write_readme_triggers_render(self):
        """Write on README.md must produce would-run output."""
        payload = {"tool_name": "Write", "tool_input": {"file_path": README}}
        r = _run_hook(payload)
        self.assertEqual(r.returncode, 0)
        self.assertIn("would-run", r.stdout)
        self.assertIn("readme-render.py", r.stdout)

    def test_notebookedit_outcomes_triggers_render(self):
        """NotebookEdit on outcomes.jsonl must produce would-run output."""
        payload = {"tool_name": "NotebookEdit", "tool_input": {"file_path": OUTCOMES}}
        r = _run_hook(payload)
        self.assertEqual(r.returncode, 0)
        self.assertIn("would-run", r.stdout)


class TestHookAlwaysExitsZero(unittest.TestCase):
    """Hook must be advisory — never return non-zero."""

    def test_malformed_json_exits_zero(self):
        """Even completely malformed stdin must not cause a non-zero exit."""
        result = subprocess.run(
            ["bash", str(HOOK)],
            input="NOT JSON AT ALL",
            capture_output=True,
            text=True,
            env={**os.environ, "DRY_RUN": "1"},
        )
        self.assertEqual(result.returncode, 0)

    def test_empty_stdin_exits_zero(self):
        """Empty stdin — exits 0."""
        result = subprocess.run(
            ["bash", str(HOOK)],
            input="",
            capture_output=True,
            text=True,
            env={**os.environ, "DRY_RUN": "1"},
        )
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
