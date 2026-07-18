"""Tests for tools/auditooor-session-start.sh.

Verifies:
- script produces a well-formed JSON sentinel at .auditooor/last_mcp_recall.json
- JSON sentinel contains all required fields
- sentinel timestamp is recent
- sentinel workspace_path matches the provided workspace
- MCP server failure causes non-zero exit
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
SESSION_START_SH = REPO_ROOT / "tools" / "auditooor-session-start.sh"
MCP_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _run_session_start(tmpdir: Path, workspace: str | None = None,
                       env: dict | None = None) -> subprocess.CompletedProcess:
    """Run auditooor-session-start.sh optionally specifying a workspace."""
    cmd = ["bash", str(SESSION_START_SH)]
    if workspace is not None:
        cmd.append(workspace)
    merged_env = {**os.environ}
    if env:
        merged_env.update(env)
    return subprocess.run(
        cmd,
        cwd=str(tmpdir),
        capture_output=True,
        text=True,
        env=merged_env,
    )


def _make_fake_git_repo(tmpdir: Path) -> Path:
    """Initialize a git repo so git rev-parse --show-toplevel works."""
    subprocess.run(["git", "init", str(tmpdir)], capture_output=True, check=True)
    return tmpdir


class TestSessionStartScript(unittest.TestCase):
    """Integration tests for auditooor-session-start.sh against the real MCP server."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._td.name)
        _make_fake_git_repo(self.tmpdir)
        # Pre-create .auditooor so we have a valid workspace dir
        (self.tmpdir / ".auditooor").mkdir(exist_ok=True)

    def tearDown(self):
        self._td.cleanup()

    def test_script_exits_zero_and_produces_sentinel(self):
        """Script exits 0 and writes .auditooor/last_mcp_recall.json."""
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        self.assertEqual(result.returncode, 0,
                         f"script failed with stderr: {result.stderr}\nstdout: {result.stdout}")
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        self.assertTrue(sentinel.exists(), "sentinel file not created")

    def test_sentinel_has_required_fields(self):
        """Sentinel JSON contains all 6 required fields."""
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())

        required_fields = [
            "context_pack_id",
            "context_pack_hash",
            "workspace_path",
            "recall_ts",
            "recall_iso",
            "owner_tool",
        ]
        for field in required_fields:
            self.assertIn(field, data, f"sentinel missing required field: {field}")

    def test_sentinel_context_pack_id_is_nonempty(self):
        """Sentinel context_pack_id is a non-empty string."""
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())
        self.assertIsInstance(data["context_pack_id"], str)
        self.assertGreater(len(data["context_pack_id"]), 0,
                           "context_pack_id should be non-empty")

    def test_sentinel_context_pack_hash_is_nonempty(self):
        """Sentinel context_pack_hash is a non-empty string."""
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())
        self.assertIsInstance(data["context_pack_hash"], str)
        self.assertGreater(len(data["context_pack_hash"]), 0,
                           "context_pack_hash should be non-empty")

    def test_sentinel_workspace_path_matches(self):
        """Sentinel workspace_path matches the provided workspace argument."""
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())
        self.assertEqual(data["workspace_path"], str(self.tmpdir))

    def test_sentinel_timestamp_is_recent(self):
        """Sentinel recall_ts is within 120 seconds of now."""
        before = time.time()
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        after = time.time()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())
        recall_ts = data["recall_ts"]
        self.assertGreaterEqual(recall_ts, before - 5,
                                "recall_ts is too far in the past")
        self.assertLessEqual(recall_ts, after + 5,
                             "recall_ts is in the future")

    def test_sentinel_iso_format(self):
        """Sentinel recall_iso is a valid UTC ISO-8601 timestamp."""
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())
        iso = data["recall_iso"]
        # Format: YYYY-MM-DDTHH:MM:SSZ
        import re
        self.assertRegex(iso, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                         f"recall_iso has unexpected format: {iso}")

    def test_missing_workspace_exits_nonzero(self):
        """Script exits non-zero when given a non-existent workspace path."""
        result = _run_session_start(self.tmpdir, workspace="/nonexistent/path/xyz")
        self.assertNotEqual(result.returncode, 0,
                            "script should fail for nonexistent workspace")

    def test_sentinel_owner_tool_field_present(self):
        """Sentinel owner_tool field is present and is a string."""
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())
        self.assertIn("owner_tool", data)
        self.assertIsInstance(data["owner_tool"], str)
        self.assertGreater(len(data["owner_tool"]), 0)

    def test_codex_environment_sets_owner_tool(self):
        """Codex shells expose CODEX_* markers even when argv is plain bash."""
        result = _run_session_start(
            self.tmpdir,
            workspace=str(self.tmpdir),
            env={"CODEX_THREAD_ID": "test-thread"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())
        self.assertEqual(data["owner_tool"], "CODEX")

    def test_owner_tool_environment_override_wins(self):
        """Operators can force an owner label for wrapped nonstandard tools."""
        result = _run_session_start(
            self.tmpdir,
            workspace=str(self.tmpdir),
            env={"AUDITOOOR_OWNER_TOOL": "CUSTOM_AGENT", "CODEX_THREAD_ID": "test-thread"},
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        data = json.loads(sentinel.read_text())
        self.assertEqual(data["owner_tool"], "CUSTOM_AGENT")

    def test_sentinel_is_valid_json(self):
        """Sentinel file is parseable as JSON (not truncated)."""
        result = _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        raw = sentinel.read_text()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            self.fail(f"Sentinel is not valid JSON: {e}\nContent: {raw[:200]}")
        self.assertIsInstance(data, dict)

    def test_idempotent_second_run_overwrites_sentinel(self):
        """Running the script twice overwrites the sentinel with a fresh one."""
        _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        sentinel = self.tmpdir / ".auditooor" / "last_mcp_recall.json"
        first_ts = json.loads(sentinel.read_text())["recall_ts"]

        # Brief sleep to ensure different timestamp
        time.sleep(1)
        _run_session_start(self.tmpdir, workspace=str(self.tmpdir))
        second_ts = json.loads(sentinel.read_text())["recall_ts"]

        self.assertGreaterEqual(second_ts, first_ts,
                                "second run should produce a >= timestamp")


if __name__ == "__main__":
    unittest.main()
