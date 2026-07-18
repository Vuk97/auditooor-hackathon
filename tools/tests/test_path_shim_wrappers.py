"""Tests for PATH-shim wrappers (PR #658 commit 8).

Wave-6 E-2 backward compat: setUp helpers write a fresh .auditooor/last_mcp_recall.json
and expose AUDITOOOR_WS_ROOT so the freshness gate passes, allowing the existing
token-gate tests to exercise the token behavior as originally designed.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
GIT_WRAPPER = REPO / "tools" / "auditooor-git-wrapper.sh"
GH_WRAPPER = REPO / "tools" / "auditooor-gh-wrapper.sh"
INSTALL = REPO / "tools" / "install-wrappers.sh"
TOKEN_TOOL = REPO / "tools" / "auditooor_mcp_token.py"


def _write_fresh_recall(workspace: str) -> None:
    """Wave-6 E-2: write a fresh .auditooor/last_mcp_recall.json so the freshness
    gate passes and existing token-gate tests continue to exercise token behavior."""
    sentinel_dir = pathlib.Path(workspace) / ".auditooor"
    sentinel_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "context_pack_id": "test.pack.v1:resume:compat",
        "context_pack_hash": "compat_hash",
        "workspace_path": workspace,
        "recall_ts": time.time(),
        "recall_iso": "2026-05-11T00:00:00Z",
        "owner_tool": "TEST_COMPAT",
    }
    (sentinel_dir / "last_mcp_recall.json").write_text(json.dumps(data, indent=2))


def _issue_token(workspace, scope="write", ttl=14400):
    """Helper: issue a fresh token for tests."""
    proc = subprocess.run(
        ["python3", str(TOKEN_TOOL), "issue",
         "--workspace", workspace, "--scope", scope, "--ttl", str(ttl), "--no-log"],
        capture_output=True, text=True,
        env={**os.environ, "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content"},
    )
    return proc.stdout.strip()


def _make_fake_git(tmp_dir):
    """Creates a fake git binary that just prints args + writes to a marker file."""
    fake = pathlib.Path(tmp_dir) / "fake-git"
    marker = pathlib.Path(tmp_dir) / "fake-git-called"
    fake.write_text(f'''#!/usr/bin/env bash
echo "FAKE-GIT: $@" > "{marker}"
echo "fake git was called with: $@"
''')
    fake.chmod(0o755)
    return str(fake), marker


class TestGitWrapper(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = "test-shim-secret-32-bytes-content"
        self.tmp = tempfile.mkdtemp()
        # Make tmp a git repo so wrapper can find toplevel
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)
        self.fake_git, self.marker = _make_fake_git(self.tmp)
        # Wave-6 E-2: provide a fresh recall sentinel so the freshness gate passes
        # and these tests continue to exercise token behavior as originally designed.
        _write_fresh_recall(self.tmp)
        # Override real git via env
        self.env = {**os.environ,
                    "AUDITOOOR_REAL_GIT": self.fake_git,
                    "AUDITOOOR_WORKSPACE": str(pathlib.Path(self.tmp).resolve()),
                    "AUDITOOOR_WS_ROOT": str(pathlib.Path(self.tmp).resolve())}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_passthrough_for_read_only_subcommand(self):
        # `git log` should pass through without token
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(GIT_WRAPPER), "log", "--oneline"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file(), "fake git should have been called")
        self.assertIn("log", self.marker.read_text())

    def test_blocked_without_token_on_commit(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(GIT_WRAPPER), "commit", "-m", "test"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)
        self.assertFalse(self.marker.is_file(), "fake git should NOT have been called")

    def test_passes_with_valid_token_on_commit(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.env, "AUDITOOOR_MCP_SESSION_TOKEN": token}
        proc = subprocess.run(
            ["bash", str(GIT_WRAPPER), "commit", "-m", "test"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertTrue(self.marker.is_file())

    def test_blocked_with_wrong_scope(self):
        # Token has only `read` scope; commit needs `write`
        token = _issue_token(self.tmp, scope="read")
        env = {**self.env, "AUDITOOOR_MCP_SESSION_TOKEN": token}
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(GIT_WRAPPER), "push"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(self.marker.is_file())

    def test_bypass_logged_when_required_zero(self):
        env = {**self.env, "AUDITOOOR_MCP_REQUIRED": "0"}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(GIT_WRAPPER), "commit", "-m", "test"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        bypass_log = pathlib.Path(self.tmp) / ".auditooor" / "bypass_log.jsonl"
        self.assertTrue(bypass_log.is_file(), "bypass log should be created")
        content = bypass_log.read_text()
        self.assertIn("git-wrapper", content)
        self.assertIn("commit", content)
        self.assertIn("AUDITOOOR_MCP_REQUIRED=0", content)

    def test_inline_mcp_token_flag(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(GIT_WRAPPER), f"--mcp-token={token}", "commit", "-m", "test"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file())
        # Verify --mcp-token=... is stripped before exec
        self.assertNotIn("--mcp-token", self.marker.read_text())


class TestInstallWrappers(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = "test-shim-secret-32-bytes-content"
        self.tmp = tempfile.mkdtemp()
        self.bin_dir = pathlib.Path(self.tmp) / "bin"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_install_creates_symlinks(self):
        env = {**os.environ, "AUDITOOOR_BIN_DIR": str(self.bin_dir)}
        proc = subprocess.run(
            ["bash", str(INSTALL), "install"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertTrue((self.bin_dir / "git").is_symlink())
        self.assertTrue((self.bin_dir / "gh").is_symlink())

    def test_uninstall_removes_symlinks(self):
        env = {**os.environ, "AUDITOOOR_BIN_DIR": str(self.bin_dir)}
        subprocess.run(["bash", str(INSTALL), "install"], capture_output=True, env=env)
        proc = subprocess.run(
            ["bash", str(INSTALL), "uninstall"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertFalse((self.bin_dir / "git").exists())

    def test_install_idempotent(self):
        env = {**os.environ, "AUDITOOOR_BIN_DIR": str(self.bin_dir)}
        subprocess.run(["bash", str(INSTALL), "install"], capture_output=True, env=env)
        proc = subprocess.run(["bash", str(INSTALL), "install"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("[unchanged]", proc.stdout)


if __name__ == "__main__":
    unittest.main()
