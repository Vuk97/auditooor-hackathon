"""Tests for codex/kimi/forge MCP-gated wrappers (PR #658 Tier-A item #4).

Wave-6 E-2 backward compat: setUp helpers write a fresh .auditooor/last_mcp_recall.json
and expose AUDITOOOR_WS_ROOT so the freshness gate passes, allowing the existing
token-gate tests to exercise the token behavior as before.
"""
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
CODEX_WRAPPER = REPO / "tools" / "auditooor-codex-wrapper.sh"
KIMI_WRAPPER = REPO / "tools" / "auditooor-kimi-wrapper.sh"
FORGE_WRAPPER = REPO / "tools" / "auditooor-forge-wrapper.sh"
TOKEN_TOOL = REPO / "tools" / "auditooor_mcp_token.py"


def _issue_token(workspace, scope="write", ttl=14400):
    """Helper: issue a fresh token for tests."""
    proc = subprocess.run(
        ["python3", str(TOKEN_TOOL), "issue",
         "--workspace", workspace, "--scope", scope, "--ttl", str(ttl), "--no-log"],
        capture_output=True, text=True,
        env={**os.environ, "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content"},
    )
    return proc.stdout.strip()


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


def _make_fake_bin(tmp_dir, name):
    """Creates a fake binary that echoes its args and writes to a marker file."""
    fake = pathlib.Path(tmp_dir) / f"fake-{name}"
    marker = pathlib.Path(tmp_dir) / f"fake-{name}-called"
    fake.write_text(f'''#!/usr/bin/env bash
echo "FAKE-{name.upper()}: $@" > "{marker}"
echo "fake {name} was called with: $@"
''')
    fake.chmod(0o755)
    return str(fake), marker


def _make_named_fake_bin(bin_dir, name):
    """Creates a PATH-discoverable fake binary named exactly like the tool."""
    bin_path = pathlib.Path(bin_dir)
    bin_path.mkdir(parents=True, exist_ok=True)
    fake = bin_path / name
    marker = bin_path / f"{name}-called"
    fake.write_text(f'''#!/usr/bin/env bash
echo "FAKE-{name.upper()}: $@" > "{marker}"
echo "fake {name} was called with: $@"
''')
    fake.chmod(0o755)
    return str(fake), marker


def _base_env(tmp_dir, fake_bin_key):
    """Build a test env with an isolated workspace and fake real binary."""
    return {
        **os.environ,
        "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content",
        "AUDITOOOR_WORKSPACE": str(pathlib.Path(tmp_dir).resolve()),
        fake_bin_key: "",  # will be set per-test
    }


class TestBashSyntax(unittest.TestCase):
    """Bash -n syntax check for all three wrappers."""

    def _check(self, wrapper):
        proc = subprocess.run(
            ["bash", "-n", str(wrapper)],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0,
                         f"{wrapper.name} bash -n failed:\n{proc.stderr}")

    def test_codex_wrapper_syntax(self):
        self._check(CODEX_WRAPPER)

    def test_kimi_wrapper_syntax(self):
        self._check(KIMI_WRAPPER)

    def test_forge_wrapper_syntax(self):
        self._check(FORGE_WRAPPER)


class TestRealBinaryDiscovery(unittest.TestCase):
    """Regression coverage for wrapper-first PATH layouts.

    The real binary resolver must skip the auditooor shim itself and still find
    valid user-local or later-PATH installs without requiring AUDITOOOR_REAL_*.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.workspace = pathlib.Path(self.tmp) / "workspace"
        self.workspace.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.workspace, check=True)
        _write_fresh_recall(str(self.workspace))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _env(self, home, path):
        env = {
            **os.environ,
            "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content",
            "AUDITOOOR_WORKSPACE": str(self.workspace.resolve()),
            "AUDITOOOR_WS_ROOT": str(self.workspace.resolve()),
            "HOME": str(pathlib.Path(home).resolve()),
            "PATH": path,
        }
        env.pop("AUDITOOOR_REAL_CODEX", None)
        env.pop("AUDITOOOR_REAL_KIMI", None)
        env.pop("AUDITOOOR_REAL_FORGE", None)
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        return env

    def _shim_first_path(self, tool, wrapper, real_bin_dir):
        shim_dir = pathlib.Path(self.tmp) / f"shim-{tool}"
        shim_dir.mkdir()
        (shim_dir / tool).symlink_to(wrapper)
        return f"{shim_dir}:{real_bin_dir}:{os.environ.get('PATH', '')}"

    def test_kimi_discovers_home_local_bin_after_wrapper_shim(self):
        home = pathlib.Path(self.tmp) / "home-kimi"
        real_bin, marker = _make_named_fake_bin(home / ".local" / "bin", "kimi")
        env = self._env(home, self._shim_first_path("kimi", KIMI_WRAPPER, pathlib.Path(real_bin).parent))

        proc = subprocess.run(
            ["bash", str(KIMI_WRAPPER), "models", "list"],
            capture_output=True, text=True, env=env, cwd=self.workspace,
        )

        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
        self.assertTrue(marker.is_file(), "home-local kimi should have been called")
        self.assertIn("models", marker.read_text())

    def test_forge_discovers_home_foundry_bin_after_wrapper_shim(self):
        home = pathlib.Path(self.tmp) / "home-forge"
        real_bin, marker = _make_named_fake_bin(home / ".foundry" / "bin", "forge")
        env = self._env(home, self._shim_first_path("forge", FORGE_WRAPPER, pathlib.Path(real_bin).parent))

        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "build"],
            capture_output=True, text=True, env=env, cwd=self.workspace,
        )

        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
        self.assertTrue(marker.is_file(), "home-foundry forge should have been called")
        self.assertIn("build", marker.read_text())

    def test_codex_discovers_home_local_bin_after_wrapper_shim(self):
        home = pathlib.Path(self.tmp) / "home-codex"
        real_bin, marker = _make_named_fake_bin(home / ".local" / "bin", "codex")
        env = self._env(home, self._shim_first_path("codex", CODEX_WRAPPER, pathlib.Path(real_bin).parent))

        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "list"],
            capture_output=True, text=True, env=env, cwd=self.workspace,
        )

        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
        self.assertTrue(marker.is_file(), "home-local codex should have been called")
        self.assertIn("list", marker.read_text())


class TestCodexWrapper(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = "test-shim-secret-32-bytes-content"
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)
        self.fake_bin, self.marker = _make_fake_bin(self.tmp, "codex")
        # Wave-6 E-2: provide a fresh recall sentinel so the freshness gate passes
        # and these tests continue to exercise token behavior as originally designed.
        _write_fresh_recall(self.tmp)
        self.env = {
            **os.environ,
            "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content",
            "AUDITOOOR_REAL_CODEX": self.fake_bin,
            "AUDITOOOR_WORKSPACE": str(pathlib.Path(self.tmp).resolve()),
            "AUDITOOOR_WS_ROOT": str(pathlib.Path(self.tmp).resolve()),
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_passthrough_list_no_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "list"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file(), "fake codex should have been called")
        self.assertIn("list", self.marker.read_text())

    def test_passthrough_status_no_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "status"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file())

    def test_blocked_exec_without_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", "some-task"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)
        self.assertFalse(self.marker.is_file(), "fake codex should NOT have been called")

    def test_blocked_run_without_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "run", "task"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)

    def test_passes_exec_with_valid_token(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.env, "AUDITOOOR_MCP_SESSION_TOKEN": token}
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "exec", "some-task"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertTrue(self.marker.is_file())

    def test_bypass_logged_when_required_zero(self):
        env = {**self.env, "AUDITOOOR_MCP_REQUIRED": "0"}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), "submit", "output.txt"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        bypass_log = pathlib.Path(self.tmp) / ".auditooor" / "bypass_log.jsonl"
        self.assertTrue(bypass_log.is_file(), "bypass log should be created")
        content = bypass_log.read_text()
        self.assertIn("AUDITOOOR_MCP_REQUIRED=0", content)

    def test_inline_mcp_token_flag(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(CODEX_WRAPPER), f"--mcp-token={token}", "exec", "task"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file())
        self.assertNotIn("--mcp-token", self.marker.read_text())


class TestKimiWrapper(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = "test-shim-secret-32-bytes-content"
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)
        self.fake_bin, self.marker = _make_fake_bin(self.tmp, "kimi")
        # Wave-6 E-2: provide a fresh recall sentinel so the freshness gate passes.
        _write_fresh_recall(self.tmp)
        self.env = {
            **os.environ,
            "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content",
            "AUDITOOOR_REAL_KIMI": self.fake_bin,
            "AUDITOOOR_WORKSPACE": str(pathlib.Path(self.tmp).resolve()),
            "AUDITOOOR_WS_ROOT": str(pathlib.Path(self.tmp).resolve()),
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_passthrough_models_list_no_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(KIMI_WRAPPER), "models", "list"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file(), "fake kimi should have been called")
        self.assertIn("models", self.marker.read_text())

    def test_blocked_query_without_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(KIMI_WRAPPER), "query", "what is 2+2"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)
        self.assertFalse(self.marker.is_file())

    def test_blocked_chat_without_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(KIMI_WRAPPER), "chat"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)

    def test_passes_query_with_valid_token(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.env, "AUDITOOOR_MCP_SESSION_TOKEN": token}
        proc = subprocess.run(
            ["bash", str(KIMI_WRAPPER), "query", "hello"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertTrue(self.marker.is_file())

    def test_bypass_logged_when_required_zero(self):
        env = {**self.env, "AUDITOOOR_MCP_REQUIRED": "0"}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(KIMI_WRAPPER), "run", "prompt.txt"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        bypass_log = pathlib.Path(self.tmp) / ".auditooor" / "bypass_log.jsonl"
        self.assertTrue(bypass_log.is_file())
        self.assertIn("AUDITOOOR_MCP_REQUIRED=0", bypass_log.read_text())

    def test_inline_mcp_token_flag(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(KIMI_WRAPPER), f"--mcp-token={token}", "query", "hello"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file())
        self.assertNotIn("--mcp-token", self.marker.read_text())


class TestForgeWrapper(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = "test-shim-secret-32-bytes-content"
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)
        self.fake_bin, self.marker = _make_fake_bin(self.tmp, "forge")
        # Wave-6 E-2: provide a fresh recall sentinel so the freshness gate passes.
        _write_fresh_recall(self.tmp)
        self.env = {
            **os.environ,
            "AUDITOOOR_MCP_SECRET": "test-shim-secret-32-bytes-content",
            "AUDITOOOR_REAL_FORGE": self.fake_bin,
            "AUDITOOOR_WORKSPACE": str(pathlib.Path(self.tmp).resolve()),
            "AUDITOOOR_WS_ROOT": str(pathlib.Path(self.tmp).resolve()),
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_passthrough_build_no_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "build"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file(), "fake forge should have been called")
        self.assertIn("build", self.marker.read_text())

    def test_passthrough_test_no_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "test"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file())

    def test_passthrough_coverage_no_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "coverage"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file())

    def test_blocked_script_without_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "script", "Deploy.s.sol"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)
        self.assertFalse(self.marker.is_file())

    def test_blocked_create_without_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "create", "src/Token.sol:Token"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)

    def test_blocked_verify_contract_without_token(self):
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        env.pop("AUDITOOOR_MCP_REQUIRED", None)
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "verify-contract", "0xdeadbeef", "Token"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stderr)

    def test_passes_script_with_valid_token(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.env, "AUDITOOOR_MCP_SESSION_TOKEN": token}
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "script", "Deploy.s.sol"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        self.assertTrue(self.marker.is_file())

    def test_bypass_logged_when_required_zero(self):
        env = {**self.env, "AUDITOOOR_MCP_REQUIRED": "0"}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), "create", "src/Token.sol:Token"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr}")
        bypass_log = pathlib.Path(self.tmp) / ".auditooor" / "bypass_log.jsonl"
        self.assertTrue(bypass_log.is_file())
        self.assertIn("AUDITOOOR_MCP_REQUIRED=0", bypass_log.read_text())

    def test_inline_mcp_token_flag(self):
        token = _issue_token(self.tmp, scope="write")
        env = {**self.env}
        env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(FORGE_WRAPPER), f"--mcp-token={token}", "script", "Deploy.s.sol"],
            capture_output=True, text=True, env=env, cwd=self.tmp,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.marker.is_file())
        self.assertNotIn("--mcp-token", self.marker.read_text())


if __name__ == "__main__":
    unittest.main()
