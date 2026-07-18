"""Wave-6 E-2: tests for MCP recall freshness gate in CLI wrapper scripts.

Tests that:
1. Each wrapper script contains the freshness-gate code block.
2. Stale .auditooor/last_mcp_recall.json (>max-age) is REJECTED by the wrapper.
3. Fresh recall ALLOWS wrapper exec (token gate still applies; we use bypass=0).
4. Missing recall file REJECTS.
5. AUDITOOOR_MCP_REQUIRED=0 bypass works and logs to bypass_log.jsonl.
6. AUDITOOOR_RECALL_MAX_AGE_S=60 shortens the window correctly.

Tests use tempdir + mock wrapper-subprocess; they do NOT invoke real codex/kimi/git.
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
TOOLS = REPO / "tools"

# All 5 wrappers under test
WRAPPERS = {
    "codex": TOOLS / "auditooor-codex-wrapper.sh",
    "kimi": TOOLS / "auditooor-kimi-wrapper.sh",
    "git": TOOLS / "auditooor-git-wrapper.sh",
    "gh": TOOLS / "auditooor-gh-wrapper.sh",
    "forge": TOOLS / "auditooor-forge-wrapper.sh",
}

# Sentinel string that MUST appear in every freshness-gated wrapper
FRESHNESS_SENTINEL = "Wave-6 E-2: MCP recall freshness gate"

# A gated subcommand for each wrapper (used to trigger the write-gate path)
GATED_SUBCMD = {
    "codex": ["exec", "task"],
    "kimi": ["query", "hello"],
    "git": ["commit", "-m", "test"],
    "gh": ["pr", "create"],
    "forge": ["script", "Deploy.s.sol"],
}

# Env key for real binary override
REAL_BIN_KEY = {
    "codex": "AUDITOOOR_REAL_CODEX",
    "kimi": "AUDITOOOR_REAL_KIMI",
    "git": "AUDITOOOR_REAL_GIT",
    "gh": "AUDITOOOR_REAL_GH",
    "forge": "AUDITOOOR_REAL_FORGE",
}


def _make_fake_bin(tmp_dir: str, name: str):
    """Create a fake binary that writes to a marker file and exits 0."""
    fake = pathlib.Path(tmp_dir) / f"fake-{name}"
    marker = pathlib.Path(tmp_dir) / f"fake-{name}-called"
    fake.write_text(f"""#!/usr/bin/env bash
echo "FAKE-{name.upper()}: $@" > "{marker}"
echo "fake {name} called"
""")
    fake.chmod(0o755)
    return str(fake), marker


def _write_recall_sentinel(ws: str, age_s: float = 0.0) -> None:
    """Write a .auditooor/last_mcp_recall.json with given age (0=fresh)."""
    sentinel_dir = pathlib.Path(ws) / ".auditooor"
    sentinel_dir.mkdir(parents=True, exist_ok=True)
    recall_ts = time.time() - age_s
    data = {
        "context_pack_id": "test.pack.v1:resume:abc123",
        "context_pack_hash": "abc123def456",
        "workspace_path": ws,
        "recall_ts": recall_ts,
        "recall_iso": "2026-05-11T00:00:00Z",
        "owner_tool": "TEST",
    }
    (sentinel_dir / "last_mcp_recall.json").write_text(json.dumps(data, indent=2))


def _base_env(tool: str, tmp_dir: str, fake_bin: str, **extras) -> dict:
    """Base env dict for wrapper tests."""
    env = {
        **os.environ,
        "AUDITOOOR_MCP_SECRET": "test-freshness-gate-secret-32-bytes",
        "AUDITOOOR_WORKSPACE": str(pathlib.Path(tmp_dir).resolve()),
        "AUDITOOOR_WS_ROOT": str(pathlib.Path(tmp_dir).resolve()),
        REAL_BIN_KEY[tool]: fake_bin,
    }
    env.pop("AUDITOOOR_MCP_SESSION_TOKEN", None)
    env.pop("AUDITOOOR_MCP_REQUIRED", None)
    env.pop("AUDITOOOR_NO_FRESHNESS_CHECK", None)
    env.pop("AUDITOOOR_RECALL_MAX_AGE_S", None)
    env.update(extras)
    return env


def _run_wrapper(tool: str, args: list, env: dict, cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(WRAPPERS[tool]), *args],
        capture_output=True, text=True, env=env, cwd=cwd,
    )


class TestFreshnessGateSentinelPresence(unittest.TestCase):
    """Deliverable 1 / Deliverable 3: each wrapper contains the freshness sentinel."""

    def _check(self, tool_name: str, wrapper_path: pathlib.Path) -> None:
        content = wrapper_path.read_text()
        self.assertIn(
            FRESHNESS_SENTINEL, content,
            f"{wrapper_path.name} is missing Wave-6 E-2 freshness gate sentinel string",
        )

    def test_codex_wrapper_has_freshness_gate(self):
        self._check("codex", WRAPPERS["codex"])

    def test_kimi_wrapper_has_freshness_gate(self):
        self._check("kimi", WRAPPERS["kimi"])

    def test_git_wrapper_has_freshness_gate(self):
        self._check("git", WRAPPERS["git"])

    def test_gh_wrapper_has_freshness_gate(self):
        self._check("gh", WRAPPERS["gh"])

    def test_forge_wrapper_has_freshness_gate(self):
        self._check("forge", WRAPPERS["forge"])

    def test_no_freshness_check_escape_hatch_present(self):
        """Every wrapper must support AUDITOOOR_NO_FRESHNESS_CHECK for backward compat."""
        for name, path in WRAPPERS.items():
            content = path.read_text()
            self.assertIn(
                "AUDITOOOR_NO_FRESHNESS_CHECK",
                content,
                f"{path.name} missing AUDITOOOR_NO_FRESHNESS_CHECK escape hatch",
            )


class TestFreshnessGateMissingFile(unittest.TestCase):
    """Missing .auditooor/last_mcp_recall.json must REJECT (exit 1)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _test_tool_rejected_no_recall(self, tool: str) -> None:
        fake_bin, marker = _make_fake_bin(self.tmp, tool)
        env = _base_env(tool, self.tmp, fake_bin)
        # No recall file written — should reject
        proc = _run_wrapper(tool, GATED_SUBCMD[tool], env, self.tmp)
        self.assertEqual(proc.returncode, 1, f"{tool}: expected exit 1 when recall missing\nstderr={proc.stderr}")
        self.assertIn("REJECTED", proc.stderr, f"{tool}: expected REJECTED in stderr")
        self.assertFalse(marker.is_file(), f"{tool}: fake binary should NOT have been called")

    def test_codex_rejected_when_no_recall(self):
        self._test_tool_rejected_no_recall("codex")

    def test_kimi_rejected_when_no_recall(self):
        self._test_tool_rejected_no_recall("kimi")

    def test_git_rejected_when_no_recall(self):
        self._test_tool_rejected_no_recall("git")

    def test_gh_rejected_when_no_recall(self):
        self._test_tool_rejected_no_recall("gh")

    def test_forge_rejected_when_no_recall(self):
        self._test_tool_rejected_no_recall("forge")


class TestFreshnessGateStaleFile(unittest.TestCase):
    """Stale recall (>max-age) must REJECT."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _test_tool_rejected_stale(self, tool: str) -> None:
        fake_bin, marker = _make_fake_bin(self.tmp, tool)
        # Write recall that is 3000 seconds old (> default 1800)
        _write_recall_sentinel(self.tmp, age_s=3000)
        env = _base_env(tool, self.tmp, fake_bin)
        proc = _run_wrapper(tool, GATED_SUBCMD[tool], env, self.tmp)
        self.assertEqual(proc.returncode, 1, f"{tool}: expected exit 1 when recall stale\nstderr={proc.stderr}")
        self.assertIn("REJECTED", proc.stderr)
        self.assertIn("stale", proc.stderr.lower())
        self.assertFalse(marker.is_file(), f"{tool}: fake binary should NOT have been called")

    def test_codex_rejected_when_recall_stale(self):
        self._test_tool_rejected_stale("codex")

    def test_kimi_rejected_when_recall_stale(self):
        self._test_tool_rejected_stale("kimi")

    def test_git_rejected_when_recall_stale(self):
        self._test_tool_rejected_stale("git")

    def test_gh_rejected_when_recall_stale(self):
        self._test_tool_rejected_stale("gh")

    def test_forge_rejected_when_recall_stale(self):
        self._test_tool_rejected_stale("forge")


class TestFreshnessGateFreshAllows(unittest.TestCase):
    """Fresh recall + AUDITOOOR_MCP_REQUIRED=0 (no token) allows exec and reaches
    real binary (bypassed at token gate, not freshness gate)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _test_tool_fresh_allows(self, tool: str) -> None:
        fake_bin, marker = _make_fake_bin(self.tmp, tool)
        # Write fresh recall (0 seconds old)
        _write_recall_sentinel(self.tmp, age_s=0)
        env = _base_env(tool, self.tmp, fake_bin, AUDITOOOR_MCP_REQUIRED="0")
        proc = _run_wrapper(tool, GATED_SUBCMD[tool], env, self.tmp)
        self.assertEqual(proc.returncode, 0, f"{tool}: expected exit 0 with fresh recall + bypass\nstderr={proc.stderr}")
        self.assertTrue(marker.is_file(), f"{tool}: fake binary should have been called")

    def test_codex_allowed_when_fresh_recall(self):
        self._test_tool_fresh_allows("codex")

    def test_kimi_allowed_when_fresh_recall(self):
        self._test_tool_fresh_allows("kimi")

    def test_git_allowed_when_fresh_recall(self):
        self._test_tool_fresh_allows("git")

    def test_gh_allowed_when_fresh_recall(self):
        self._test_tool_fresh_allows("gh")

    def test_forge_allowed_when_fresh_recall(self):
        self._test_tool_fresh_allows("forge")


class TestFreshnessGateBypassLogging(unittest.TestCase):
    """AUDITOOOR_MCP_REQUIRED=0 bypasses gate AND logs to bypass_log.jsonl."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_bypass_logged_when_recall_missing(self):
        """No recall file + AUDITOOOR_MCP_REQUIRED=0 must log bypass entry."""
        tool = "git"
        fake_bin, marker = _make_fake_bin(self.tmp, tool)
        env = _base_env(tool, self.tmp, fake_bin, AUDITOOOR_MCP_REQUIRED="0")
        proc = _run_wrapper(tool, GATED_SUBCMD[tool], env, self.tmp)
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
        bypass_log = pathlib.Path(self.tmp) / ".auditooor" / "bypass_log.jsonl"
        self.assertTrue(bypass_log.is_file(), "bypass_log.jsonl should be created")
        entries = [json.loads(line) for line in bypass_log.read_text().strip().split("\n") if line.strip()]
        bypass_reasons = [e.get("reason", "") for e in entries]
        self.assertTrue(
            any("no_recall_file" in r or "AUDITOOOR_MCP_REQUIRED=0" in r for r in bypass_reasons),
            f"Expected bypass reason in log; got: {bypass_reasons}",
        )

    def test_bypass_logged_when_recall_stale(self):
        """Stale recall + AUDITOOOR_MCP_REQUIRED=0 must log bypass entry with age_s."""
        tool = "codex"
        fake_bin, marker = _make_fake_bin(self.tmp, tool)
        _write_recall_sentinel(self.tmp, age_s=3600)
        env = _base_env(tool, self.tmp, fake_bin, AUDITOOOR_MCP_REQUIRED="0")
        proc = _run_wrapper(tool, GATED_SUBCMD[tool], env, self.tmp)
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
        bypass_log = pathlib.Path(self.tmp) / ".auditooor" / "bypass_log.jsonl"
        self.assertTrue(bypass_log.is_file())
        content = bypass_log.read_text()
        self.assertTrue(
            "recall_stale" in content or "AUDITOOOR_MCP_REQUIRED=0" in content,
            f"Expected stale-recall bypass in log; got: {content}",
        )


class TestFreshnessGateMaxAgeOverride(unittest.TestCase):
    """AUDITOOOR_RECALL_MAX_AGE_S=60 shortens the window."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_custom_max_age_rejects_90s_old_recall(self):
        """With max_age=60, a 90-second-old recall should be REJECTED."""
        tool = "forge"
        fake_bin, marker = _make_fake_bin(self.tmp, tool)
        _write_recall_sentinel(self.tmp, age_s=90)  # 90s old
        env = _base_env(
            tool, self.tmp, fake_bin,
            AUDITOOOR_RECALL_MAX_AGE_S="60",  # tighter window
        )
        proc = _run_wrapper(tool, GATED_SUBCMD[tool], env, self.tmp)
        self.assertEqual(proc.returncode, 1, f"Expected reject with 90s recall and max_age=60\nstderr={proc.stderr}")
        self.assertIn("REJECTED", proc.stderr)
        self.assertFalse(marker.is_file())

    def test_custom_max_age_allows_30s_old_recall_with_bypass(self):
        """With max_age=60, a 30-second-old recall should pass freshness gate."""
        tool = "kimi"
        fake_bin, marker = _make_fake_bin(self.tmp, tool)
        _write_recall_sentinel(self.tmp, age_s=30)  # 30s old — fresh within 60s window
        env = _base_env(
            tool, self.tmp, fake_bin,
            AUDITOOOR_RECALL_MAX_AGE_S="60",
            AUDITOOOR_MCP_REQUIRED="0",  # bypass token gate
        )
        proc = _run_wrapper(tool, GATED_SUBCMD[tool], env, self.tmp)
        self.assertEqual(proc.returncode, 0, f"Expected pass with 30s recall and max_age=60\nstderr={proc.stderr}")
        self.assertTrue(marker.is_file())


class TestFreshnessGateEscapeHatch(unittest.TestCase):
    """AUDITOOOR_NO_FRESHNESS_CHECK=1 skips freshness entirely (backward compat)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=self.tmp, check=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_freshness_check_skips_stale_rejection(self):
        """Even with a stale recall, AUDITOOOR_NO_FRESHNESS_CHECK=1 must not reject
        at the freshness gate (token bypass still needed for exec)."""
        tool = "git"
        fake_bin, marker = _make_fake_bin(self.tmp, tool)
        _write_recall_sentinel(self.tmp, age_s=9999)  # very stale
        env = _base_env(
            tool, self.tmp, fake_bin,
            AUDITOOOR_NO_FRESHNESS_CHECK="1",
            AUDITOOOR_MCP_REQUIRED="0",
        )
        proc = _run_wrapper(tool, GATED_SUBCMD[tool], env, self.tmp)
        self.assertEqual(proc.returncode, 0, f"Expected pass with NO_FRESHNESS_CHECK=1\nstderr={proc.stderr}")
        self.assertTrue(marker.is_file())


class TestInstallWrappersSubcommands(unittest.TestCase):
    """Test new install-wrappers.sh subcommands (check-path, check-freshness-wiring)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin_dir = pathlib.Path(self.tmp) / "bin"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_install(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(TOOLS / "install-wrappers.sh"), *args],
            capture_output=True, text=True,
            env={**os.environ, "AUDITOOOR_BIN_DIR": str(self.bin_dir)},
        )

    def test_check_freshness_wiring_passes_for_updated_wrappers(self):
        """check-freshness-wiring should report OK for all wrappers we just updated."""
        proc = self._run_install("check-freshness-wiring")
        # All 5 wrappers have the sentinel — should be exit 0
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("[OK]", proc.stdout)

    def test_check_path_returns_nonzero_when_not_in_path(self):
        """check-path should exit 1 if ~/.auditooor/bin not in PATH."""
        env = {**os.environ, "AUDITOOOR_BIN_DIR": str(self.bin_dir)}
        # Remove the bin dir from PATH to ensure it's absent
        path_without = ":".join(
            p for p in os.environ.get("PATH", "").split(":")
            if "auditooor" not in p.lower()
        )
        env["PATH"] = path_without
        proc = subprocess.run(
            ["bash", str(TOOLS / "install-wrappers.sh"), "check-path"],
            capture_output=True, text=True, env=env,
        )
        # Should exit 1 and explain how to add
        self.assertEqual(proc.returncode, 1, f"stdout={proc.stdout}")
        self.assertIn("does not include", proc.stdout)

    def test_install_idempotent_with_freshness_check(self):
        """install subcommand should still be idempotent after Wave-6 E-2."""
        self._run_install("install")
        proc = self._run_install("install")
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
        self.assertIn("[unchanged]", proc.stdout)


if __name__ == "__main__":
    unittest.main()
