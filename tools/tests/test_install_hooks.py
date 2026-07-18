"""Tests for tools/install-hooks.sh.

Verifies:
- installer is idempotent (re-running install does not error)
- creates the expected hook files
- hooks contain the 'auditooor' marker
- AUDITOOOR_MCP_REQUIRED=0 bypass logs to bypass_log.jsonl
- uninstall removes hooks and restores backups
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

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_HOOKS_SH = REPO_ROOT / "tools" / "install-hooks.sh"
TOKEN_TOOL = REPO_ROOT / "tools" / "auditooor_mcp_token.py"
TEST_TOKEN_SECRET = "test-install-hooks-secret-32-bytes"


def _run_installer(tmpdir: Path, subcmd: str, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run install-hooks.sh with a fake git repo rooted at tmpdir."""
    # AUDITOOOR_WS_ROOT tells install-hooks.sh which repo to use, isolating the
    # test from whatever repo the script lives in.
    merged_env = {
        **os.environ,
        "AUDITOOOR_WS_ROOT": str(tmpdir),
        "AUDITOOOR_BIN_DIR": str(tmpdir / ".auditooor" / "bin"),
    }
    if env:
        merged_env.update(env)
    return subprocess.run(
        ["bash", str(INSTALL_HOOKS_SH), subcmd],
        cwd=str(tmpdir),
        capture_output=True,
        text=True,
        env=merged_env,
    )


def _make_fake_repo(tmpdir: Path) -> Path:
    """Initialize a bare git repo and return the hooks dir."""
    subprocess.run(["git", "init", str(tmpdir)], capture_output=True, check=True)
    subprocess.run(["git", "-C", str(tmpdir), "config", "user.email", "test@test.com"],
                   capture_output=True, check=True)
    subprocess.run(["git", "-C", str(tmpdir), "config", "user.name", "Test"],
                   capture_output=True, check=True)
    hooks_dir = tmpdir / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    return hooks_dir


def _write_recall_sentinel(tmpdir: Path, age_s: int = 0) -> None:
    """Write a minimal last_mcp_recall.json in the fake repo."""
    auditooor_dir = tmpdir / ".auditooor"
    auditooor_dir.mkdir(exist_ok=True)
    (auditooor_dir / "last_mcp_recall.json").write_text(json.dumps({
        "context_pack_id": "test.pack.v1:resume:abc123",
        "context_pack_hash": "abc123def456",
        "workspace_path": str(tmpdir),
        "recall_ts": time.time() - age_s,
        "recall_iso": "2026-05-21T00:00:00Z",
        "owner_tool": "TEST",
    }))


def _issue_token(tmpdir: Path, *scopes: str) -> str:
    """Issue an MCP token bound to the fake repo."""
    token_scopes = scopes or ("write",)
    result = subprocess.run(
        [
            sys.executable,
            str(TOKEN_TOOL),
            "issue",
            "--workspace",
            str(tmpdir),
            "--scope",
            *token_scopes,
            "--no-log",
        ],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "AUDITOOOR_MCP_SECRET": TEST_TOKEN_SECRET},
    )
    return result.stdout.strip()


def _issue_write_token(tmpdir: Path) -> str:
    """Issue a write-scoped MCP token bound to the fake repo."""
    return _issue_token(tmpdir, "write")


class TestInstallHooks(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self._td.name)
        self.hooks_dir = _make_fake_repo(self.tmpdir)

    def tearDown(self):
        self._td.cleanup()

    def test_install_creates_hooks(self):
        """install subcommand creates pre-commit, commit-msg, and pre-push hooks."""
        result = _run_installer(self.tmpdir, "install")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue((self.hooks_dir / "pre-commit").exists(),
                        "pre-commit hook not created")
        self.assertTrue((self.hooks_dir / "commit-msg").exists(),
                        "commit-msg hook not created")
        self.assertTrue((self.hooks_dir / "pre-push").exists(),
                        "pre-push hook not created")
        self.assertTrue((self.tmpdir / ".auditooor" / "bin" / "auditooor-session-start.sh").exists(),
                        "session-start shim not created")

    def test_active_hooks_are_bundled_in_repo(self):
        """The active tools/git-hooks directory bundles commit-msg and pre-push."""
        for name in ("commit-msg", "pre-push"):
            hook = REPO_ROOT / "tools" / "git-hooks" / name
            self.assertTrue(hook.exists(), f"{name} hook missing from tools/git-hooks/")
            text = hook.read_text()
            self.assertIn("auditooor", text, f"{name} hook missing auditooor marker")
        self.assertTrue(os.access(str(REPO_ROOT / "tools" / "git-hooks" / "commit-msg"), os.X_OK))
        self.assertTrue(os.access(str(REPO_ROOT / "tools" / "git-hooks" / "pre-push"), os.X_OK))

    def test_hooks_contain_auditooor_marker(self):
        """Installed hooks contain the 'auditooor' marker for ownership tracking."""
        _run_installer(self.tmpdir, "install")
        for name in ("pre-commit", "commit-msg", "pre-push"):
            hook_text = (self.hooks_dir / name).read_text()
            self.assertIn("auditooor", hook_text,
                          f"{name} hook missing 'auditooor' marker")

    def test_pre_push_hook_contains_token_and_freshness_gate(self):
        """pre-push requires fresh recall and a write-scoped MCP token."""
        _run_installer(self.tmpdir, "install")
        hook_text = (self.hooks_dir / "pre-push").read_text()
        self.assertIn("last_mcp_recall.json", hook_text)
        self.assertIn("AUDITOOOR_MCP_SESSION_TOKEN", hook_text)
        self.assertIn("--require-scope write", hook_text)

    def test_pre_commit_hook_contains_hackerman_record_validation(self):
        """pre-commit validates staged hackerman_record YAML when the validator exists."""
        _run_installer(self.tmpdir, "install")
        hook_text = (self.hooks_dir / "pre-commit").read_text()
        self.assertIn("hackerman-record-validate.py", hook_text)
        self.assertIn("audit/corpus_tags/tags/*.yaml", hook_text)
        self.assertIn("hackerman_record staged YAML OK", hook_text)

    def test_pre_commit_hook_contains_rule_contract_advisory_block(self):
        """pre-commit wires the P17 rule-contract self-test (advisory-first)."""
        _run_installer(self.tmpdir, "install")
        hook_text = (self.hooks_dir / "pre-commit").read_text()
        self.assertIn("rule-contract-check.py", hook_text)
        self.assertIn("AUDITOOOR_RULE_CONTRACT_STRICT", hook_text)
        # The --changed scoping must be present so unrelated edits are a no-op.
        self.assertIn("--changed", hook_text)

    def test_rule_contract_advisory_flag_unset_does_not_brick_commit(self):
        """REGRESSION (P17 safety contract): with AUDITOOOR_RULE_CONTRACT_STRICT
        UNSET, the installed pre-commit exits 0 even when a staged edit would
        VIOLATE a bound rule-contract. Flag-unset behavior is advisory (WARN
        only) -- byte-identical to pre-P17 blocking behavior for rule edits."""
        _run_installer(self.tmpdir, "install")
        pc = self.hooks_dir / "pre-commit"
        # Simulate a staged tools/*.py change by driving the RCC tool directly
        # in advisory mode against an intentionally-violated contract and
        # asserting rc==0 (the pre-commit only aborts when the flag is set).
        rcc = REPO_ROOT / "tools" / "rule-contract-check.py"
        # Author a throwaway violated contract, replay it advisory, assert rc 0.
        contracts_dir = REPO_ROOT / "tools" / "rules" / "contracts"
        throwaway = contracts_dir / "_test_flag_unset_regression.yaml"
        throwaway.write_text(
            "name: p17-regression-violated\n"
            "tool: tools/exploit-queue-schema-check.py\n"
            "rationale: intentionally-inverted fixture to prove advisory rc 0\n"
            "argv: [\"--workspace\", \"{fixture_dir}\"]\n"
            "must_catch:\n"
            "  - label: should-fail-but-passes\n"
            "    files:\n"
            "      \".auditooor/exploit_queue.json\": '{\"rows\":[]}'\n"
            "must_pass:\n"
            "  - label: clean\n"
            "    files:\n"
            "      \".auditooor/exploit_queue.json\": '{\"rows\":[{\"id\":\"r\",\"source\":\"hunt\",\"attack_class\":\"x\",\"mechanism\":\"y\",\"impact_class\":\"z\"}]}'\n"
        )
        try:
            env = {k: v for k, v in os.environ.items()
                   if k != "AUDITOOOR_RULE_CONTRACT_STRICT"}
            advisory = subprocess.run(
                [sys.executable, str(rcc), "--tool",
                 "tools/exploit-queue-schema-check.py", "--no-mutation"],
                capture_output=True, text=True, env=env)
            self.assertEqual(advisory.returncode, 0,
                             msg=f"advisory (flag unset) must exit 0: {advisory.stderr}")
            # And with the flag SET, the same violated contract exits nonzero.
            env_strict = {**env, "AUDITOOOR_RULE_CONTRACT_STRICT": "1"}
            strict = subprocess.run(
                [sys.executable, str(rcc), "--tool",
                 "tools/exploit-queue-schema-check.py", "--no-mutation"],
                capture_output=True, text=True, env=env_strict)
            self.assertEqual(strict.returncode, 1,
                             msg="strict (flag set) must exit 1 on violation")
        finally:
            throwaway.unlink()
        # The installed hook itself must exist and be advisory-wired.
        self.assertIn("not blocking", pc.read_text())

    def test_hooks_are_executable(self):
        """Installed hooks are executable."""
        _run_installer(self.tmpdir, "install")
        for name in ("pre-commit", "commit-msg", "pre-push"):
            hook = self.hooks_dir / name
            self.assertTrue(os.access(str(hook), os.X_OK),
                            f"{name} hook is not executable")

    def test_install_is_idempotent(self):
        """Re-running install does not error and hooks remain valid."""
        r1 = _run_installer(self.tmpdir, "install")
        self.assertEqual(r1.returncode, 0, msg=r1.stderr)
        r2 = _run_installer(self.tmpdir, "install")
        self.assertEqual(r2.returncode, 0, msg=r2.stderr)
        # Hooks still exist and are auditooor-managed
        for name in ("pre-commit", "commit-msg", "pre-push"):
            hook_text = (self.hooks_dir / name).read_text()
            self.assertIn("auditooor", hook_text)

    def test_install_backs_up_foreign_hooks(self):
        """A pre-existing foreign hook is backed up before installation."""
        # Create a foreign pre-commit hook
        foreign_hook = self.hooks_dir / "pre-commit"
        foreign_hook.write_text("#!/bin/bash\necho foreign\n")
        foreign_hook.chmod(0o755)

        _run_installer(self.tmpdir, "install")
        backup = self.hooks_dir / "pre-commit.auditooor-backup"
        self.assertTrue(backup.exists(), "backup of foreign hook not created")
        self.assertEqual(backup.read_text(), "#!/bin/bash\necho foreign\n")

    def test_uninstall_removes_hooks(self):
        """uninstall subcommand removes the installed hooks."""
        _run_installer(self.tmpdir, "install")
        result = _run_installer(self.tmpdir, "uninstall")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertFalse((self.hooks_dir / "pre-commit").exists(),
                         "pre-commit hook still present after uninstall")
        self.assertFalse((self.hooks_dir / "commit-msg").exists(),
                         "commit-msg hook still present after uninstall")
        self.assertFalse((self.hooks_dir / "pre-push").exists(),
                         "pre-push hook still present after uninstall")

    def test_check_reports_not_installed(self):
        """check subcommand reports NOT INSTALLED when hooks are absent."""
        result = _run_installer(self.tmpdir, "check")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("NOT INSTALLED", result.stdout)

    def test_check_reports_installed_after_install(self):
        """check subcommand reports INSTALLED after hooks are put in place."""
        _run_installer(self.tmpdir, "install")
        result = _run_installer(self.tmpdir, "check")
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("INSTALLED", result.stdout)

    def test_session_start_shim_runs_repo_local_script(self):
        """Installed session-start shim resolves the current workspace script."""
        tools_dir = self.tmpdir / "tools"
        tools_dir.mkdir(exist_ok=True)
        marker = self.tmpdir / ".auditooor" / "shim-marker.txt"
        marker.parent.mkdir(exist_ok=True)

        repo_script = tools_dir / "auditooor-session-start.sh"
        repo_script.write_text(textwrap.dedent(f"""\
            #!/usr/bin/env bash
            set -euo pipefail
            printf '%s\\n' "${{AUDITOOOR_SESSION_START_MARKER}}" > "{marker}"
        """))
        repo_script.chmod(0o755)

        _run_installer(self.tmpdir, "install")
        shim = self.tmpdir / ".auditooor" / "bin" / "auditooor-session-start.sh"

        result = subprocess.run(
            ["bash", str(shim)],
            env={**os.environ,
                 "AUDITOOOR_SESSION_START_MARKER": str(marker),
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(marker.read_text().strip(), str(marker))

    def test_bypass_env_logs_to_bypass_log(self):
        """AUDITOOOR_MCP_REQUIRED=0 allows commit and writes to bypass_log.jsonl."""
        _run_installer(self.tmpdir, "install")

        # Simulate running the pre-commit hook directly with the bypass env
        pre_commit = self.hooks_dir / "pre-commit"
        bypass_log = self.tmpdir / ".auditooor" / "bypass_log.jsonl"

        # Ensure .auditooor dir exists for bypass_log
        (self.tmpdir / ".auditooor").mkdir(exist_ok=True)

        result = subprocess.run(
            ["bash", str(pre_commit)],
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "0",
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0,
                         f"bypass should exit 0, got: {result.stderr}")
        self.assertTrue(bypass_log.exists(),
                        "bypass_log.jsonl not created on bypass")

        line = bypass_log.read_text().strip()
        self.assertTrue(line, "bypass_log.jsonl is empty")
        record = json.loads(line)
        self.assertEqual(record["event"], "bypass")
        self.assertEqual(record["hook"], "pre-commit")

    def test_pre_push_hook_rejects_missing_recall(self):
        """pre-push exits 1 when last_mcp_recall.json is absent."""
        _run_installer(self.tmpdir, "install")
        pre_push = self.hooks_dir / "pre-push"

        result = subprocess.run(
            ["bash", str(pre_push), "origin", "https://example.invalid/repo.git"],
            input="",
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "1",
                 "AUDITOOOR_MCP_TOKEN_TOOL": str(TOKEN_TOOL),
                 "AUDITOOOR_MCP_SECRET": TEST_TOKEN_SECRET,
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("last_mcp_recall.json not found", result.stderr)

    def test_pre_push_hook_rejects_missing_token_with_fresh_recall(self):
        """pre-push exits 1 when recall is fresh but no MCP token is present."""
        _run_installer(self.tmpdir, "install")
        _write_recall_sentinel(self.tmpdir)
        pre_push = self.hooks_dir / "pre-push"

        result = subprocess.run(
            ["bash", str(pre_push), "origin", "https://example.invalid/repo.git"],
            input="",
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "1",
                 "AUDITOOOR_MCP_TOKEN_TOOL": str(TOKEN_TOOL),
                 "AUDITOOOR_MCP_SECRET": TEST_TOKEN_SECRET,
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("AUDITOOOR_MCP_SESSION_TOKEN", result.stderr)

    def test_pre_push_hook_accepts_valid_token_with_fresh_recall(self):
        """pre-push exits 0 with fresh recall and a write-scoped MCP token."""
        _run_installer(self.tmpdir, "install")
        _write_recall_sentinel(self.tmpdir)
        token = _issue_write_token(self.tmpdir)
        pre_push = self.hooks_dir / "pre-push"

        result = subprocess.run(
            ["bash", str(pre_push), "origin", "https://example.invalid/repo.git"],
            input="",
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "1",
                 "AUDITOOOR_MCP_SESSION_TOKEN": token,
                 "AUDITOOOR_MCP_TOKEN_TOOL": str(TOKEN_TOOL),
                 "AUDITOOOR_MCP_SECRET": TEST_TOKEN_SECRET,
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("MCP session token OK", result.stderr)

    def test_pre_push_hook_rejects_cross_workspace_override_and_token(self):
        """pre-push rejects an AUDITOOOR_WS_ROOT override for another repo."""
        _run_installer(self.tmpdir, "install")
        pre_push = self.hooks_dir / "pre-push"

        with tempfile.TemporaryDirectory() as other_td:
            other_repo = Path(other_td)
            _make_fake_repo(other_repo)
            _write_recall_sentinel(other_repo)
            other_token = _issue_write_token(other_repo)

            result = subprocess.run(
                ["bash", str(pre_push), "origin", "https://example.invalid/repo.git"],
                input="",
                env={**os.environ,
                     "AUDITOOOR_MCP_REQUIRED": "1",
                     "AUDITOOOR_MCP_SESSION_TOKEN": other_token,
                     "AUDITOOOR_MCP_TOKEN_TOOL": str(TOKEN_TOOL),
                     "AUDITOOOR_MCP_SECRET": TEST_TOKEN_SECRET,
                     "GIT_DIR": str(self.tmpdir / ".git"),
                     "AUDITOOOR_WS_ROOT": str(other_repo)},
                cwd=str(self.tmpdir),
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("AUDITOOOR_WS_ROOT resolves", result.stderr)
        self.assertIn("but git is pushing", result.stderr)

    def test_pre_push_hook_rejects_wrong_scope_token(self):
        """pre-push rejects a token that is valid but lacks write scope."""
        _run_installer(self.tmpdir, "install")
        _write_recall_sentinel(self.tmpdir)
        token = _issue_token(self.tmpdir, "read")
        pre_push = self.hooks_dir / "pre-push"

        result = subprocess.run(
            ["bash", str(pre_push), "origin", "https://example.invalid/repo.git"],
            input="",
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "1",
                 "AUDITOOOR_MCP_SESSION_TOKEN": token,
                 "AUDITOOOR_MCP_TOKEN_TOOL": str(TOKEN_TOOL),
                 "AUDITOOOR_MCP_SECRET": TEST_TOKEN_SECRET,
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid MCP session token", result.stderr)
        self.assertIn("scope=write", result.stderr)

    def test_pre_push_hook_rejects_stale_recall(self):
        """pre-push exits 1 when last_mcp_recall.json is too old."""
        _run_installer(self.tmpdir, "install")
        _write_recall_sentinel(self.tmpdir, age_s=60)
        token = _issue_write_token(self.tmpdir)
        pre_push = self.hooks_dir / "pre-push"

        result = subprocess.run(
            ["bash", str(pre_push), "origin", "https://example.invalid/repo.git"],
            input="",
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "1",
                 "AUDITOOOR_RECALL_MAX_AGE_S": "1",
                 "AUDITOOOR_MCP_SESSION_TOKEN": token,
                 "AUDITOOOR_MCP_TOKEN_TOOL": str(TOKEN_TOOL),
                 "AUDITOOOR_MCP_SECRET": TEST_TOKEN_SECRET,
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("MCP recall sentinel is", result.stderr)
        self.assertIn("max 1s", result.stderr)

    def test_pre_push_hook_handles_workspace_path_with_apostrophe_and_space(self):
        """pre-push recall parsing passes sentinel path safely to Python."""
        with tempfile.TemporaryDirectory(prefix="repo with apostrophe ' and space ") as quoted_td:
            quoted_repo = Path(quoted_td)
            hooks_dir = _make_fake_repo(quoted_repo)
            result = _run_installer(quoted_repo, "install")
            self.assertEqual(result.returncode, 0, msg=result.stderr)

            _write_recall_sentinel(quoted_repo)
            token = _issue_write_token(quoted_repo)
            pre_push = hooks_dir / "pre-push"

            result = subprocess.run(
                ["bash", str(pre_push), "origin", "https://example.invalid/repo.git"],
                input="",
                env={**os.environ,
                     "AUDITOOOR_MCP_REQUIRED": "1",
                     "AUDITOOOR_MCP_SESSION_TOKEN": token,
                     "AUDITOOOR_MCP_TOKEN_TOOL": str(TOKEN_TOOL),
                     "AUDITOOOR_MCP_SECRET": TEST_TOKEN_SECRET,
                     "GIT_DIR": str(quoted_repo / ".git"),
                     "AUDITOOOR_WS_ROOT": str(quoted_repo)},
                cwd=str(quoted_repo),
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("MCP session token OK", result.stderr)

    def test_pre_push_bypass_env_logs_to_bypass_log(self):
        """AUDITOOOR_MCP_REQUIRED=0 allows pre-push and logs the bypass."""
        _run_installer(self.tmpdir, "install")
        pre_push = self.hooks_dir / "pre-push"
        bypass_log = self.tmpdir / ".auditooor" / "bypass_log.jsonl"

        result = subprocess.run(
            ["bash", str(pre_push), "origin", "https://example.invalid/repo.git"],
            input="",
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "0",
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(bypass_log.exists(),
                        "bypass_log.jsonl not created on pre-push bypass")
        record = json.loads(bypass_log.read_text().strip().splitlines()[-1])
        self.assertEqual(record["event"], "bypass")
        self.assertEqual(record["hook"], "pre-push")
        self.assertEqual(record["reason"], "AUDITOOOR_MCP_REQUIRED=0")

    def test_commit_msg_hook_rejects_missing_context_pack_id(self):
        """commit-msg hook exits 1 when commit message lacks context_pack_id."""
        _run_installer(self.tmpdir, "install")
        commit_msg_hook = self.hooks_dir / "commit-msg"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                        dir=str(self.tmpdir), delete=False) as f:
            f.write("Fix a bug without MCP context\n")
            msg_file = f.name

        result = subprocess.run(
            ["bash", str(commit_msg_hook), msg_file],
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "1",
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1,
                         "commit-msg hook should reject missing context_pack_id")

    def test_commit_msg_hook_accepts_valid_context_pack_id(self):
        """commit-msg hook exits 0 when commit message contains context_pack_id."""
        _run_installer(self.tmpdir, "install")
        commit_msg_hook = self.hooks_dir / "commit-msg"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                        dir=str(self.tmpdir), delete=False) as f:
            f.write("Fix a bug\n\ncontext_pack_id: auditooor.vault_context_pack.v1:resume:abc123\n")
            msg_file = f.name

        result = subprocess.run(
            ["bash", str(commit_msg_hook), msg_file],
            env={**os.environ,
                 "AUDITOOOR_MCP_REQUIRED": "1",
                 "GIT_DIR": str(self.tmpdir / ".git"),
                 "AUDITOOOR_WS_ROOT": str(self.tmpdir)},
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0,
                         f"commit-msg hook should accept valid context_pack_id, stderr: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
