#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "memory-commits-emitter.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("memory_commits_emitter", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["memory_commits_emitter"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def _test_env() -> dict[str, str]:
    """Env that lets the auditooor-git-wrapper bypass the MCP-token gate in
    hermetic test contexts.

    The wrapper at /Users/wolf/.auditooor/bin/git (PATH-shadowed) gates
    `git commit` on two things: (1) presence of a fresh
    .auditooor/last_mcp_recall.json sentinel in the repo, and (2) a valid
    AUDITOOOR_MCP_SESSION_TOKEN. Sentinel #1 is seeded by
    _seed_mcp_sentinel(); gate #2 is bypassed by AUDITOOOR_MCP_REQUIRED=0
    which emits an audit log line into .auditooor/bypass_log.jsonl and
    proceeds. Tests are non-production and the bypass log goes into the
    ephemeral tempdir, so this is safe and hermetic.
    """
    env = dict(os.environ)
    env["AUDITOOOR_MCP_REQUIRED"] = "0"
    return env


def _seed_mcp_sentinel(repo: Path) -> None:
    """Write a minimal-valid .auditooor/last_mcp_recall.json so the
    auditooor-git-wrapper freshness gate accepts the ephemeral test repo.
    Marked synthetic_fixture: true per global CLAUDE.md test-fixture rule.
    """
    sentinel_dir = repo / ".auditooor"
    sentinel_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "context_pack_id": "auditooor.vault_context_pack.v1:resume:test-fixture-synthetic-fixture-true",
        "context_pack_hash": "0" * 64,
        "workspace_path": str(repo),
        "recall_ts": time.time(),
        "synthetic_fixture": True,
        "owner_tool": "test_memory_commits_emitter",
    }
    (sentinel_dir / "last_mcp_recall.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        env=_test_env(),
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc.stdout.strip()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stage_repo(root: Path, message: str = "feat: add tracker (#123)") -> tuple[str, str]:
    _git(root, "init")
    _seed_mcp_sentinel(root)
    _git(root, "config", "user.name", "Test User")
    _git(root, "config", "user.email", "test@example.com")
    _write(root / "README.md", "# demo\n")
    _write(root / "tools" / "helper.py", "print('ok')\n")
    _git(root, "add", "README.md", "tools/helper.py")
    _git(root, "commit", "-m", message, "-m", "Body line 1.\n\nBody line 2.")
    branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD")
    sha = _git(root, "rev-parse", "HEAD")
    return branch, sha


class MemoryCommitsEmitterTest(unittest.TestCase):
    def test_emit_head_commit_note_contains_pr_links_and_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-commits-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            vault = Path(tmp) / "vault"
            branch, sha = _stage_repo(repo)

            results = MOD.emit_commits(
                vault,
                repo_root=repo,
                shas=[MOD.head_sha(repo)],
            )

            self.assertEqual([result.status for result in results], ["written"])
            note = vault / "commits" / f"{sha[:8]}.md"
            text = note.read_text(encoding="utf-8")
            self.assertIn(f'sha: "{sha}"', text)
            self.assertIn('author: "Test User"', text)
            self.assertIn('short_sha: ', text)
            self.assertIn("[[prs/123]]", text)
            self.assertIn("Body line 1.", text)
            self.assertIn("- `README.md`", text)
            self.assertIn("- `tools/helper.py`", text)
            self.assertTrue(branch)

    def test_emit_is_idempotent_when_note_content_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-commits-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            vault = Path(tmp) / "vault"
            _, sha = _stage_repo(repo, message="fix: keep stable commit note")

            first = MOD.emit_commits(vault, repo_root=repo, shas=[sha])
            note = vault / "commits" / f"{sha[:8]}.md"
            before_mtime_ns = note.stat().st_mtime_ns
            second = MOD.emit_commits(vault, repo_root=repo, shas=[sha])
            after_mtime_ns = note.stat().st_mtime_ns

            self.assertEqual(first[0].status, "written")
            self.assertEqual(second[0].status, "unchanged")
            self.assertEqual(before_mtime_ns, after_mtime_ns)

    def test_cli_can_emit_from_git_ref_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-commits-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            vault = Path(tmp) / "vault"
            branch, sha = _stage_repo(repo, message="chore: ref path coverage")
            ref_path = repo / ".git" / "refs" / "heads" / branch

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-root",
                    str(repo),
                    "--vault-dir",
                    str(vault),
                    "--ref-path",
                    str(ref_path),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=_test_env(),
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("[commits] written", proc.stdout)
            note = vault / "commits" / f"{sha[:8]}.md"
            self.assertTrue(note.is_file())
            self.assertIn("chore: ref path coverage", note.read_text(encoding="utf-8"))

    def test_dry_run_resolves_head_without_writing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="memory-commits-") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            vault = Path(tmp) / "vault"
            _, sha = _stage_repo(repo)

            results = MOD.emit_commits(
                vault,
                repo_root=repo,
                shas=[sha],
                dry_run=True,
            )

            self.assertEqual(results[0].status, "dry_run")
            self.assertFalse((vault / "commits" / f"{sha[:8]}.md").exists())


if __name__ == "__main__":
    unittest.main()
