#!/usr/bin/env python3
"""Tests for the read-only context-pollution inventory helper."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "context-pollution-inventory.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("context_pollution_inventory", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["context_pollution_inventory"] = module
    spec.loader.exec_module(module)
    return module


tool = load_tool()


def git(args: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"git {args!r} failed: {proc.stderr}")
    return proc


def init_repo(repo: Path) -> None:
    git(["init", "-b", "main"], repo)
    git(["config", "commit.gpgsign", "false"], repo)
    (repo / "README.md").write_text("repo\n", encoding="utf-8")
    git(["add", "README.md"], repo)
    git(["commit", "-m", "init"], repo)


class ContextPollutionInventoryTests(unittest.TestCase):
    def test_reports_nested_registered_worktree_and_export_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            init_repo(repo)

            git(["checkout", "-b", "nested-branch"], repo)
            (repo / "nested.txt").write_text("nested\n", encoding="utf-8")
            git(["add", "nested.txt"], repo)
            git(["commit", "-m", "nested"], repo)
            git(["checkout", "main"], repo)

            nested = repo / "auditooor-nested"
            git(["worktree", "add", str(nested), "nested-branch"], repo)
            (nested / "dirty.txt").write_text("preserve\n", encoding="utf-8")
            (repo / "status-ws").mkdir()
            (repo / "status-ws" / "snapshot.txt").write_text("generated\n", encoding="utf-8")

            inv = tool.build_inventory(repo)
            risks = {Path(row["path"]).name: row for row in inv["risks"]}

            self.assertEqual(risks["auditooor-nested"]["kind"], "registered-worktree")
            self.assertEqual(risks["auditooor-nested"]["risk"], "dirty-nested-worktree")
            self.assertEqual(risks["auditooor-nested"]["dirty_count"], 1)
            self.assertEqual(risks["status-ws"]["kind"], "export-dir")
            self.assertIn("preserve", risks["status-ws"]["action"])

    def test_reports_nested_full_git_repo_without_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            init_repo(repo)

            nested_repo = repo / "auditooor-loop"
            nested_repo.mkdir()
            init_repo(nested_repo)
            (nested_repo / "dirty.py").write_text("print('keep')\n", encoding="utf-8")

            before = git(["status", "--short"], nested_repo).stdout
            inv = tool.build_inventory(repo)
            after = git(["status", "--short"], nested_repo).stdout
            row = next(r for r in inv["risks"] if Path(r["path"]).name == "auditooor-loop")

            self.assertEqual(before, after)
            self.assertEqual(row["kind"], "nested-git-repo")
            self.assertEqual(row["risk"], "dirty-nested-git-repo")
            self.assertEqual(row["dirty_count"], 1)

    def test_json_cli_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            init_repo(repo)
            (repo / "auditooor-export").mkdir()

            proc = subprocess.run(
                [sys.executable, str(TOOL_PATH), "--repo", str(repo), "--json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["risk_count"], 1)
            self.assertEqual(payload["risks"][0]["kind"], "export-dir")
            self.assertTrue((repo / "auditooor-export").is_dir())

    def test_git_path_risk_fails_closed_on_unknown_status(self) -> None:
        risk, action = tool.git_path_risk("nested-worktree", None)

        self.assertEqual(risk, "unknown-nested-worktree-status")
        self.assertIn("preserve", action)


if __name__ == "__main__":
    unittest.main()
