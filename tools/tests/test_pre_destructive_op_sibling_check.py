"""Unit tests for the Rule 55 pre-destructive-op-sibling-check hook.

Each test builds a throwaway git repo, writes uncommitted files, optionally
declares a pathspec, then invokes the hook the way the wrapper script would
(WRAPPER_OP=reset, WRAPPER_ARGS="--hard"). The hook's exit code is asserted.

Coverage matrix:
  1. No uncommitted changes -> pass
  2. Uncommitted file is in CURRENT lane's declared pathspec -> pass
  3. Uncommitted file is in SIBLING lane's declared pathspec -> FAIL
  4. R55_REBUTTAL env var (non-empty) overrides sibling-owned refusal -> pass
  5. .auditooor/agent_pathspec.json missing -> warn-only pass (legacy)
  6. Non-destructive `git reset` (no --hard/--merge/--keep) -> pass
  7. `git reset --hard` is policed
  8. Rebuttal file (.auditooor/r55_rebuttal.txt) is honored
  9. Empty rebuttal does NOT silence the gate
 10. Oversized rebuttal (>200 chars) is ignored
 11. R55_STRICT_NO_PATHSPEC=1 hard-fails on missing pathspec
 12. Multi-agent declaration: undeclared file warns but does not refuse
 13. Expired sibling pathspec is ignored
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "tools" / "git-hooks" / "pre-destructive-op-sibling-check.sh"


_GIT = next(
    (c for c in ("/usr/bin/git", "/opt/homebrew/bin/git", shutil.which("git"))
     if c and Path(c).exists()),
    "git",
)
_GIT_DIR = str(Path(_GIT).parent)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DestructiveOpHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(tempfile.mkdtemp(prefix="r55_destructive_"))
        self._git("init", "-q")
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "Test")
        (self.repo / "seed.txt").write_text("seed\n", encoding="utf-8")
        self._git("add", "seed.txt")
        self._git("commit", "-q", "-m", "seed")

    def tearDown(self) -> None:
        shutil.rmtree(self.repo, ignore_errors=True)

    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [_GIT, *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )

    def _write(self, rel: str, content: str = "x\n") -> None:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _stage(self, rel: str) -> None:
        """Modify a tracked file (commit it first, then modify)."""
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("initial\n", encoding="utf-8")
        self._git("add", rel)
        self._git("commit", "-q", "-m", f"add {rel}")
        # Now modify it so `git status -uno` reports it as M.
        path.write_text("modified\n", encoding="utf-8")

    def _declare(self, agents: list[dict]) -> None:
        target = self.repo / ".auditooor" / "agent_pathspec.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"agents": agents}, indent=2),
            encoding="utf-8",
        )

    def _write_rebuttal_file(self, reason: str) -> None:
        target = self.repo / ".auditooor" / "r55_rebuttal.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(reason, encoding="utf-8")

    def _run_hook(
        self,
        wrapper_op: str = "reset",
        wrapper_args: str = "--hard",
        current_agent_id: str = "",
        rebuttal_env: str = "",
        strict_no_pathspec: bool = False,
        strict_undeclared: bool = False,
    ) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = _GIT_DIR + os.pathsep + env.get("PATH", "")
        env["WRAPPER_OP"] = wrapper_op
        env["WRAPPER_ARGS"] = wrapper_args
        if current_agent_id:
            env["R55_CURRENT_AGENT_ID"] = current_agent_id
        if rebuttal_env:
            env["R55_REBUTTAL"] = rebuttal_env
        if strict_no_pathspec:
            env["R55_STRICT_NO_PATHSPEC"] = "1"
        if strict_undeclared:
            env["R55_STRICT_UNDECLARED"] = "1"
        return subprocess.run(
            ["bash", str(HOOK)],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    # 1. No uncommitted changes -> pass.
    def test_no_uncommitted_changes_passes(self) -> None:
        result = self._run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no uncommitted", result.stdout)

    # 2. Uncommitted file in CURRENT lane's pathspec -> pass.
    def test_current_lane_owned_file_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._stage("tools/foo.py")
        result = self._run_hook(current_agent_id="lane-A")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("does not affect any sibling-lane", result.stdout)

    # 3. Uncommitted file in SIBLING lane's pathspec -> FAIL.
    def test_sibling_lane_owned_file_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-SIBLING",
             "files": ["agent_briefs/sibling_brief.md"],
             "expires_at": future},
        ])
        self._stage("agent_briefs/sibling_brief.md")
        result = self._run_hook(current_agent_id="lane-A")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("agent_briefs/sibling_brief.md", result.stdout)
        self.assertIn("Rule 55", result.stdout)

    # 4. R55_REBUTTAL env var (non-empty) overrides refusal.
    def test_env_rebuttal_overrides_refusal(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-SIBLING",
             "files": ["agent_briefs/sibling_brief.md"],
             "expires_at": future},
        ])
        self._stage("agent_briefs/sibling_brief.md")
        result = self._run_hook(
            current_agent_id="lane-A",
            rebuttal_env="operator authorized cleanup, all lanes acknowledged",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rebuttal accepted", result.stdout)

    # 5. Missing pathspec -> warn-only pass by default.
    def test_missing_pathspec_warn_only_pass(self) -> None:
        self._stage("tools/foo.py")
        result = self._run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WARNING", result.stdout)
        self.assertIn("missing", result.stdout)

    # 6. Non-destructive `git reset` (no --hard/--merge/--keep) -> pass.
    def test_soft_reset_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-SIBLING",
             "files": ["agent_briefs/sibling_brief.md"],
             "expires_at": future},
        ])
        self._stage("agent_briefs/sibling_brief.md")
        result = self._run_hook(
            current_agent_id="lane-A",
            wrapper_args="--soft HEAD~1",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # 7. `git reset --hard` is policed.
    def test_hard_reset_is_policed(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-SIBLING",
             "files": ["agent_briefs/sibling_brief.md"],
             "expires_at": future},
        ])
        self._stage("agent_briefs/sibling_brief.md")
        result = self._run_hook(
            current_agent_id="lane-A",
            wrapper_args="--hard HEAD",
        )
        # lane-A is not in pathspec; sibling-owned file is at risk.
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)

    # 8. Rebuttal file is honored.
    def test_rebuttal_file_honored(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-SIBLING",
             "files": ["agent_briefs/sibling_brief.md"],
             "expires_at": future},
        ])
        self._stage("agent_briefs/sibling_brief.md")
        self._write_rebuttal_file("operator authorized housekeeping sweep")
        result = self._run_hook(current_agent_id="lane-A")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rebuttal accepted", result.stdout)

    # 9. Empty rebuttal does NOT silence the gate.
    def test_empty_rebuttal_does_not_pass(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-SIBLING",
             "files": ["agent_briefs/sibling_brief.md"],
             "expires_at": future},
        ])
        self._stage("agent_briefs/sibling_brief.md")
        result = self._run_hook(
            current_agent_id="lane-A",
            rebuttal_env="   ",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    # 10. Oversized rebuttal (>200 chars) is ignored.
    def test_oversized_rebuttal_is_ignored(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-SIBLING",
             "files": ["agent_briefs/sibling_brief.md"],
             "expires_at": future},
        ])
        self._stage("agent_briefs/sibling_brief.md")
        result = self._run_hook(
            current_agent_id="lane-A",
            rebuttal_env="x" * 201,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    # 11. R55_STRICT_NO_PATHSPEC=1 hard-fails on missing pathspec.
    def test_strict_no_pathspec_hard_fails(self) -> None:
        self._stage("tools/foo.py")
        result = self._run_hook(strict_no_pathspec=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    # 12. Multi-agent declaration: undeclared file warns but does not refuse
    # (unless R55_STRICT_UNDECLARED=1).
    def test_undeclared_file_warns_only(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        # 'tools/random.py' is not in any declared pathspec.
        self._stage("tools/random.py")
        result = self._run_hook(current_agent_id="lane-A")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("undeclared", result.stdout)

    # 13. Expired sibling pathspec is ignored.
    def test_expired_sibling_pathspec_ignored(self) -> None:
        past = _iso(datetime.now(timezone.utc) - timedelta(hours=3))
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-EXPIRED",
             "files": ["agent_briefs/sibling_brief.md"],
             "expires_at": past},
        ])
        self._stage("agent_briefs/sibling_brief.md")
        result = self._run_hook(current_agent_id="lane-A")
        # sibling-EXPIRED is no longer live; the file is undeclared. With
        # default strictness, undeclared warns but passes.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
