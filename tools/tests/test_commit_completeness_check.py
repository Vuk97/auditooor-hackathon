"""Unit tests for tools/commit-completeness-check.py.

Non-vacuous discipline: every gate behavior is tested in BOTH directions
(present -> FAIL, removed -> PASS) over a REAL git repo so the git plumbing
(`git diff --cached`, `git diff`, `git ls-files --others`) is genuinely
exercised, not mocked away.

Caveat-B anchor case: a registry with 3 files but only 2 staged must FAIL
and name the missing one; all 3 staged must PASS.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "commit-completeness-check.py"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CommitCompletenessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(tempfile.mkdtemp(prefix="cc_check_"))
        self._git("init", "-q")
        self._git("config", "user.email", "t@example.com")
        self._git("config", "user.name", "tester")
        # Seed a HEAD commit so HEAD baseline exists.
        (self.repo / "seed.txt").write_text("seed\n", encoding="utf-8")
        self._git("add", "seed.txt")
        self._git("commit", "-q", "-m", "seed")
        self.pathspec = self.repo / ".auditooor" / "agent_pathspec.json"
        self.pathspec.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.repo, ignore_errors=True)

    # -- helpers ---------------------------------------------------------
    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            capture_output=True, text=True, check=False)

    def _write_registry(self, lane: str, files: list[str],
                        ttl_seconds: int = 3600,
                        extra_agents: list[dict] | None = None) -> None:
        exp = _iso(datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds))
        agents = [{"agent_id": lane, "files": files, "expires_at": exp}]
        if extra_agents:
            agents.extend(extra_agents)
        self.pathspec.write_text(
            json.dumps({"agents": agents}, indent=2), encoding="utf-8")

    def _touch(self, rel: str, content: str = "x\n") -> None:
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        cmd = [sys.executable, str(TOOL),
               "--repo-root", str(self.repo),
               "--pathspec-file", str(self.pathspec), *args]
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    # -- the caveat-B anchor: 3 registered, 2 staged ---------------------
    def test_under_commit_three_registered_two_staged_fails(self) -> None:
        files = ["a.py", "b.py", "c.py"]
        self._write_registry("lane-X", files)
        for f in files:
            self._touch(f)
        # Stage only 2 of 3.
        self._git("add", "a.py", "b.py")
        res = self._run("--lane", "lane-X", "--no-over-commit")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("UNDER-COMMIT", res.stdout)
        self.assertIn("c.py", res.stdout)
        # The staged ones must NOT be reported as missing.
        self.assertNotIn("    - a.py", res.stdout)
        self.assertNotIn("    - b.py", res.stdout)

    def test_under_commit_all_three_staged_passes(self) -> None:
        files = ["a.py", "b.py", "c.py"]
        self._write_registry("lane-X", files)
        for f in files:
            self._touch(f)
        self._git("add", "a.py", "b.py", "c.py")
        res = self._run("--lane", "lane-X", "--no-over-commit")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("OK", res.stdout)

    # -- registered-but-clean file is NOT an under-commit ----------------
    def test_registered_file_with_no_pending_content_is_not_under_commit(self) -> None:
        # c.py is registered but never created/changed -> no pending content.
        self._write_registry("lane-X", ["a.py", "b.py", "c.py"])
        self._touch("a.py")
        self._touch("b.py")
        self._git("add", "a.py", "b.py")
        res = self._run("--lane", "lane-X", "--no-over-commit")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    # -- untracked registered file left unstaged = under-commit ----------
    def test_untracked_registered_file_unstaged_fails(self) -> None:
        self._write_registry("lane-X", ["a.py", "b.py"])
        self._touch("a.py")
        self._touch("b.py")
        self._git("add", "a.py")  # b.py remains untracked + unstaged
        res = self._run("--lane", "lane-X", "--no-over-commit")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("b.py", res.stdout)
        self.assertIn("untracked", res.stdout)

    # -- modified-unstaged registered file = under-commit ----------------
    def test_modified_tracked_registered_file_unstaged_fails(self) -> None:
        # Commit a.py and b.py first, then modify both, stage only a.py.
        self._touch("a.py", "v1\n")
        self._touch("b.py", "v1\n")
        self._git("add", "a.py", "b.py")
        self._git("commit", "-q", "-m", "base")
        self._write_registry("lane-X", ["a.py", "b.py"])
        self._touch("a.py", "v2\n")
        self._touch("b.py", "v2\n")
        self._git("add", "a.py")
        res = self._run("--lane", "lane-X", "--no-over-commit")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("modified-unstaged", res.stdout)
        self.assertIn("b.py", res.stdout)

    # -- OVER-COMMIT: staged file in no live lane ------------------------
    def test_over_commit_unregistered_staged_file_fails(self) -> None:
        self._write_registry("lane-X", ["a.py"])
        self._touch("a.py")
        self._touch("rogue.py")
        self._git("add", "a.py", "rogue.py")
        res = self._run("--lane", "lane-X")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("OVER-COMMIT", res.stdout)
        self.assertIn("rogue.py", res.stdout)

    def test_over_commit_clean_when_staged_file_registered_to_sibling(self) -> None:
        # rogue.py is owned by a sibling live lane -> union mode = clean.
        exp = _iso(datetime.now(timezone.utc) + timedelta(seconds=3600))
        sibling = {"agent_id": "lane-Y", "files": ["rogue.py"],
                   "expires_at": exp}
        self._write_registry("lane-X", ["a.py"], extra_agents=[sibling])
        self._touch("a.py")
        self._touch("rogue.py")
        self._git("add", "a.py", "rogue.py")
        res = self._run("--lane", "lane-X")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_over_commit_strict_lane_rejects_sibling_owned_file(self) -> None:
        # Same setup but --strict-lane -> sibling ownership does NOT excuse it.
        exp = _iso(datetime.now(timezone.utc) + timedelta(seconds=3600))
        sibling = {"agent_id": "lane-Y", "files": ["rogue.py"],
                   "expires_at": exp}
        self._write_registry("lane-X", ["a.py"], extra_agents=[sibling])
        self._touch("a.py")
        self._touch("rogue.py")
        self._git("add", "a.py", "rogue.py")
        res = self._run("--lane", "lane-X", "--strict-lane")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("OVER-COMMIT", res.stdout)
        self.assertIn("rogue.py", res.stdout)

    # -- combined under + over commit both reported ----------------------
    def test_both_under_and_over_commit_reported(self) -> None:
        self._write_registry("lane-X", ["a.py", "b.py"])
        self._touch("a.py")
        self._touch("b.py")      # registered, pending, unstaged -> under
        self._touch("rogue.py")  # unregistered, staged -> over
        self._git("add", "a.py", "rogue.py")
        res = self._run("--lane", "lane-X")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("UNDER-COMMIT", res.stdout)
        self.assertIn("OVER-COMMIT", res.stdout)
        self.assertIn("b.py", res.stdout)
        self.assertIn("rogue.py", res.stdout)

    # -- fully clean lane passes both checks -----------------------------
    def test_fully_clean_lane_passes(self) -> None:
        self._write_registry("lane-X", ["a.py", "b.py"])
        self._touch("a.py")
        self._touch("b.py")
        self._git("add", "a.py", "b.py")
        res = self._run("--lane", "lane-X")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("OK", res.stdout)

    # -- environment / usage failures (fail-closed rc=2) -----------------
    def test_lane_not_found_rc2(self) -> None:
        self._write_registry("lane-X", ["a.py"])
        res = self._run("--lane", "lane-MISSING")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("not found", res.stderr)

    def test_expired_lane_rc2_without_include_flag(self) -> None:
        exp = _iso(datetime.now(timezone.utc) - timedelta(seconds=60))
        self.pathspec.write_text(json.dumps({"agents": [
            {"agent_id": "lane-X", "files": ["a.py"], "expires_at": exp}]}),
            encoding="utf-8")
        res = self._run("--lane", "lane-X", "--no-over-commit")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("EXPIRED", res.stderr)

    def test_expired_lane_checkable_with_include_expired(self) -> None:
        exp = _iso(datetime.now(timezone.utc) - timedelta(seconds=60))
        self.pathspec.write_text(json.dumps({"agents": [
            {"agent_id": "lane-X", "files": ["a.py", "b.py"],
             "expires_at": exp}]}), encoding="utf-8")
        self._touch("a.py")
        self._touch("b.py")
        self._git("add", "a.py")  # under-commit b.py
        res = self._run("--lane", "lane-X", "--no-over-commit",
                        "--include-expired")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("b.py", res.stdout)

    def test_empty_files_list_rc2(self) -> None:
        self._write_registry("lane-X", [])
        res = self._run("--lane", "lane-X")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("empty", res.stderr)

    # -- flat single-agent registry shape supported ----------------------
    def test_flat_single_agent_shape(self) -> None:
        exp = _iso(datetime.now(timezone.utc) + timedelta(seconds=3600))
        self.pathspec.write_text(json.dumps(
            {"agent_id": "lane-X", "files": ["a.py", "b.py"],
             "expires_at": exp}), encoding="utf-8")
        self._touch("a.py")
        self._touch("b.py")
        self._git("add", "a.py")
        res = self._run("--lane", "lane-X", "--no-over-commit")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("b.py", res.stdout)


if __name__ == "__main__":
    unittest.main()
