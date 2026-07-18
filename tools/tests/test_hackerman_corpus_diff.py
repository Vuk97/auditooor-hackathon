"""Tests for ``tools/hackerman-corpus-diff.py``.

Cases (>=8):

1. empty repo (no commits touching prefix) -> totals all zero
2. single added file -> 1 added, subtree resolved from first path component
3. single deleted file -> 1 deleted
4. modified file (same path, different content) -> 1 modified, NOT
   counted as add+delete
5. multi-subtree mixed (added in A, modified in B, deleted in C)
6. flat file directly under prefix bucketed under ``_flat``
7. unchanged paths are skipped (no double counting)
8. JSON envelope schema == ``auditooor.hackerman_corpus_diff.v1``
9. subtrees ordering by total desc, then name asc
10. CLI ``--json`` exit 0 + parseable envelope
11. ``--from`` ref that doesn't exist -> empty base, all head treated as added
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-corpus-diff.py"


def _load_tool() -> Any:
    name = "_hackerman_corpus_diff_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _git(repo: Path, args: list[str], check: bool = True) -> str:
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", "t")
    env.setdefault("GIT_AUTHOR_EMAIL", "t@t")
    env.setdefault("GIT_COMMITTER_NAME", "t")
    env.setdefault("GIT_COMMITTER_EMAIL", "t@t")
    proc = subprocess.run(
        ["git", "-C", str(repo)] + args,
        capture_output=True, text=True, env=env,
    )
    if check and proc.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed: {proc.stderr}"
        )
    return proc.stdout


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, ["init", "-q", "-b", "main"])
    _git(repo, ["config", "user.email", "t@t"])
    _git(repo, ["config", "user.name", "t"])
    # Empty commit so HEAD exists.
    _git(repo, ["commit", "--allow-empty", "-q", "-m", "init"])


def _write_and_commit(
    repo: Path, rel: str, content: str, msg: str
) -> str:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    _git(repo, ["add", "--", rel])
    _git(repo, ["commit", "-q", "-m", msg])
    return _git(repo, ["rev-parse", "HEAD"]).strip()


def _rm_and_commit(repo: Path, rel: str, msg: str) -> str:
    _git(repo, ["rm", "-q", "--", rel])
    _git(repo, ["commit", "-q", "-m", msg])
    return _git(repo, ["rev-parse", "HEAD"]).strip()


PREFIX = "audit/corpus_tags/tags"


class TestCorpusDiff(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        _init_repo(self.repo)
        self.base_sha = _git(self.repo, ["rev-parse", "HEAD"]).strip()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # 1
    def test_empty_no_changes(self) -> None:
        diff = tool.build_diff(self.repo, self.base_sha, "HEAD", PREFIX)
        self.assertEqual(diff["totals"]["total"], 0)
        self.assertEqual(diff["subtrees"], [])
        self.assertEqual(diff["schema"], tool.SCHEMA)

    # 2
    def test_single_added(self) -> None:
        _write_and_commit(
            self.repo, f"{PREFIX}/lending/r1/record.yaml", "a: 1\n", "add r1"
        )
        diff = tool.build_diff(self.repo, self.base_sha, "HEAD", PREFIX)
        self.assertEqual(diff["totals"]["added"], 1)
        self.assertEqual(diff["totals"]["modified"], 0)
        self.assertEqual(diff["totals"]["deleted"], 0)
        self.assertEqual(diff["subtrees"][0]["subtree"], "lending")
        self.assertEqual(diff["subtrees"][0]["added"], 1)

    # 3
    def test_single_deleted(self) -> None:
        _write_and_commit(
            self.repo, f"{PREFIX}/dex/r1/record.yaml", "a: 1\n", "add r1"
        )
        base = _git(self.repo, ["rev-parse", "HEAD"]).strip()
        _rm_and_commit(self.repo, f"{PREFIX}/dex/r1/record.yaml", "rm r1")
        diff = tool.build_diff(self.repo, base, "HEAD", PREFIX)
        self.assertEqual(diff["totals"]["deleted"], 1)
        self.assertEqual(diff["totals"]["added"], 0)
        self.assertEqual(diff["subtrees"][0]["subtree"], "dex")
        self.assertEqual(diff["subtrees"][0]["deleted"], 1)

    # 4
    def test_modified_not_double_counted(self) -> None:
        _write_and_commit(
            self.repo, f"{PREFIX}/bridge/r1/record.yaml", "a: 1\n", "add"
        )
        base = _git(self.repo, ["rev-parse", "HEAD"]).strip()
        _write_and_commit(
            self.repo, f"{PREFIX}/bridge/r1/record.yaml", "a: 2\n", "edit"
        )
        diff = tool.build_diff(self.repo, base, "HEAD", PREFIX)
        self.assertEqual(diff["totals"]["modified"], 1)
        self.assertEqual(diff["totals"]["added"], 0)
        self.assertEqual(diff["totals"]["deleted"], 0)
        self.assertEqual(diff["subtrees"][0]["subtree"], "bridge")
        self.assertEqual(diff["subtrees"][0]["modified"], 1)

    # 5
    def test_multi_subtree_mixed(self) -> None:
        # Base: B has r1, C has r1
        _write_and_commit(self.repo, f"{PREFIX}/B/r1/record.yaml", "x: 1\n", "B-add")
        _write_and_commit(self.repo, f"{PREFIX}/C/r1/record.yaml", "y: 1\n", "C-add")
        base = _git(self.repo, ["rev-parse", "HEAD"]).strip()
        # Head: add in A, modify B, delete C
        _write_and_commit(self.repo, f"{PREFIX}/A/r1/record.yaml", "z: 1\n", "A-add")
        _write_and_commit(self.repo, f"{PREFIX}/B/r1/record.yaml", "x: 2\n", "B-mod")
        _rm_and_commit(self.repo, f"{PREFIX}/C/r1/record.yaml", "C-del")
        diff = tool.build_diff(self.repo, base, "HEAD", PREFIX)
        self.assertEqual(diff["totals"]["added"], 1)
        self.assertEqual(diff["totals"]["modified"], 1)
        self.assertEqual(diff["totals"]["deleted"], 1)
        by_sub = {r["subtree"]: r for r in diff["subtrees"]}
        self.assertEqual(by_sub["A"]["added"], 1)
        self.assertEqual(by_sub["B"]["modified"], 1)
        self.assertEqual(by_sub["C"]["deleted"], 1)

    # 6
    def test_flat_bucket(self) -> None:
        _write_and_commit(
            self.repo, f"{PREFIX}/some-flat.yaml", "k: 1\n", "flat-add"
        )
        diff = tool.build_diff(self.repo, self.base_sha, "HEAD", PREFIX)
        self.assertEqual(diff["totals"]["added"], 1)
        self.assertEqual(diff["subtrees"][0]["subtree"], "_flat")

    # 7
    def test_unchanged_skipped(self) -> None:
        _write_and_commit(self.repo, f"{PREFIX}/x/r1/record.yaml", "a: 1\n", "x")
        base = _git(self.repo, ["rev-parse", "HEAD"]).strip()
        # Empty commit -> nothing under prefix changed
        _git(self.repo, ["commit", "--allow-empty", "-q", "-m", "no-op"])
        diff = tool.build_diff(self.repo, base, "HEAD", PREFIX)
        self.assertEqual(diff["totals"]["total"], 0)
        self.assertEqual(diff["subtrees"], [])

    # 8
    def test_schema_envelope(self) -> None:
        diff = tool.build_diff(self.repo, self.base_sha, "HEAD", PREFIX)
        self.assertEqual(diff["schema"], "auditooor.hackerman_corpus_diff.v1")
        for key in (
            "generated_at", "repo", "tags_prefix",
            "from_ref", "to_ref", "from_sha", "to_sha",
            "totals", "subtrees",
        ):
            self.assertIn(key, diff)

    # 9
    def test_subtree_ordering(self) -> None:
        # A has 1 change, B has 3 changes, C has 1 change. Expect B first,
        # then A, C tied on total -> alphabetical.
        for i in range(3):
            _write_and_commit(
                self.repo, f"{PREFIX}/B/r{i}/record.yaml", f"v: {i}\n", f"B{i}"
            )
        _write_and_commit(self.repo, f"{PREFIX}/A/r1/record.yaml", "v: 1\n", "A")
        _write_and_commit(self.repo, f"{PREFIX}/C/r1/record.yaml", "v: 1\n", "C")
        diff = tool.build_diff(self.repo, self.base_sha, "HEAD", PREFIX)
        order = [r["subtree"] for r in diff["subtrees"]]
        self.assertEqual(order, ["B", "A", "C"])

    # 10
    def test_cli_json(self) -> None:
        _write_and_commit(
            self.repo, f"{PREFIX}/lending/r1/record.yaml", "a: 1\n", "add"
        )
        proc = subprocess.run(
            [
                sys.executable, str(TOOL_PATH),
                "--repo", str(self.repo),
                "--from", self.base_sha,
                "--to", "HEAD",
                "--json",
            ],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertEqual(payload["totals"]["added"], 1)

    # 11
    def test_missing_from_ref_treated_as_empty(self) -> None:
        _write_and_commit(
            self.repo, f"{PREFIX}/lending/r1/record.yaml", "a: 1\n", "add"
        )
        # Bogus ref -> base set empty -> everything in HEAD is "added"
        diff = tool.build_diff(
            self.repo, "refs/heads/does-not-exist", "HEAD", PREFIX
        )
        self.assertEqual(diff["totals"]["added"], 1)
        self.assertEqual(diff["totals"]["deleted"], 0)

    # 12
    def test_render_table_smoke(self) -> None:
        _write_and_commit(
            self.repo, f"{PREFIX}/lending/r1/record.yaml", "a: 1\n", "add"
        )
        diff = tool.build_diff(self.repo, self.base_sha, "HEAD", PREFIX)
        table = tool.render_table(diff)
        self.assertIn("lending", table)
        self.assertIn("hackerman-corpus-diff", table)


if __name__ == "__main__":
    unittest.main()
