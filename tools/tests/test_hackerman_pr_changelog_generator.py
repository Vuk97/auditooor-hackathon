"""Tests for ``tools/hackerman-pr-changelog-generator.py``.

Cases (>=6):

1. markdown format on synthetic 3-commit branch (1 W2.1, 1 W2.4, 1 W2.9)
2. JSON format on same synthetic branch + schema check
3. empty branch (base == branch) emits "No commits" cleanly
4. commit with no W2.x ref groups under "Unclassified"
5. commit with multiple W2.x refs (e.g. "W2.1 + W2.5 combined") gets
   multi-lane attribution
6. context_pack_id extraction tolerates legacy commits without the
   hook footer (commit with no footer -> ``context_pack_id`` is None)
7. close-criteria detection: a commit body mentioning Check #73 and
   Check #74 flips C4 to covered
8. CLI --format json --output writes parseable JSON
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-pr-changelog-generator.py"


def _load_tool() -> Any:
    name = "_hackerman_pr_changelog_generator_test_mod"
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


def _init_repo(repo: Path) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, ["init", "-q", "-b", "main"])
    _git(repo, ["config", "user.email", "t@t"])
    _git(repo, ["config", "user.name", "t"])
    _git(repo, ["commit", "--allow-empty", "-q", "-m", "init"])
    return _git(repo, ["rev-parse", "HEAD"]).strip()


def _commit_on_branch(
    repo: Path, branch: str, path: str, content: str, msg: str,
) -> str:
    cur = _git(repo, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()
    if cur != branch:
        # create or switch
        existing = _git(
            repo, ["branch", "--list", branch], check=False,
        ).strip()
        if existing:
            _git(repo, ["checkout", "-q", branch])
        else:
            _git(repo, ["checkout", "-q", "-b", branch])
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    _git(repo, ["add", "--", path])
    _git(repo, ["commit", "-q", "-F", "-"], check=False)
    # That last commit -F - won't work easily; redo properly:
    return ""


def _commit(
    repo: Path, path: str, content: str, msg: str,
) -> str:
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    _git(repo, ["add", "--", path])
    # write message to a temp file for multi-line bodies
    msg_file = repo / ".tmp_msg"
    msg_file.write_text(msg, encoding="utf-8")
    _git(repo, ["commit", "-q", "-F", str(msg_file)])
    msg_file.unlink()
    return _git(repo, ["rev-parse", "HEAD"]).strip()


class TestPRChangelogGenerator(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.base_sha = _init_repo(self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _branch_from_base(self, branch: str) -> None:
        _git(self.repo, ["checkout", "-q", "-b", branch])

    def test_markdown_three_lane_branch(self) -> None:
        self._branch_from_base("feat")
        _commit(
            self.repo, "a.txt", "a\n",
            (
                "Wave-2 W2.1: migrate schema v1 -> v1.1\n\n"
                "Body line one.\n\n"
                "context_pack_id: auditooor.vault_context_pack.v1:resume:aaa1\n"
            ),
        )
        _commit(
            self.repo, "b.txt", "b\n",
            (
                "Wave-2 W2.4: ship audit-firm-PDF extractor\n\n"
                "context_pack_id: auditooor.vault_context_pack.v1:resume:bbb2\n"
            ),
        )
        _commit(
            self.repo, "c.txt", "c\n",
            (
                "Wave-2 W2.9: wire R38 + R39 gates as Check #73 / Check #74\n\n"
                "context_pack_id: auditooor.vault_context_pack.v1:resume:ccc3\n"
            ),
        )
        out = tool.generate(self.repo, "main", "feat", "markdown")
        self.assertIn("# PR Changelog: feat -> main", out)
        self.assertIn("| W2.1 | 1 |", out)
        self.assertIn("| W2.4 | 1 |", out)
        self.assertIn("| W2.9 | 1 |", out)
        # Close criteria coverage table renders
        self.assertIn("Wave-2-A Close Criteria Coverage", out)
        # No em-dashes
        self.assertNotIn("—", out)
        self.assertNotIn("–", out)

    def test_json_format_schema(self) -> None:
        self._branch_from_base("feat")
        _commit(
            self.repo, "a.txt", "a\n",
            (
                "Wave-2 W2.1: migrate schema v1 -> v1.1\n\n"
                "context_pack_id: auditooor.vault_context_pack.v1:resume:aaa1\n"
            ),
        )
        out = tool.generate(self.repo, "main", "feat", "json")
        parsed = json.loads(out)
        self.assertEqual(parsed["schema"], "auditooor.hackerman_pr_changelog.v1")
        self.assertEqual(parsed["branch"], "feat")
        self.assertEqual(parsed["base"], "main")
        self.assertEqual(parsed["total_commits"], 1)
        self.assertIn("W2.1", parsed["lanes"])
        self.assertEqual(len(parsed["commits"]), 1)
        self.assertEqual(
            parsed["unique_context_pack_ids"],
            ["auditooor.vault_context_pack.v1:resume:aaa1"],
        )

    def test_empty_branch(self) -> None:
        # base == branch -> no commits
        out = tool.generate(self.repo, "main", "main", "markdown")
        self.assertIn("No commits", out)
        out_json = tool.generate(self.repo, "main", "main", "json")
        parsed = json.loads(out_json)
        self.assertEqual(parsed["total_commits"], 0)
        self.assertEqual(parsed["commits"], [])

    def test_unclassified_lane(self) -> None:
        self._branch_from_base("feat")
        _commit(
            self.repo, "x.txt", "x\n",
            "chore: random tweak with no lane marker\n",
        )
        out = tool.generate(self.repo, "main", "feat", "json")
        parsed = json.loads(out)
        self.assertIn("Unclassified", parsed["lanes"])
        self.assertEqual(parsed["commits"][0]["lanes"], ["Unclassified"])

    def test_multi_lane_attribution(self) -> None:
        self._branch_from_base("feat")
        _commit(
            self.repo, "x.txt", "x\n",
            (
                "Wave-2 W2.1 + W2.5 combined: schema migration plus "
                "audit-firm-PDF backfill\n\n"
                "context_pack_id: auditooor.vault_context_pack.v1:resume:ddd4\n"
            ),
        )
        out = tool.generate(self.repo, "main", "feat", "json")
        parsed = json.loads(out)
        self.assertIn("W2.1", parsed["lanes"])
        self.assertIn("W2.5", parsed["lanes"])
        # Same commit appears in both lane groupings
        self.assertEqual(parsed["lanes"]["W2.1"], parsed["lanes"]["W2.5"])

    def test_legacy_commit_no_context_pack(self) -> None:
        self._branch_from_base("feat")
        _commit(
            self.repo, "x.txt", "x\n",
            "Wave-2 W2.1: legacy commit predates the hook footer\n",
        )
        out = tool.generate(self.repo, "main", "feat", "json")
        parsed = json.loads(out)
        self.assertIsNone(parsed["commits"][0]["context_pack_id"])
        self.assertEqual(parsed["unique_context_pack_ids"], [])

    def test_close_criteria_c4_covered(self) -> None:
        self._branch_from_base("feat")
        _commit(
            self.repo, "x.txt", "x\n",
            (
                "Wave-2 W2.9: wire R38 + R39 gates as Check #73 / Check #74\n\n"
                "context_pack_id: auditooor.vault_context_pack.v1:resume:eee5\n"
            ),
        )
        out = tool.generate(self.repo, "main", "feat", "json")
        parsed = json.loads(out)
        c4 = next(c for c in parsed["close_criteria"] if c["id"] == "C4")
        self.assertTrue(c4["covered"])
        self.assertEqual(len(c4["commits"]), 1)

    def test_cli_json_output_file(self) -> None:
        self._branch_from_base("feat")
        _commit(
            self.repo, "x.txt", "x\n",
            (
                "Wave-2 W2.1: schema v1 -> v1.1 migration\n\n"
                "context_pack_id: auditooor.vault_context_pack.v1:resume:fff6\n"
            ),
        )
        with tempfile.NamedTemporaryFile(
            "w+", suffix=".json", delete=False,
        ) as f:
            out_path = f.name
        try:
            rc = tool.main(
                [
                    "--repo", str(self.repo),
                    "--base", "main",
                    "--branch", "feat",
                    "--format", "json",
                    "--output", out_path,
                ]
            )
            self.assertEqual(rc, 0)
            with open(out_path, "r", encoding="utf-8") as f:
                parsed = json.loads(f.read())
            self.assertEqual(
                parsed["schema"], "auditooor.hackerman_pr_changelog.v1",
            )
            self.assertEqual(parsed["total_commits"], 1)
        finally:
            Path(out_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
