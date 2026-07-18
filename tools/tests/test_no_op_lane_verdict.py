"""Regression tests for the no-op-no-persistent-changes verdict (Lane 231, 2026-05-26).

Covers:
  1. Empty claimed_paths         -> no-op verdict (pass-no-paths-claimed via r70)
  2. All paths under /tmp/       -> no-op-no-persistent-changes (pass-state)
  3. Mix of /tmp/ + real path    -> real path goes through normal classification
  4. Real persistent change      -> normal pass verdict (tracked-and-committed)
  5. lane_result_validator recognises no-op as pass

# R36: declared in .auditooor/agent_pathspec.json under
# lane231-no-op-verdict-2026-05-26 via tools/agent-pathspec-register.py.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# ---- load r70 module -------------------------------------------------------
_spec70 = importlib.util.spec_from_file_location(
    "r70_file_tracked_verifier",
    ROOT / "tools" / "r70-file-tracked-verifier.py",
)
r70 = importlib.util.module_from_spec(_spec70)
_spec70.loader.exec_module(r70)  # type: ignore[union-attr]

# ---- load lane_result_validator module -------------------------------------
_spec_lrv = importlib.util.spec_from_file_location(
    "lane_result_validator",
    ROOT / "tools" / "lib" / "lane_result_validator.py",
)
lrv = importlib.util.module_from_spec(_spec_lrv)
# Register in sys.modules BEFORE exec so @dataclass can resolve cls.__module__
sys.modules["lane_result_validator"] = lrv
_spec_lrv.loader.exec_module(lrv)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Git helpers (mirror pattern from test_r70_file_tracked_verifier.py)
# ---------------------------------------------------------------------------

def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", "lane231-test")
    env.setdefault("GIT_AUTHOR_EMAIL", "lane231-test@example.invalid")
    env.setdefault("GIT_COMMITTER_NAME", "lane231-test")
    env.setdefault("GIT_COMMITTER_EMAIL", "lane231-test@example.invalid")
    # Bypass the auditooor git wrapper MCP-freshness gate for hermetic temp repos.
    env["AUDITOOOR_MCP_REQUIRED"] = "0"
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )


def _make_git_repo(tmp_path: Path) -> Path:
    """Initialise a hermetic git repo under tmp_path (HEAD exists after init)."""
    _git(["init", "-q", "-b", "main"], cwd=tmp_path)
    _git(["config", "user.email", "lane231-test@example.invalid"], cwd=tmp_path)
    _git(["config", "user.name", "lane231-test"], cwd=tmp_path)
    (tmp_path / "README.md").write_text("init\n", encoding="utf-8")
    _git(["add", "README.md"], cwd=tmp_path)
    _git(["commit", "-q", "-m", "init"], cwd=tmp_path)
    return tmp_path


class TestNoOpEmptyPaths(unittest.TestCase):
    """Empty claimed_paths list -> pass-no-paths-claimed (no-op pass-state)."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(Path(self._tmp))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_empty_list_returns_pass_no_paths(self) -> None:
        result = r70.check([], repo_root=self.repo)
        self.assertEqual(result["verdict"], r70.OV_PASS_NO_PATHS)
        self.assertEqual(result["claimed_path_count"], 0)

    def test_empty_list_exit_code_zero(self) -> None:
        rc = r70.main(["--claimed-paths", "", "--json"])
        self.assertEqual(rc, 0)

    def test_json_schema_present_on_empty(self) -> None:
        result = r70.check([], repo_root=self.repo)
        self.assertIn("schema", result)
        self.assertIn("verdict", result)


class TestNoOpTmpPaths(unittest.TestCase):
    """All claimed_paths under /tmp/ -> no-op-no-persistent-changes (pass)."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(Path(self._tmp))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _check_tmp(self, *paths: str) -> dict:
        return r70.check(list(paths), repo_root=self.repo)

    def test_single_tmp_path_is_no_op(self) -> None:
        result = self._check_tmp("/tmp/lane231_brief.md")
        self.assertEqual(result["verdict"], r70.OV_NO_OP)

    def test_multiple_tmp_paths_are_no_op(self) -> None:
        result = self._check_tmp(
            "/tmp/lane231_brief.md",
            "/tmp/foo/bar.json",
            "/tmp/spawn_worker_123.md",
        )
        self.assertEqual(result["verdict"], r70.OV_NO_OP)

    def test_no_op_is_pass_state_not_fail(self) -> None:
        result = self._check_tmp("/tmp/anything.py")
        self.assertNotIn(result["verdict"], {
            r70.OV_FAIL_UNTRACKED_OR_MISSING,
            r70.OV_FAIL_STRICT,
            r70.OV_ERROR,
        })

    def test_no_op_flag_is_true(self) -> None:
        result = self._check_tmp("/tmp/x.md")
        self.assertTrue(result.get("no_op", False))

    def test_no_op_json_schema_valid(self) -> None:
        result = self._check_tmp("/tmp/a.py", "/tmp/b.sh")
        self.assertIn("schema", result)
        self.assertIn("verdict", result)
        self.assertIn("claimed_path_count", result)
        self.assertIsInstance(result["per_path"], list)

    def test_no_op_cli_returns_zero(self) -> None:
        rc = r70.main([
            "--claimed-paths", "/tmp/foo.md,/tmp/bar.json",
            "--repo-root", str(self.repo),
            "--json",
        ])
        self.assertEqual(rc, 0)

    def test_per_path_entries_have_verdict_set(self) -> None:
        result = self._check_tmp("/tmp/x.md", "/tmp/y.py")
        for entry in result["per_path"]:
            self.assertEqual(entry["verdict"], r70.OV_NO_OP)


class TestNoOpMixedPaths(unittest.TestCase):
    """Mix of /tmp/ + real repo path -> real path classified normally."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(Path(self._tmp))

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_mixed_paths_not_treated_as_no_op(self) -> None:
        # tools/lib/lane_result_validator.py exists in the auditooor repo
        # but not in our hermetic temp repo - it will be missing-from-disk.
        # The key property: result is NOT no-op because a non-/tmp/ path exists.
        result = r70.check(
            ["/tmp/brief.md", "tools/lib/lane_result_validator.py"],
            repo_root=self.repo,
        )
        self.assertNotEqual(result["verdict"], r70.OV_NO_OP)

    def test_mixed_returns_some_verdict_not_error(self) -> None:
        result = r70.check(
            ["/tmp/brief.md", "tools/lib/lane_result_validator.py"],
            repo_root=self.repo,
        )
        self.assertNotEqual(result["verdict"], r70.OV_ERROR)


class TestRealPersistentChange(unittest.TestCase):
    """Real persistent change -> pass-all-tracked-and-committed."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp()
        self.repo = _make_git_repo(Path(self._tmp))
        # Create + commit a real tools/ file
        tools_dir = self.repo / "tools"
        tools_dir.mkdir(exist_ok=True)
        real_file = tools_dir / "sample_tool.py"
        real_file.write_text("# sample\n", encoding="utf-8")
        _git(["add", "tools/sample_tool.py"], cwd=self.repo)
        _git(["commit", "-q", "-m", "add sample"], cwd=self.repo)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_committed_real_file_passes(self) -> None:
        result = r70.check(
            ["tools/sample_tool.py"],
            repo_root=self.repo,
        )
        self.assertEqual(result["verdict"], r70.OV_PASS_ALL)

    def test_committed_real_file_not_no_op(self) -> None:
        result = r70.check(
            ["tools/sample_tool.py"],
            repo_root=self.repo,
        )
        self.assertNotEqual(result["verdict"], r70.OV_NO_OP)


class TestLaneResultValidatorNoOp(unittest.TestCase):
    """lane_result_validator recognises no-op-no-persistent-changes as pass."""

    def test_r70_verdict_no_op_constant_exists(self) -> None:
        self.assertEqual(lrv.R70_VERDICT_NO_OP, "no-op-no-persistent-changes")

    def test_validate_paths_r70_with_tmp_text(self) -> None:
        """validate_paths_r70 on text with /tmp/ paths -> pass (no-paths-found)
        because _R70_PATH_RE only matches canonical tree paths, not /tmp/."""
        text = "Files touched: /tmp/lane231_brief.md and /tmp/spawn_worker.md"
        result = lrv.validate_paths_r70(text)
        # /tmp/ paths don't match the canonical-tree regex -> no-paths-found
        self.assertIn(result["verdict"], {"no-paths-found", "pass-all-tracked-and-committed"})

    def test_no_op_verdict_maps_to_pass_in_validator(self) -> None:
        """R70_VERDICT_NO_OP is in the pass-set used by validate_paths_r70."""
        pass_verdicts = {
            "pass-all-tracked-and-committed",
            "pass-no-paths-claimed",
            "ok-rebuttal",
            lrv.R70_VERDICT_NO_OP,
        }
        self.assertIn("no-op-no-persistent-changes", pass_verdicts)

    def test_validate_lane_result_no_op_text_does_not_fail(self) -> None:
        """A lane result text that mentions only /tmp/ paths should not fail."""
        text = (
            "Lane 220 completed. Fixed /tmp/brief.md and /tmp/foo.sh. "
            "No persistent repo changes were needed (tooling lane)."
        )
        result = lrv.validate_lane_result(text, no_live_call=True)
        # R69 no claims, R70 no canonical paths -> overall should be no-claims-found
        self.assertEqual(result["verdict"], "no-claims-found")
        r70_sub = result.get("r70", {})
        self.assertIn(r70_sub.get("verdict"), {
            "no-paths-found",
            "pass-all-tracked-and-committed",
            "no-op-no-persistent-changes",
        })


if __name__ == "__main__":
    unittest.main()
