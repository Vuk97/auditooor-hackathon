#!/usr/bin/env python3
"""Tests for cut-pristine-guard: fail-closed when the audited source is dirty
(leftover mutation-test operators), pristine otherwise; test/PoC edits ignored."""
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "cut_pristine_guard",
    Path(__file__).resolve().parent.parent / "cut-pristine-guard.py",
)
mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mod)


def _git(root, *a):
    subprocess.run(["git", "-C", str(root), *a], capture_output=True, text=True, check=False)


def _mk_repo(tmp):
    root = Path(tmp)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t.t")
    _git(root, "config", "user.name", "t")
    (root / "contracts" / "modules").mkdir(parents=True)
    (root / "test").mkdir()
    (root / "contracts" / "modules" / "SSVClusters.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract C { function f() public pure returns(uint){ return 1-0; } }\n")
    (root / "test" / "Harness.t.sol").write_text("contract H {}\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


class TestPristineGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = _mk_repo(self.tmp)

    def test_clean_tree_is_pristine(self):
        rep = mod.evaluate(self.root)
        self.assertEqual(rep["status"], "pristine")
        self.assertEqual(rep["cut_dirty"], [])

    def test_mutated_contract_is_dirty(self):
        f = self.root / "contracts" / "modules" / "SSVClusters.sol"
        f.write_text(f.read_text().replace("1-0", "1+0"))  # mutation-test operator
        rep = mod.evaluate(self.root)
        self.assertEqual(rep["status"], "dirty")
        self.assertTrue(any("SSVClusters.sol" in c for c in rep["cut_dirty"]))
        self.assertIn("checkout", rep["restore_cmd"])

    def test_test_file_edit_does_not_invalidate(self):
        (self.root / "test" / "Harness.t.sol").write_text("contract H { uint x; }\n")
        rep = mod.evaluate(self.root)
        self.assertEqual(rep["status"], "pristine")  # harness edits are expected
        self.assertEqual(rep["cut_dirty"], [])

    def test_check_exit_code(self):
        # clean -> rc 0
        self.assertEqual(mod.main([str(self.root), "--check"]), 0)
        # dirty CUT -> rc 1
        f = self.root / "contracts" / "modules" / "SSVClusters.sol"
        f.write_text(f.read_text().replace("1-0", "1+0"))
        self.assertEqual(mod.main([str(self.root), "--check"]), 1)

    def test_new_poc_under_test_is_ignored(self):
        (self.root / "test" / "PoC_x.t.sol").write_text("contract P {}\n")
        # untracked test file - diff --name-only HEAD won't list untracked, but
        # even if added it is excluded; assert pristine for the CUT
        rep = mod.evaluate(self.root)
        self.assertEqual(rep["status"], "pristine")

    def test_bypass_env(self):
        f = self.root / "contracts" / "modules" / "SSVClusters.sol"
        f.write_text(f.read_text().replace("1-0", "1+0"))
        os.environ["AUDITOOOR_CUT_PRISTINE_BYPASS"] = "1"
        try:
            self.assertEqual(mod.main([str(self.root), "--check"]), 0)
        finally:
            del os.environ["AUDITOOOR_CUT_PRISTINE_BYPASS"]

    def test_non_git_dir(self):
        d = tempfile.mkdtemp()
        rep = mod.evaluate(Path(d))
        self.assertIn(rep["status"], ("not-a-git-repo", "error"))


if __name__ == "__main__":
    unittest.main()
