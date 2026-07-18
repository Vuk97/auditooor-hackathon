#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""Unit tests for tools/fork-upstream-resolve.py (fork detect + upstream resolve)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "fork-upstream-resolve.py"
_spec = importlib.util.spec_from_file_location("fork_upstream_resolve", _TOOL)
mod = importlib.util.module_from_spec(_spec)
sys.modules["fork_upstream_resolve"] = mod
_spec.loader.exec_module(mod)


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, rel, content):
        p = self.ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def _git_repo(self, rel, origin):
        p = self.ws / rel
        p.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init"], cwd=p, check=True, capture_output=True)
        subprocess.run(
            ["git", "remote", "add", "origin", origin],
            cwd=p,
            check=True,
            capture_output=True,
        )
        return p


class TestDetectFork(_Base):
    def test_non_fork_plain_dir(self):
        is_fork, reasons = mod.detect_fork(self.ws)
        self.assertFalse(is_fork)
        self.assertEqual(reasons, [])

    def test_cargo_pinned_rev_is_fork(self):
        self._write("Cargo.toml",
                    '[dependencies]\nfoo = { git = "https://github.com/a/b", rev = "abc1234" }\n')
        is_fork, reasons = mod.detect_fork(self.ws)
        self.assertTrue(is_fork)
        self.assertTrue(any("pinned git rev" in r for r in reasons))

    def test_gomod_replace_is_fork(self):
        self._write("go.mod", "module x\n\nreplace foo => github.com/acme/repo v1.2.3\n")
        is_fork, _ = mod.detect_fork(self.ws)
        self.assertTrue(is_fork)

    def test_vendored_tree_is_fork(self):
        self._write("vendor/upstream/x.go", "package x\n")
        is_fork, reasons = mod.detect_fork(self.ws)
        self.assertTrue(is_fork)
        self.assertTrue(any("vendored" in r for r in reasons))

    def test_marker_file_is_fork(self):
        self._write("FORK_OF.txt", "acme/repo\n")
        is_fork, _ = mod.detect_fork(self.ws)
        self.assertTrue(is_fork)

    def test_same_family_unproven_differential_seed_is_fork_obligation(self):
        self._write(
            ".auditooor/differential_seed_queue.json",
            json.dumps({
                "schema": "auditooor.cross_workspace_differential_seed.v1",
                "target_families": ["morpho-blue"],
                "selected_siblings": [
                    {"workspace": "morpho", "families": ["morpho-blue"]},
                ],
                "hypotheses": [
                    {"hypothesis_id": "DIFF-1", "prior_workspace": "morpho", "verdict": "unproven"},
                    {"hypothesis_id": "DIFF-2", "prior_workspace": "zebra", "verdict": "unproven"},
                ],
            }),
        )
        is_fork, reasons = mod.detect_fork(self.ws)
        self.assertTrue(is_fork)
        self.assertTrue(any("same-family differential seed" in r for r in reasons))
        self.assertTrue(any("unproven=1" in r for r in reasons))

    def test_mirrors_master_gate_detect_fork(self):
        # The detector must agree with audit-completeness-check.py::_detect_fork.
        acc_tool = Path(__file__).resolve().parent.parent / "audit-completeness-check.py"
        spec = importlib.util.spec_from_file_location("acc_for_test", acc_tool)
        acc = importlib.util.module_from_spec(spec)
        sys.modules["acc_for_test"] = acc
        spec.loader.exec_module(acc)
        self._write("Cargo.toml",
                    '[dependencies]\nx = { git = "https://github.com/acme/up", rev = "deadbeef0" }\n')
        ours = mod.detect_fork(self.ws)[0]
        theirs = acc._detect_fork(self.ws)[0]
        self.assertEqual(ours, theirs)


class TestResolveUpstream(_Base):
    def test_resolve_from_cargo_git_url(self):
        self._write("Cargo.toml",
                    '[dependencies]\nfoo = { git = "https://github.com/acme/upstream-repo", rev = "abc1234" }\n')
        up, src = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "acme/upstream-repo")
        self.assertIn("cargo", src)

    def test_resolve_from_cargo_strips_dot_git(self):
        self._write("Cargo.toml",
                    '[dependencies]\nfoo = { git = "https://github.com/acme/up.git", rev = "abc1234" }\n')
        up, _ = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "acme/up")

    def test_resolve_from_gomod_replace(self):
        self._write("go.mod", "module x\n\nreplace foo => github.com/acme/gorepo v1.2.3\n")
        up, src = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "acme/gorepo")
        self.assertIn("gomod", src)

    def test_resolve_from_gomod_replace_with_version_lhs(self):
        self._write("go.mod",
                    "module x\n\nreplace foo v1.0.0 => github.com/acme/gorepo v1.2.3\n")
        up, _ = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "acme/gorepo")

    def test_marker_json_takes_priority(self):
        self._write("Cargo.toml",
                    '[dependencies]\nfoo = { git = "https://github.com/cargo/repo", rev = "abc1234" }\n')
        self._write(".auditooor/fork_target.json",
                    json.dumps({"upstream": "marker/wins"}))
        up, src = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "marker/wins")
        self.assertIn("marker", src)

    def test_marker_json_url_form(self):
        self._write(".auditooor/fork_target.json",
                    json.dumps({"upstream": "https://github.com/owner/proj.git"}))
        up, _ = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "owner/proj")

    def test_fork_of_txt_owner_repo(self):
        self._write("FORK_OF.txt", "# comment line\nfoo/bar\n")
        up, src = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "foo/bar")
        self.assertIn("FORK_OF", src)

    def test_unresolvable_returns_none(self):
        # Vendored tree => fork, but no resolvable upstream source.
        self._write("vendor/x/y.go", "package y\n")
        up, _ = mod.resolve_upstream(self.ws)
        self.assertIsNone(up)

    def test_resolve_from_git_remote_at_src_root(self):
        self._git_repo("src", "https://github.com/acme/src-root.git")
        up, src = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "acme/src-root")
        self.assertEqual(src, "git:origin remote")

    def test_resolve_from_git_remote_in_legacy_src_child(self):
        self._git_repo("src/legacy", "git@github.com:acme/legacy.git")
        up, src = mod.resolve_upstream(self.ws)
        self.assertEqual(up, "acme/legacy")
        self.assertEqual(src, "git:origin remote")


class TestEvaluateAndCLI(_Base):
    def test_evaluate_not_a_fork(self):
        v = mod.evaluate(self.ws)
        self.assertEqual(v["verdict"], "not-a-fork")
        self.assertFalse(v["is_fork"])
        self.assertIsNone(v["upstream"])

    def test_evaluate_resolved(self):
        self._write("Cargo.toml",
                    '[dependencies]\nfoo = { git = "https://github.com/acme/up", rev = "abc1234" }\n')
        v = mod.evaluate(self.ws)
        self.assertEqual(v["verdict"], "resolved")
        self.assertTrue(v["is_fork"])
        self.assertEqual(v["upstream"], "acme/up")
        self.assertEqual(v["lang_hint"], "rust")

    def test_evaluate_fork_unresolved(self):
        self._write("vendor/x/y.go", "package y\n")
        v = mod.evaluate(self.ws)
        self.assertEqual(v["verdict"], "fork-upstream-unresolved")
        self.assertTrue(v["is_fork"])
        self.assertIsNone(v["upstream"])

    def test_lang_hint_go(self):
        self._write("go.mod", "module x\n\nreplace foo => github.com/a/b v1\n")
        v = mod.evaluate(self.ws)
        self.assertEqual(v["lang_hint"], "go")

    def test_probe_workspace_prefers_src_root_checkout(self):
        repo = self._git_repo("src", "https://github.com/acme/src-root.git")
        self.assertEqual(mod._probe_workspace(self.ws), str(repo.resolve(strict=False)))

    def test_probe_workspace_accepts_legacy_src_child_checkout(self):
        repo = self._git_repo("src/legacy", "https://github.com/acme/legacy.git")
        self.assertEqual(mod._probe_workspace(self.ws), str(repo.resolve(strict=False)))

    def test_cli_resolved_rc_zero(self):
        self._write("Cargo.toml",
                    '[dependencies]\nfoo = { git = "https://github.com/acme/up", rev = "abc1234" }\n')
        rc = mod.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 0)

    def test_cli_not_a_fork_rc_zero(self):
        rc = mod.main(["--workspace", str(self.ws)])
        self.assertEqual(rc, 0)

    def test_cli_fork_unresolved_rc_one_FAIL_CLOSE(self):
        # FAIL-CLOSE: a fork whose upstream cannot be resolved is a non-zero
        # exit so the orchestrator records the probe could not auto-run.
        self._write("vendor/x/y.go", "package y\n")
        rc = mod.main(["--workspace", str(self.ws)])
        self.assertEqual(rc, 1)

    def test_cli_missing_workspace_rc_two(self):
        rc = mod.main(["--workspace", str(self.ws / "nope"), "--json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
