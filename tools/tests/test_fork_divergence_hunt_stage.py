#!/usr/bin/env python3
# r36-rebuttal: PR8b lane owns only this test + its tool; orchestrator commits.
"""Unit tests for tools/fork-divergence-hunt-stage.py.

Exercises the named hunt stage end-to-end with real git repos in tempdirs:
auto-detect upstream + pin, enumerate post-pin SECURITY commits, check
backport-presence against the fork tree, emit not-backported leads into the
proof-obligation queue. Anchor: the dYdX cometbft fork-lag class (a pinned
fork lags an upstream security-fix series).
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

_TOOL = Path(__file__).resolve().parent.parent / "fork-divergence-hunt-stage.py"
_spec = importlib.util.spec_from_file_location("fork_divergence_hunt_stage", _TOOL)
mod = importlib.util.module_from_spec(_spec)
sys.modules["fork_divergence_hunt_stage"] = mod
_spec.loader.exec_module(mod)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
    })
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, env=env, timeout=60)


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")


def _commit(repo: Path, fname: str, content: str, subject: str, body: str = "") -> str:
    (repo / fname).write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    msg = subject if not body else f"{subject}\n\n{body}"
    _git(repo, "commit", "-q", "-m", msg)
    r = _git(repo, "rev-parse", "HEAD")
    return r.stdout.strip()


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws = self.root / "ws"
        self.upstream = self.root / "upstream"
        self.ws.mkdir()

    def tearDown(self):
        self._tmp.cleanup()


class TestSecurityReason(_Base):
    def test_security_term_subject(self):
        self.assertTrue(mod._security_reason("fix integer overflow in decode", ""))
        self.assertTrue(mod._security_reason("blocksync verification hardening", ""))
        self.assertTrue(mod._security_reason("patch CVE-2024-1234", ""))

    def test_plain_fix_without_context_skipped(self):
        self.assertEqual(mod._security_reason("fix typo in docs", ""), "")

    def test_fix_with_security_context(self):
        self.assertTrue(mod._security_reason("fix missing length check on tx", ""))

    def test_routine_feature_skipped(self):
        self.assertEqual(mod._security_reason("add new RPC endpoint", ""), "")


class TestNormalizeSubject(_Base):
    def test_strips_pr_suffix(self):
        self.assertEqual(
            mod._normalize_subject("Trust mitigations (#16)"),
            "trust mitigations",
        )

    def test_collapses_whitespace(self):
        self.assertEqual(mod._normalize_subject("fix   the   bug"), "fix the bug")


class TestPinResolution(_Base):
    def test_pin_from_marker(self):
        (self.ws / ".auditooor").mkdir()
        (self.ws / ".auditooor" / "fork_target.json").write_text(
            json.dumps({"upstream": "org/repo", "pin": "904204b11c9e0011223344"}),
            encoding="utf-8")
        sha, src = mod.resolve_pin_sha(self.ws)
        self.assertEqual(sha, "904204b11c9e0011223344")
        self.assertIn("marker", src)

    def test_pin_from_gomod_pseudo(self):
        (self.ws / "go.mod").write_text(
            "module x\n\nrequire github.com/cometbft/cometbft "
            "v0.38.0-20240101000000-904204b11c9e\n", encoding="utf-8")
        sha, src = mod.resolve_pin_sha(self.ws)
        self.assertEqual(sha, "904204b11c9e")
        self.assertIn("pseudo-version", src)

    def test_pin_from_cargo_rev(self):
        (self.ws / "Cargo.toml").write_text(
            'foo = { git = "https://github.com/o/r", rev = "abcdef1234567" }\n',
            encoding="utf-8")
        sha, src = mod.resolve_pin_sha(self.ws)
        self.assertEqual(sha, "abcdef1234567")

    def test_pin_unresolved(self):
        sha, src = mod.resolve_pin_sha(self.ws)
        self.assertIsNone(sha)


class TestBackportDetection(_Base):
    def test_subject_match_is_backport(self):
        commit = {"sha": "deadbeef" * 5, "subject": "fix length check (#42)", "body": ""}
        subj_map = {"fix length check": "f0f0f0f0"}
        done, ev = mod.is_backported(commit, subj_map, set())
        self.assertTrue(done)
        self.assertIn("subject-match", ev)

    def test_cherry_pick_trailer_is_backport(self):
        up = "abcdef1234567890" + "0" * 24
        commit = {"sha": up, "subject": "x", "body": ""}
        done, ev = mod.is_backported(commit, {}, {"abcdef1234567"})
        self.assertTrue(done)
        self.assertIn("cherry-pick", ev)

    def test_not_backported(self):
        commit = {"sha": "f" * 40, "subject": "unique fix", "body": ""}
        done, ev = mod.is_backported(commit, {"other thing": "x"}, set())
        self.assertFalse(done)


class TestEndToEndForkLag(_Base):
    """The dYdX cometbft fork-lag class, mechanized.

    Upstream ships a security-fix series after the pin. The fork backported
    ONE of them but not the others. The stage must surface exactly the
    not-backported security commits as leads.
    """

    def _build(self):
        # upstream history
        _init_repo(self.upstream)
        pin = _commit(self.upstream, "core.go", "v0", "initial release (#1)")
        _commit(self.upstream, "core.go", "v1", "add metrics endpoint (#2)")  # non-security
        _commit(self.upstream, "core.go", "v2",
                "fix missing bounds check on block decode (#3)")  # security, backported
        sha_oob = _commit(self.upstream, "core.go", "v3",
                          "blocksync verification hardening (#4)")  # security, NOT backported
        sha_panic = _commit(self.upstream, "core.go", "v4",
                            "guard against panic on malicious header (#5)")  # security, NOT backported
        _commit(self.upstream, "docs.md", "d", "fix typo in readme (#6)")  # non-security

        # fork: pinned at `pin`, backported only the bounds-check fix
        fork = self.ws  # workspace IS the fork git tree
        _init_repo(fork)
        _commit(fork, "core.go", "v0", "initial release (#1)")
        _commit(fork, "core.go", "fork-local", "fork: add custom accounting (#100)")
        # backport of the bounds-check fix (subject preserved)
        _commit(fork, "core.go", "v2b", "fix missing bounds check on block decode (#3)")

        # workspace marker: declare upstream + pin
        (self.ws / ".auditooor").mkdir(exist_ok=True)
        (self.ws / ".auditooor" / "fork_target.json").write_text(
            json.dumps({"upstream": "cometbft/cometbft", "pin": pin}),
            encoding="utf-8")
        return pin, sha_oob, sha_panic

    def test_surfaces_not_backported_leads(self):
        pin, sha_oob, sha_panic = self._build()
        payload = mod.run_stage(
            ws=self.ws, upstream_clone=self.upstream,
            upstream_override=None, pin_override=None,
            window=400, allow_network=False, emit_queue=False,
        )
        self.assertEqual(payload["verdict"], "not-backported-leads-found")
        self.assertEqual(payload["upstream"], "cometbft/cometbft")
        self.assertEqual(payload["pin_sha"], pin)
        # 3 security commits after pin; 1 backported -> 2 leads
        self.assertEqual(payload["security_commits_scanned"], 3)
        self.assertEqual(payload["backported_count"], 1)
        leads = {l["sha"] for l in payload["not_backported_leads"]}
        self.assertIn(sha_oob, leads)
        self.assertIn(sha_panic, leads)
        self.assertEqual(len(leads), 2)

    def test_emit_to_proof_queue(self):
        pin, sha_oob, sha_panic = self._build()
        payload = mod.run_stage(
            ws=self.ws, upstream_clone=self.upstream,
            upstream_override=None, pin_override=None,
            window=400, allow_network=False, emit_queue=True,
        )
        self.assertIsNotNone(payload["queue"])
        self.assertEqual(payload["queue"]["tasks_added"], 2)
        qpath = self.ws / ".auditooor" / "proof_obligation_queue.json"
        self.assertTrue(qpath.exists())
        data = json.loads(qpath.read_text())
        self.assertIn("tasks", data)
        self.assertEqual(len(data["tasks"]), 2)
        t = data["tasks"][0]
        self.assertTrue(t["task_id"].startswith("fork-divergence-"))
        self.assertEqual(t["chain_id"], "fork-divergence-not-backported")
        self.assertIn("upstream_commit", t["fork_divergence"])

    def test_emit_is_idempotent(self):
        pin, _, _ = self._build()
        for _ in range(2):
            payload = mod.run_stage(
                ws=self.ws, upstream_clone=self.upstream,
                upstream_override=None, pin_override=None,
                window=400, allow_network=False, emit_queue=True,
            )
        qpath = self.ws / ".auditooor" / "proof_obligation_queue.json"
        data = json.loads(qpath.read_text())
        # second run must not duplicate
        self.assertEqual(len(data["tasks"]), 2)
        self.assertEqual(payload["queue"]["tasks_added"], 0)

    def test_all_backported_no_leads(self):
        # upstream where the only post-pin security commit is backported
        _init_repo(self.upstream)
        pin = _commit(self.upstream, "c.go", "v0", "init (#1)")
        _commit(self.upstream, "c.go", "v1", "fix missing length check (#2)")
        _init_repo(self.ws)
        _commit(self.ws, "c.go", "v0", "init (#1)")
        _commit(self.ws, "c.go", "v1b", "fix missing length check (#2)")
        (self.ws / ".auditooor").mkdir(exist_ok=True)
        (self.ws / ".auditooor" / "fork_target.json").write_text(
            json.dumps({"upstream": "o/r", "pin": pin}), encoding="utf-8")
        payload = mod.run_stage(
            ws=self.ws, upstream_clone=self.upstream,
            upstream_override=None, pin_override=None,
            window=400, allow_network=False, emit_queue=False,
        )
        self.assertEqual(payload["verdict"], "fork-current-no-leads")
        self.assertEqual(payload["backported_count"], 1)
        self.assertEqual(len(payload["not_backported_leads"]), 0)


class TestNonFork(_Base):
    def test_non_fork_noop(self):
        # plain workspace, no fork markers/manifests
        payload = mod.run_stage(
            ws=self.ws, upstream_clone=None, upstream_override=None,
            pin_override=None, window=400, allow_network=False, emit_queue=False,
        )
        self.assertEqual(payload["verdict"], "not-a-fork")


class TestPinNotInClone(_Base):
    def test_pin_unreachable_warns(self):
        _init_repo(self.upstream)
        _commit(self.upstream, "c.go", "v0", "init (#1)")
        (self.ws / ".auditooor").mkdir()
        (self.ws / ".auditooor" / "fork_target.json").write_text(
            json.dumps({"upstream": "o/r", "pin": "f" * 40}), encoding="utf-8")
        _init_repo(self.ws)
        _commit(self.ws, "c.go", "v0", "init (#1)")
        payload = mod.run_stage(
            ws=self.ws, upstream_clone=self.upstream, upstream_override=None,
            pin_override=None, window=400, allow_network=False, emit_queue=False,
        )
        self.assertTrue(any("not found" in w for w in payload["warnings"]))


class TestNoUpstreamSource(_Base):
    def test_no_clone_no_network(self):
        (self.ws / ".auditooor").mkdir()
        (self.ws / ".auditooor" / "fork_target.json").write_text(
            json.dumps({"upstream": "o/r", "pin": "a" * 40}), encoding="utf-8")
        payload = mod.run_stage(
            ws=self.ws, upstream_clone=None, upstream_override="o/r",
            pin_override="a" * 40, window=400, allow_network=False, emit_queue=False,
        )
        self.assertEqual(payload["verdict"], "no-upstream-source")


class TestCLI(_Base):
    def test_cli_json_smoke(self):
        r = subprocess.run(
            [sys.executable, str(_TOOL), "--workspace", str(self.ws), "--json"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(data["schema"], mod.SCHEMA)
        self.assertEqual(data["verdict"], "not-a-fork")

    def test_cli_missing_workspace(self):
        r = subprocess.run(
            [sys.executable, str(_TOOL), "--workspace",
             str(self.root / "nope"), "--json"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
