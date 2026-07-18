#!/usr/bin/env python3
"""Hermetic tests for ``tools/agent-worktree-dispatch.py``.

PR #129. Codex requirement: every gh/git interaction is stubbed via a
``subprocess.run`` shim — no live network or repo state may be touched.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from unittest import mock


# Load ``tools/agent-worktree-dispatch.py`` as a module despite the hyphen.
ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tools" / "agent-worktree-dispatch.py"
_spec = importlib.util.spec_from_file_location("agent_worktree_dispatch", SRC)
assert _spec is not None and _spec.loader is not None
awd = importlib.util.module_from_spec(_spec)
# Register before exec_module — dataclass introspection looks up the module via
# sys.modules during decoration (Python 3.12+ behavior).
sys.modules["agent_worktree_dispatch"] = awd
_spec.loader.exec_module(awd)


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class FakeRunner:
    """Records calls; returns canned responses keyed on the first 2-3 argv tokens."""

    def __init__(self, responses: dict[tuple, subprocess.CompletedProcess]):
        self.responses = responses
        self.calls: list[list[str]] = []

    def __call__(self, cmd, cwd=None, capture_output=True, text=True, check=False, env=None):
        self.calls.append(list(cmd))
        # match longest-prefix
        for key, resp in self.responses.items():
            if tuple(cmd[: len(key)]) == key:
                return resp
        return _completed(returncode=0)


def _patch_runner(responses: dict[tuple, subprocess.CompletedProcess]) -> FakeRunner:
    fake = FakeRunner(responses)
    awd._RUNNER = fake  # type: ignore[attr-defined]
    return fake


# ---------------------------------------------------------------------------
# Test 1 — branch name generation
# ---------------------------------------------------------------------------


class TestBranchNameGeneration(unittest.TestCase):
    def test_canonical_branch_string(self):
        ts = datetime(2026, 4, 25, 14, 30, tzinfo=timezone.utc)
        name = awd.make_branch_name(129, "plan-revise", now=ts)
        self.assertEqual(name, "pr129-plan-revise-20260425T1430Z")

    def test_minute_precision(self):
        ts = datetime(2026, 1, 1, 0, 0, 59, tzinfo=timezone.utc)
        name = awd.make_branch_name(7, "x", now=ts)
        self.assertEqual(name, "pr7-x-20260101T0000Z")


# ---------------------------------------------------------------------------
# Test 2 — slug rejection
# ---------------------------------------------------------------------------


class TestBranchNameRejectsBadSlug(unittest.TestCase):
    def test_uppercase_rejected(self):
        with self.assertRaises(ValueError):
            awd.validate_slug("Plan-Revise")

    def test_spaces_rejected(self):
        with self.assertRaises(ValueError):
            awd.validate_slug("plan revise")

    def test_underscore_rejected(self):
        with self.assertRaises(ValueError):
            awd.validate_slug("plan_revise")

    def test_overlong_rejected(self):
        with self.assertRaises(ValueError):
            awd.validate_slug("a" * 41)

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            awd.validate_slug("")

    def test_negative_parent_pr_rejected(self):
        with self.assertRaises(ValueError):
            awd.make_branch_name(-1, "ok-slug")

    def test_valid_kebab(self):
        # Sanity — should not raise
        awd.validate_slug("plan-revise-123")
        awd.validate_slug("a")
        awd.validate_slug("a" * 40)


# ---------------------------------------------------------------------------
# Test 3 — tracker round-trip
# ---------------------------------------------------------------------------


class TestTrackerRoundtrip(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "active_agents.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def test_write_read_mutate(self):
        e1 = awd.TrackerEntry(
            created_iso="2026-04-25T14:30:00Z",
            branch="pr129-a-20260425T1430Z",
            worktree="/tmp/wt-a",
            parent_pr=129,
            state="prepared",
            retry_count=0,
        )
        e2 = awd.TrackerEntry(
            created_iso="2026-04-25T14:31:00Z",
            branch="pr129-b-20260425T1431Z",
            worktree="/tmp/wt-b",
            parent_pr=129,
            state="prepared",
            retry_count=0,
        )
        awd.tracker_write(self.path, [e1, e2])

        # Round-trip parse.
        loaded = awd.tracker_read(self.path)
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded[0].branch, e1.branch)
        self.assertEqual(loaded[1].branch, e2.branch)

        # Mutate one row via upsert; the other must be untouched.
        e1_new = awd.TrackerEntry(
            created_iso=e1.created_iso,
            branch=e1.branch,
            worktree=e1.worktree,
            parent_pr=e1.parent_pr,
            state="pushed-verified",
            retry_count=0,
        )
        awd.tracker_upsert(self.path, e1_new)
        reloaded = awd.tracker_read(self.path)
        by_branch = {e.branch: e for e in reloaded}
        self.assertEqual(by_branch[e1.branch].state, "pushed-verified")
        self.assertEqual(by_branch[e2.branch].state, "prepared")

    def test_atomic_write_no_partial(self):
        # If write fails midway the original file must be intact.
        awd.tracker_write(
            self.path,
            [
                awd.TrackerEntry(
                    created_iso="2026-04-25T14:30:00Z",
                    branch="pr1-x-20260425T1430Z",
                    worktree="/tmp/wt-x",
                    parent_pr=1,
                    state="prepared",
                    retry_count=0,
                )
            ],
        )
        original = self.path.read_text(encoding="utf-8")

        class BadEntry(awd.TrackerEntry):
            def serialize(self):  # type: ignore[override]
                raise OSError("simulated write failure")

        bad = BadEntry(
            created_iso="2026-04-25T14:31:00Z",
            branch="pr1-y-20260425T1431Z",
            worktree="/tmp/wt-y",
            parent_pr=1,
            state="prepared",
            retry_count=0,
        )
        with self.assertRaises(OSError):
            awd.tracker_write(self.path, [bad])
        # Original intact.
        self.assertEqual(self.path.read_text(encoding="utf-8"), original)

    def test_corrupt_line_raises(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("only\ttwo\tfields\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            awd.tracker_read(self.path)


# ---------------------------------------------------------------------------
# Test 4 — state transitions
# ---------------------------------------------------------------------------


class TestStateTransitions(unittest.TestCase):
    def test_legal_path(self):
        s = awd.transition_state("prepared", "dispatched")
        self.assertEqual(s, "dispatched")
        s = awd.transition_state(s, "pushed-verified")
        self.assertEqual(s, "pushed-verified")
        s = awd.transition_state(s, "cleaned")
        self.assertEqual(s, "cleaned")

    def test_illegal_skip_rejected(self):
        with self.assertRaises(ValueError):
            awd.transition_state("prepared", "cleaned")

    def test_terminal_state(self):
        with self.assertRaises(ValueError):
            awd.transition_state("cleaned", "prepared")

    def test_idempotent_same_state(self):
        s = awd.transition_state("prepared", "prepared")
        self.assertEqual(s, "prepared")

    def test_unknown_state_rejected(self):
        with self.assertRaises(ValueError):
            awd.transition_state("prepared", "garbage")
        with self.assertRaises(ValueError):
            awd.transition_state("garbage", "prepared")


# ---------------------------------------------------------------------------
# Test 5 — stale classification
# ---------------------------------------------------------------------------


class TestStaleClassification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "transcript.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def test_died_at_launch_no_transcript(self):
        klass = awd.classify_stale(
            None,
            now_ts=1_000_000.0,
            launched_ts=1_000_000.0 - 600,  # 10 min ago
        )
        self.assertEqual(klass, "suspected-died-at-launch")

    def test_died_at_launch_tiny_transcript(self):
        self.path.write_text("hi", encoding="utf-8")
        os.utime(self.path, (1_000_000.0 - 600, 1_000_000.0 - 600))
        klass = awd.classify_stale(
            self.path,
            now_ts=1_000_000.0,
            launched_ts=1_000_000.0 - 600,
        )
        self.assertEqual(klass, "suspected-died-at-launch")

    def test_stalled_mid_work(self):
        # Large transcript, but mtime is 1 hour stale.
        self.path.write_text("x" * 10_000, encoding="utf-8")
        stale_mtime = 1_000_000.0 - 3600
        os.utime(self.path, (stale_mtime, stale_mtime))
        klass = awd.classify_stale(
            self.path,
            now_ts=1_000_000.0,
            launched_ts=1_000_000.0 - 7200,
        )
        self.assertEqual(klass, "suspected-stalled-mid-work")

    def test_active(self):
        self.path.write_text("x" * 10_000, encoding="utf-8")
        os.utime(self.path, (1_000_000.0 - 60, 1_000_000.0 - 60))
        klass = awd.classify_stale(
            self.path,
            now_ts=1_000_000.0,
            launched_ts=1_000_000.0 - 120,
        )
        self.assertEqual(klass, "active")


# ---------------------------------------------------------------------------
# Test 6 — verified-push mismatch parsing
# ---------------------------------------------------------------------------


class TestVerifiedPushMismatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tracker = Path(self.tmp.name) / "active_agents.txt"
        os.environ["AUDITOOOR_AGENTS_FILE"] = str(self.tracker)
        # Seed tracker with one entry; worktree dir is just a placeholder.
        self.wt = Path(self.tmp.name) / "wt"
        self.wt.mkdir()
        self.entry = awd.TrackerEntry(
            created_iso="2026-04-25T14:30:00Z",
            branch="pr129-test-20260425T1430Z",
            worktree=str(self.wt),
            parent_pr=129,
            state="prepared",
            retry_count=0,
        )
        awd.tracker_upsert(self.tracker, self.entry)
        self._orig_runner = awd._RUNNER

    def tearDown(self):
        awd._RUNNER = self._orig_runner
        self.tmp.cleanup()
        os.environ.pop("AUDITOOOR_AGENTS_FILE", None)

    def _run_verify(self, *, parent_pr=None):
        argv = ["verify-push", "--branch", self.entry.branch]
        if parent_pr is not None:
            argv += ["--parent-pr", str(parent_pr)]
        return awd.main(argv)

    def test_match_exit_zero(self):
        sha = "deadbeef" * 5
        _patch_runner(
            {
                ("git", "rev-parse", "HEAD"): _completed(stdout=sha + "\n"),
                ("gh", "api"): _completed(stdout=sha + "\n"),
            }
        )
        rc = self._run_verify()
        self.assertEqual(rc, awd.EXIT_OK)
        e = awd.tracker_find(self.tracker, self.entry.branch)
        self.assertEqual(e.state, "pushed-verified")

    def test_mismatch_exit_two(self):
        _patch_runner(
            {
                ("git", "rev-parse", "HEAD"): _completed(stdout="aa" * 20 + "\n"),
                ("gh", "api"): _completed(stdout="bb" * 20 + "\n"),
            }
        )
        rc = self._run_verify()
        self.assertEqual(rc, awd.EXIT_PUSH_MISMATCH)
        e = awd.tracker_find(self.tracker, self.entry.branch)
        self.assertEqual(e.state, "push-mismatch")

    def test_remote_missing_exit_three(self):
        _patch_runner(
            {
                ("git", "rev-parse", "HEAD"): _completed(stdout="aa" * 20 + "\n"),
                ("gh", "api"): _completed(
                    stdout="", stderr="HTTP 404: Not Found", returncode=1
                ),
            }
        )
        rc = self._run_verify()
        self.assertEqual(rc, awd.EXIT_REMOTE_MISSING)
        e = awd.tracker_find(self.tracker, self.entry.branch)
        self.assertEqual(e.state, "push-mismatch")

    def test_network_failure_exit_four(self):
        _patch_runner(
            {
                ("git", "rev-parse", "HEAD"): _completed(stdout="aa" * 20 + "\n"),
                ("gh", "api"): _completed(
                    stdout="", stderr="connection reset", returncode=1
                ),
            }
        )
        rc = self._run_verify()
        self.assertEqual(rc, awd.EXIT_NETWORK)


# ---------------------------------------------------------------------------
# Test 6b — verify-push endpoint syntax (Codex 16:15Z blocker)
# ---------------------------------------------------------------------------


class TestVerifyPushEndpoint(unittest.TestCase):
    """Codex 16:15Z blocker: ``gh api`` does NOT expand ``:owner/:repo`` literal
    placeholders — only ``{owner}``/``{repo}``/``{branch}`` curly-brace
    placeholders are documented. The default verify-push endpoint must use
    either curly-brace placeholders OR a concrete ``<owner>/<repo>`` resolved
    from ``git remote get-url origin``.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tracker = Path(self.tmp.name) / "active_agents.txt"
        os.environ["AUDITOOOR_AGENTS_FILE"] = str(self.tracker)
        self.wt = Path(self.tmp.name) / "wt"
        self.wt.mkdir()
        self.entry = awd.TrackerEntry(
            created_iso="2026-04-25T14:30:00Z",
            branch="pr129-endpoint-20260425T1430Z",
            worktree=str(self.wt),
            parent_pr=129,
            state="prepared",
            retry_count=0,
        )
        awd.tracker_upsert(self.tracker, self.entry)
        self._orig_runner = awd._RUNNER

    def tearDown(self):
        awd._RUNNER = self._orig_runner
        self.tmp.cleanup()
        os.environ.pop("AUDITOOOR_AGENTS_FILE", None)

    def _captured_argv_for(self, *, repo_arg=None, origin_url=None):
        """Run verify-push and return the full list of recorded argvs."""
        sha = "deadbeef" * 5
        responses = {
            ("git", "rev-parse", "HEAD"): _completed(stdout=sha + "\n"),
            ("gh", "api"): _completed(stdout=sha + "\n"),
        }
        if origin_url is not None:
            responses[("git", "remote", "get-url", "origin")] = _completed(
                stdout=origin_url + "\n"
            )
        else:
            # Make origin lookup fail so we exercise the {owner}/{repo}
            # placeholder fallback path.
            responses[("git", "remote", "get-url", "origin")] = _completed(
                returncode=128, stderr="fatal: No such remote 'origin'\n"
            )
        runner = _patch_runner(responses)
        argv = ["verify-push", "--branch", self.entry.branch]
        if repo_arg is not None:
            argv += ["--repo", repo_arg]
        rc = awd.main(argv)
        self.assertEqual(rc, awd.EXIT_OK)
        return runner.calls

    def _gh_api_call(self, calls):
        for call in calls:
            if len(call) >= 2 and call[0] == "gh" and call[1] == "api":
                return call
        self.fail(f"no gh api call recorded; got: {calls}")

    def test_default_endpoint_never_uses_colon_placeholders(self):
        """Default endpoint (no --repo) must never contain ``:owner`` or
        ``:repo`` literal text — those are not real ``gh api`` placeholders.
        """
        calls = self._captured_argv_for(origin_url=None)
        gh_call = self._gh_api_call(calls)
        joined = " ".join(gh_call)
        self.assertNotIn(":owner", joined)
        self.assertNotIn(":repo", joined)
        # Must contain the branch we asked about.
        self.assertIn(self.entry.branch, joined)
        # And must hit the heads endpoint shape.
        self.assertTrue(
            any(f"git/refs/heads/{self.entry.branch}" in tok for tok in gh_call),
            f"no heads-endpoint token in {gh_call}",
        )

    def test_default_endpoint_uses_brace_placeholders_when_origin_missing(self):
        """When ``git remote get-url origin`` fails, fall back to the
        ``{owner}/{repo}`` curly-brace placeholders that ``gh api`` documents.
        """
        calls = self._captured_argv_for(origin_url=None)
        gh_call = self._gh_api_call(calls)
        expected = f"repos/{{owner}}/{{repo}}/git/refs/heads/{self.entry.branch}"
        self.assertIn(expected, gh_call)

    def test_default_endpoint_uses_resolved_owner_repo_when_origin_present(self):
        """When origin is a real GitHub URL, derive ``<owner>/<repo>`` from it
        and pass a concrete path — no placeholders, no ``:owner/:repo``.
        """
        calls = self._captured_argv_for(
            origin_url="https://github.com/Vuk97/auditooor.git"
        )
        gh_call = self._gh_api_call(calls)
        expected = f"repos/Vuk97/auditooor/git/refs/heads/{self.entry.branch}"
        self.assertIn(expected, gh_call)
        self.assertNotIn(":owner", " ".join(gh_call))
        self.assertNotIn(":repo", " ".join(gh_call))

    def test_default_endpoint_handles_ssh_origin(self):
        """SSH-form origin URL must also resolve."""
        calls = self._captured_argv_for(
            origin_url="git@github.com:Vuk97/auditooor.git"
        )
        gh_call = self._gh_api_call(calls)
        expected = f"repos/Vuk97/auditooor/git/refs/heads/{self.entry.branch}"
        self.assertIn(expected, gh_call)

    def test_explicit_repo_argument_used_verbatim(self):
        """``--repo Vuk97/auditooor`` must produce ``repos/Vuk97/auditooor/...``
        regardless of what ``git remote get-url origin`` would have returned.
        """
        calls = self._captured_argv_for(
            repo_arg="Vuk97/auditooor",
            origin_url="https://github.com/SomeoneElse/forked.git",
        )
        gh_call = self._gh_api_call(calls)
        expected = f"repos/Vuk97/auditooor/git/refs/heads/{self.entry.branch}"
        self.assertIn(expected, gh_call)
        self.assertNotIn("SomeoneElse", " ".join(gh_call))

    def test_resolve_origin_owner_repo_unit(self):
        """Unit-level coverage of the URL parser for the common shapes."""
        cases = [
            ("https://github.com/Vuk97/auditooor.git", "Vuk97/auditooor"),
            ("https://github.com/Vuk97/auditooor", "Vuk97/auditooor"),
            ("git@github.com:Vuk97/auditooor.git", "Vuk97/auditooor"),
            ("git@github.com:Vuk97/auditooor", "Vuk97/auditooor"),
            ("ssh://git@github.com/Vuk97/auditooor.git", "Vuk97/auditooor"),
            ("https://x-access-token:tok@github.com/Vuk97/auditooor.git", "Vuk97/auditooor"),
        ]
        for url, expected in cases:
            with self.subTest(url=url):
                _patch_runner(
                    {("git", "remote", "get-url", "origin"): _completed(stdout=url + "\n")}
                )
                self.assertEqual(awd._resolve_origin_owner_repo(), expected)

        # Non-GitHub or malformed → None.
        bad_cases = [
            "https://gitlab.com/foo/bar.git",
            "not-a-url",
            "",
        ]
        for url in bad_cases:
            with self.subTest(url=url):
                _patch_runner(
                    {("git", "remote", "get-url", "origin"): _completed(stdout=url + "\n")}
                )
                self.assertIsNone(awd._resolve_origin_owner_repo())


# ---------------------------------------------------------------------------
# Test 7 — retry caps at one
# ---------------------------------------------------------------------------


class TestRetryCap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tracker = Path(self.tmp.name) / "active_agents.txt"
        os.environ["AUDITOOOR_AGENTS_FILE"] = str(self.tracker)
        self.entry = awd.TrackerEntry(
            created_iso="2026-04-25T14:30:00Z",
            branch="pr129-retry-20260425T1430Z",
            worktree=str(Path(self.tmp.name) / "wt"),
            parent_pr=129,
            state="prepared",
            retry_count=0,
        )
        awd.tracker_upsert(self.tracker, self.entry)

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("AUDITOOOR_AGENTS_FILE", None)

    def test_first_retry_ok_second_blocked(self):
        rc = awd.main(["retry", "--branch", self.entry.branch])
        self.assertEqual(rc, awd.EXIT_OK)
        e = awd.tracker_find(self.tracker, self.entry.branch)
        self.assertEqual(e.retry_count, 1)
        self.assertEqual(e.state, "retry-needed")

        rc2 = awd.main(["retry", "--branch", self.entry.branch])
        self.assertEqual(rc2, awd.EXIT_RETRY_EXHAUSTED)
        e2 = awd.tracker_find(self.tracker, self.entry.branch)
        self.assertEqual(e2.retry_count, 1, "retry count must not advance past cap")

    def test_unknown_branch_exits_tracker(self):
        rc = awd.main(["retry", "--branch", "pr999-nope-20260425T0000Z"])
        self.assertEqual(rc, awd.EXIT_TRACKER)


# ---------------------------------------------------------------------------
# Test 8 — cleanup refuses unverified
# ---------------------------------------------------------------------------


class TestCleanupRefusesUnverified(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tracker = Path(self.tmp.name) / "active_agents.txt"
        os.environ["AUDITOOOR_AGENTS_FILE"] = str(self.tracker)
        self.wt = Path(self.tmp.name) / "wt"
        self.wt.mkdir()
        self._orig_runner = awd._RUNNER

    def tearDown(self):
        awd._RUNNER = self._orig_runner
        self.tmp.cleanup()
        os.environ.pop("AUDITOOOR_AGENTS_FILE", None)

    def _seed(self, state):
        entry = awd.TrackerEntry(
            created_iso="2026-04-25T14:30:00Z",
            branch="pr129-clean-20260425T1430Z",
            worktree=str(self.wt),
            parent_pr=129,
            state=state,
            retry_count=0,
        )
        awd.tracker_upsert(self.tracker, entry)
        return entry

    def test_refuses_when_prepared(self):
        entry = self._seed("prepared")
        # Track whether git worktree remove was called.
        runner = _patch_runner({})
        rc = awd.main(["cleanup", "--branch", entry.branch])
        self.assertNotEqual(rc, awd.EXIT_OK)
        # Worktree dir still exists (we never asked the fake to delete it).
        self.assertTrue(self.wt.exists())
        # No git worktree remove call must have been issued.
        for call in runner.calls:
            self.assertNotEqual(call[:3], ["git", "worktree", "remove"])

    def test_refuses_when_push_mismatch(self):
        entry = self._seed("push-mismatch")
        runner = _patch_runner({})
        rc = awd.main(["cleanup", "--branch", entry.branch])
        self.assertNotEqual(rc, awd.EXIT_OK)
        self.assertTrue(self.wt.exists())
        for call in runner.calls:
            self.assertNotEqual(call[:3], ["git", "worktree", "remove"])

    def test_allows_when_pushed_verified(self):
        entry = self._seed("pushed-verified")
        runner = _patch_runner(
            {
                ("git", "worktree", "remove"): _completed(returncode=0),
            }
        )
        rc = awd.main(["cleanup", "--branch", entry.branch])
        self.assertEqual(rc, awd.EXIT_OK)
        e = awd.tracker_find(self.tracker, entry.branch)
        self.assertEqual(e.state, "cleaned")
        # Confirm git worktree remove was actually invoked.
        self.assertTrue(
            any(call[:3] == ["git", "worktree", "remove"] for call in runner.calls),
            f"git worktree remove not called: {runner.calls}",
        )


# ---------------------------------------------------------------------------
# Test 9 — prepare command machine-parseable output
# ---------------------------------------------------------------------------


class TestPrepareMachineOutput(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "wt-root"
        self.tracker = Path(self.tmp.name) / "active_agents.txt"
        os.environ["AUDITOOOR_WORKTREE_DIR"] = str(self.root)
        os.environ["AUDITOOOR_AGENTS_FILE"] = str(self.tracker)
        self._orig_runner = awd._RUNNER

    def tearDown(self):
        awd._RUNNER = self._orig_runner
        self.tmp.cleanup()
        os.environ.pop("AUDITOOOR_WORKTREE_DIR", None)
        os.environ.pop("AUDITOOOR_AGENTS_FILE", None)

    def test_prepare_emits_key_value_lines(self):
        # Mock git rev-parse --verify (base ref OK), mock worktree add success.
        _patch_runner(
            {
                ("git", "status", "--porcelain"): _completed(returncode=0),
                ("git", "rev-parse", "--verify"): _completed(returncode=0, stdout="abc123\n"),
                ("git", "worktree", "add"): _completed(returncode=0),
                # gh pr view fallback should not even be needed but stub anyway.
                ("gh", "pr", "view"): _completed(returncode=0, stdout="main\n"),
            }
        )
        captured = mock.MagicMock()
        with mock.patch("builtins.print", captured):
            rc = awd.main(
                [
                    "prepare",
                    "--parent-pr",
                    "129",
                    "--task-slug",
                    "plan-revise",
                    "--base-branch",
                    "origin/main",
                ]
            )
        self.assertEqual(rc, awd.EXIT_OK)
        printed = "\n".join(
            (call.args[0] if call.args else "") for call in captured.call_args_list
        )
        self.assertIn("AGENT_BRANCH=pr129-plan-revise-", printed)
        self.assertIn(f"AGENT_PARENT_PR=129", printed)
        self.assertIn("AGENT_WORKTREE=", printed)
        self.assertIn("AGENT_TRACKER=", printed)

    def test_prepare_rejects_dirty_coordinator_checkout(self):
        runner = _patch_runner(
            {
                ("git", "status", "--porcelain"): _completed(stdout=" M docs/KNOWN_LIMITATIONS.md\n"),
                ("git", "rev-parse", "--verify"): _completed(returncode=0, stdout="abc123\n"),
                ("git", "worktree", "add"): _completed(returncode=0),
            }
        )
        rc = awd.main(
            [
                "prepare",
                "--parent-pr",
                "129",
                "--task-slug",
                "plan-revise",
                "--base-branch",
                "origin/main",
            ]
        )
        self.assertEqual(rc, awd.EXIT_UNSAFE_WORKSPACE)
        add_calls = [c for c in runner.calls if c[:3] == ["git", "worktree", "add"]]
        self.assertEqual(add_calls, [], "dirty coordinator checkout must not create worktrees")

    def test_prepare_rejects_unwritable_worktree_root(self):
        runner = _patch_runner(
            {
                ("git", "status", "--porcelain"): _completed(returncode=0),
                ("git", "rev-parse", "--verify"): _completed(returncode=0, stdout="abc123\n"),
                ("git", "worktree", "add"): _completed(returncode=0),
            }
        )
        with mock.patch.object(
            awd,
            "_ensure_writable_dir",
            return_value=(False, "permission denied"),
        ):
            rc = awd.main(
                [
                    "prepare",
                    "--parent-pr",
                    "129",
                    "--task-slug",
                    "plan-revise",
                    "--base-branch",
                    "origin/main",
                ]
            )
        self.assertEqual(rc, awd.EXIT_UNSAFE_WORKSPACE)
        add_calls = [c for c in runner.calls if c[:3] == ["git", "worktree", "add"]]
        self.assertEqual(add_calls, [], "unwritable worktree root must not create worktrees")

    def test_prepare_rejects_bad_slug(self):
        rc = awd.main(
            ["prepare", "--parent-pr", "129", "--task-slug", "Plan_Revise"]
        )
        self.assertEqual(rc, awd.EXIT_BAD_INPUT)

    def test_prepare_fetches_parent_ref_before_worktree_add(self):
        """I-04 (PR #158): every `prepare` invocation must `git fetch
        origin <base>` before `git worktree add` so parallel agents that
        started before the latest parent commit landed do not silently
        produce stale-base PRs.
        """
        runner = _patch_runner(
            {
                ("git", "status", "--porcelain"): _completed(returncode=0),
                ("git", "rev-parse", "--verify"): _completed(returncode=0, stdout="abc123\n"),
                ("git", "worktree", "add"): _completed(returncode=0),
                ("git", "fetch"): _completed(returncode=0),
            }
        )
        rc = awd.main(
            [
                "prepare",
                "--parent-pr",
                "129",
                "--task-slug",
                "plan-revise",
                "--base-branch",
                "origin/main",
            ]
        )
        self.assertEqual(rc, awd.EXIT_OK)
        # The fetch call must come BEFORE the worktree add call.
        idx_fetch = next(
            (i for i, c in enumerate(runner.calls) if c[:2] == ["git", "fetch"]),
            None,
        )
        idx_add = next(
            (i for i, c in enumerate(runner.calls) if c[:3] == ["git", "worktree", "add"]),
            None,
        )
        self.assertIsNotNone(idx_fetch, "fetch call missing — parent ref not refreshed")
        self.assertIsNotNone(idx_add, "worktree add call missing")
        self.assertLess(idx_fetch, idx_add)
        # And the fetch refspec maps the remote branch onto its
        # origin/<branch> tracking ref.
        fetch_call = runner.calls[idx_fetch]
        self.assertIn("origin", fetch_call)
        self.assertTrue(
            any("main:refs/remotes/origin/main" in tok for tok in fetch_call),
            f"fetch refspec did not map main → origin/main: {fetch_call}",
        )

    def test_prepare_skips_fetch_when_no_fetch_parent_flag(self):
        runner = _patch_runner(
            {
                ("git", "status", "--porcelain"): _completed(returncode=0),
                ("git", "rev-parse", "--verify"): _completed(returncode=0, stdout="abc123\n"),
                ("git", "worktree", "add"): _completed(returncode=0),
                ("git", "fetch"): _completed(returncode=0),
            }
        )
        rc = awd.main(
            [
                "prepare",
                "--parent-pr",
                "129",
                "--task-slug",
                "plan-revise",
                "--base-branch",
                "origin/main",
                "--no-fetch-parent",
            ]
        )
        self.assertEqual(rc, awd.EXIT_OK)
        fetch_calls = [c for c in runner.calls if c[:2] == ["git", "fetch"]]
        self.assertEqual(fetch_calls, [], "fetch should be suppressed by --no-fetch-parent")

    def test_prepare_does_not_fetch_for_local_only_base(self):
        """If the operator passes a non-origin base (e.g. a local branch),
        the fetch step must be a no-op — there is no remote to refresh.
        """
        runner = _patch_runner(
            {
                ("git", "status", "--porcelain"): _completed(returncode=0),
                ("git", "rev-parse", "--verify"): _completed(returncode=0, stdout="abc123\n"),
                ("git", "worktree", "add"): _completed(returncode=0),
            }
        )
        rc = awd.main(
            [
                "prepare",
                "--parent-pr",
                "129",
                "--task-slug",
                "plan-revise",
                "--base-branch",
                "feature/local-only",
            ]
        )
        self.assertEqual(rc, awd.EXIT_OK)
        fetch_calls = [c for c in runner.calls if c[:2] == ["git", "fetch"]]
        self.assertEqual(fetch_calls, [], "must not fetch for non-origin base ref")


if __name__ == "__main__":
    unittest.main()
