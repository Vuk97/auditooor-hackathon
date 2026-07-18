#!/usr/bin/env python3
"""capability-v3 iter-003 T5 — codex-peer-poll regression tests.

Hermetic: no live `gh`, no live `git`. All subprocess boundaries are
stubbed via `unittest.mock.patch`. Fixtures are built inline.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "codex-peer-poll.py"


def _load_tool():
    """Load codex-peer-poll.py as a module for direct unit testing.

    We use importlib because the filename contains a hyphen, which
    is not a valid Python identifier for `import`.
    """
    spec = importlib.util.spec_from_file_location("codex_peer_poll", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_gh_pr_view(payload: dict) -> MagicMock:
    """Build a subprocess.run-shaped mock return for `gh pr view`."""
    rv = MagicMock()
    rv.returncode = 0
    rv.stdout = json.dumps(payload)
    rv.stderr = ""
    return rv


class ClassifyTests(unittest.TestCase):
    """T5 test #1: classifier locks."""

    def test_classifies_review_feedback_from_codex_commit_body(self) -> None:
        """Comment body 'change function foo to return bar' authored by
        Codex should classify as suggestion or review-feedback.

        Locks the classifier: if this test regresses, we've lost the
        ability to distinguish peer suggestions from noise.
        """
        tool = _load_tool()

        body_with_line_ref = (
            "At line 42, change function foo to return bar — this "
            "avoids the off-by-one."
        )
        cls = tool.classify_comment(body_with_line_ref)
        self.assertIn(cls, {"review-feedback", "suggestion"})

        # Body without explicit line ref but with imperative mood →
        # should still classify as suggestion (not unclassified).
        body_imperative = "change function foo to return bar"
        cls2 = tool.classify_comment(body_imperative)
        self.assertIn(cls2, {"suggestion", "review-feedback"})

        # And a review event with CHANGES_REQUESTED state → review-feedback
        # regardless of body.
        review_event = {
            "state": "CHANGES_REQUESTED",
            "body": "",
        }
        self.assertEqual(tool.classify_review(review_event), "review-feedback")


class FilterSymmetryTests(unittest.TestCase):
    """T5 test #2 + #5: filter + symmetry."""

    def _mixed_pr_payload(self) -> dict:
        """Returns a PR payload with one Opus-authored commit and one
        Codex-authored commit, plus one Opus comment and one Codex comment."""
        return {
            "headRefName": "claudeboy-capability-v3",
            "baseRefName": "main",
            "comments": [
                {
                    "author": {"login": "Vuk97"},
                    "body": (
                        "Iter-v3-3 plan landed. See Claude Opus 4.7 "
                        "commit trailer for authorship."
                    ),
                    "createdAt": "2026-04-24T08:43:18Z",
                    "url": "https://github.com/x/y/pull/104#issuecomment-A",
                },
                {
                    "author": {"login": "Vuk97"},
                    "body": (
                        "Codex here — consider rebasing on main; "
                        "the merge conflict is trivial."
                    ),
                    "createdAt": "2026-04-24T08:55:26Z",
                    "url": "https://github.com/x/y/pull/104#issuecomment-B",
                },
            ],
            "reviews": [],
            "commits": [
                {
                    "oid": "aaaaaaa0000000000000000000000000000000a1",
                    "messageHeadline": "Opus: cap v3 iter-003 T5",
                    "messageBody": (
                        "Co-Authored-By: Claude Opus 4.7 (1M context) "
                        "<noreply@anthropic.com>"
                    ),
                    "committedDate": "2026-04-24T09:00:00Z",
                    "authoredDate": "2026-04-24T09:00:00Z",
                    "authors": [
                        {
                            "name": "Vuk Tanaskovic",
                            "login": "",
                            "email": "wolf@Vuks-Laptop.local",
                        }
                    ],
                },
                {
                    "oid": "bbbbbbb0000000000000000000000000000000b2",
                    "messageHeadline": "Codex: impact-bound replay refinement",
                    "messageBody": "Co-Authored-By: codex <noreply@openai.com>",
                    "committedDate": "2026-04-24T09:05:00Z",
                    "authoredDate": "2026-04-24T09:05:00Z",
                    "authors": [
                        {
                            "name": "Vuk Tanaskovic",
                            "login": "",
                            "email": "wolf@Vuks-Laptop.local",
                        }
                    ],
                },
            ],
        }

    def test_filters_out_self_authored_events(self) -> None:
        """Invoking with --peer-name opus returns Codex-authored events only."""
        tool = _load_tool()
        payload = self._mixed_pr_payload()

        events = tool.build_events(
            pr_data=payload,
            git_commits=[],
            peer_name="opus",
            since="2026-04-24T00:00:00Z",
        )

        # Opus is running → we want Codex events only. The Opus commit
        # must be dropped; the Codex commit + Codex comment kept.
        oids = [e["sha_or_url"] for e in events if e["type"] == "commit"]
        self.assertNotIn(
            "aaaaaaa0000000000000000000000000000000a1",
            oids,
            "Opus commit leaked into --peer-name opus output",
        )
        self.assertIn(
            "bbbbbbb0000000000000000000000000000000b2",
            oids,
            "Codex commit missing from --peer-name opus output",
        )
        # At least one Codex comment (by body marker) should survive.
        preview_blob = " ".join(e.get("body_preview", "") for e in events)
        self.assertIn("Codex", preview_blob)
        # And the Claude-Opus-marker comment should NOT survive.
        self.assertNotIn("Claude Opus 4.7", preview_blob)

    def test_symmetry_codex_peer_name_returns_opus_events(self) -> None:
        """Mirror of the filter test. --peer-name codex returns Opus events."""
        tool = _load_tool()
        payload = self._mixed_pr_payload()

        events = tool.build_events(
            pr_data=payload,
            git_commits=[],
            peer_name="codex",
            since="2026-04-24T00:00:00Z",
        )

        oids = [e["sha_or_url"] for e in events if e["type"] == "commit"]
        self.assertIn(
            "aaaaaaa0000000000000000000000000000000a1",
            oids,
            "Opus commit missing from --peer-name codex output",
        )
        self.assertNotIn(
            "bbbbbbb0000000000000000000000000000000b2",
            oids,
            "Codex commit leaked into --peer-name codex output",
        )


class EmptyWindowTests(unittest.TestCase):
    """T5 test #3: empty window is not an error."""

    def test_empty_since_returns_empty_list_not_error(self) -> None:
        """--since in the future, run as a subprocess against the real
        entrypoint. Must exit 0 with events=[]."""
        with patch.object(
            subprocess,
            "run",
            side_effect=FileNotFoundError("gh not available in hermetic test"),
        ):
            # We can't easily patch the tool subprocess from here since
            # it runs as a real python process — so instead we invoke
            # the module directly via importlib + main(argv=[...]).
            tool = _load_tool()

        # Capture stdout.
        import io

        future = "2099-01-01T00:00:00Z"
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            # Hermetically stub both gh and git subprocess calls.
            with patch.object(
                tool,
                "_gh_pr_view",
                return_value={
                    "headRefName": "claudeboy-capability-v3",
                    "baseRefName": "main",
                    "comments": [
                        {
                            "author": {"login": "Vuk97"},
                            "body": "old codex suggestion: change X",
                            "createdAt": "2020-01-01T00:00:00Z",
                            "url": "https://example/1",
                        }
                    ],
                    "reviews": [],
                    "commits": [],
                },
            ), patch.object(tool, "_git_log_since", return_value=[]):
                rc = tool.main(
                    [
                        "--pr-number",
                        "104",
                        "--since",
                        future,
                        "--peer-name",
                        "opus",
                    ]
                )
        finally:
            sys.stdout = old_stdout

        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["events"], [])
        self.assertEqual(out["peer_name"], "opus")
        self.assertEqual(out["since"], future)
        # Counts should be all zeros.
        self.assertEqual(sum(out["counts"]["by_type"].values()), 0)


class LogAppendTests(unittest.TestCase):
    """T5 test #4: --log-append creates the file if missing."""

    def test_log_append_creates_file_if_missing(self) -> None:
        tool = _load_tool()

        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "new_log_subdir" / "codex_log.md"
            self.assertFalse(log_path.exists())

            import io

            buf = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = buf
                with patch.object(
                    tool,
                    "_gh_pr_view",
                    return_value={
                        "headRefName": "claudeboy-capability-v3",
                        "baseRefName": "main",
                        "comments": [
                            {
                                "author": {"login": "Vuk97"},
                                "body": (
                                    "Codex here — change the nonce "
                                    "check in module foo (suggestion)."
                                ),
                                "createdAt": "2026-04-24T10:00:00Z",
                                "url": "https://example/1",
                            }
                        ],
                        "reviews": [],
                        "commits": [],
                    },
                ), patch.object(tool, "_git_log_since", return_value=[]):
                    rc = tool.main(
                        [
                            "--pr-number",
                            "104",
                            "--since",
                            "2026-04-24T00:00:00Z",
                            "--peer-name",
                            "opus",
                            "--log-append",
                            str(log_path),
                        ]
                    )
            finally:
                sys.stdout = old_stdout

            self.assertEqual(rc, 0)
            self.assertTrue(log_path.exists(), "log file not created")
            contents = log_path.read_text(encoding="utf-8")
            # Must contain the markdown table header we render.
            self.assertIn("peer poll", contents)
            self.assertIn("| type | class | author | route | preview |", contents)
            # Must reference the Codex comment we fed.
            self.assertIn("comment", contents)


class FetchFlagTests(unittest.TestCase):
    """PR #104 blocker #8 fix — `--fetch` flag gates the git-fetch call.

    The tool's docstring claims read-only. Before this fix it ran
    `git fetch --all --prune` unconditionally inside `_git_log_since`,
    which mutates local remote-tracking refs and prunes stale ones.
    The fix gates that call behind an explicit `--fetch` flag; default
    is strictly read-only.
    """

    _EMPTY_PR_PAYLOAD = {
        "headRefName": "claudeboy-capability-v3",
        "baseRefName": "main",
        "comments": [],
        "reviews": [],
        "commits": [],
    }

    def _run_main_capturing_git_calls(
        self, *, extra_argv: list[str]
    ) -> list[list[str]]:
        """Invoke `main(...)` with all subprocess boundaries stubbed.

        Returns the list of argv lists that `subprocess.run` saw
        inside `_git_log_since`. Stubs `_gh_pr_view` to an empty
        payload so the test doesn't depend on live `gh`.
        """
        tool = _load_tool()

        observed: list[list[str]] = []

        def fake_run(
            cmd, *args, **kwargs
        ):  # noqa: ANN001,ARG001 — stdlib subprocess.run signature
            observed.append(list(cmd))
            rv = MagicMock()
            rv.returncode = 0
            # An empty `git log` stdout is the shape _git_log_since
            # expects; other calls don't read stdout.
            rv.stdout = ""
            rv.stderr = ""
            return rv

        import io

        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            with patch.object(
                tool, "_gh_pr_view", return_value=self._EMPTY_PR_PAYLOAD
            ), patch.object(tool.subprocess, "run", side_effect=fake_run):
                rc = tool.main(
                    [
                        "--pr-number",
                        "104",
                        "--since",
                        "2026-04-24T00:00:00Z",
                        "--peer-name",
                        "opus",
                    ]
                    + extra_argv
                )
        finally:
            sys.stdout = old_stdout

        self.assertEqual(rc, 0)
        return observed

    def test_no_fetch_default_doesnt_call_git_fetch(self) -> None:
        """Default invocation: no `git fetch` subprocess call.

        This is the core promise of the fix — the tool honors its
        read-only docstring unless the caller explicitly opts in.
        """
        calls = self._run_main_capturing_git_calls(extra_argv=[])

        for cmd in calls:
            if cmd and cmd[0] == "git" and len(cmd) >= 2 and cmd[1] == "fetch":
                self.fail(
                    f"Default invocation must not call `git fetch`. "
                    f"Observed call: {cmd!r}. All calls: {calls!r}"
                )

    def test_fetch_flag_calls_git_fetch(self) -> None:
        """Explicit `--fetch`: the tool DOES run
        `git fetch --all --prune` before reading the log."""
        calls = self._run_main_capturing_git_calls(extra_argv=["--fetch"])

        fetch_calls = [
            cmd
            for cmd in calls
            if cmd and cmd[0] == "git" and len(cmd) >= 2 and cmd[1] == "fetch"
        ]
        self.assertTrue(
            fetch_calls,
            f"`--fetch` must trigger a `git fetch` call. Calls: {calls!r}",
        )
        # And the precise arg shape must be preserved (all remote-tracking
        # refs + prune stale ones).
        self.assertEqual(
            fetch_calls[0],
            ["git", "fetch", "--all", "--prune"],
            "`--fetch` should run `git fetch --all --prune` exactly.",
        )


class PeerIdentityHeuristicTests(unittest.TestCase):
    """PR #104 blocker #8 fix — tightened peer-identity heuristic.

    Before this fix: a Codex comment on a `claudeboy-capv3-*` branch
    fell through to the branch-name rule and was confidently labelled
    "opus" (self), which the filter then dropped. Fix: for comments
    and reviews, do NOT use claudeboy-branch as an Opus signal —
    Codex also comments/reviews on those shared branches. When no
    richer signal (body marker / author name / explicit codex branch)
    is present, return "unknown" so the filter includes the event
    rather than silently dropping it.
    """

    def test_codex_comment_on_claudeboy_branch_not_misclassified_as_self(
        self,
    ) -> None:
        tool = _load_tool()

        # A Codex-authored comment on a claudeboy branch, with an
        # explicit "Codex here" self-ID marker. The old heuristic
        # *would* have returned "opus" if the body marker lookup
        # failed; the new heuristic returns "codex" via the body
        # marker path, and falls through to "unknown" (never "opus")
        # if the marker is absent.
        marker_peer = tool._guess_peer(
            body="Codex here — this looks fine but consider rebasing.",
            head_ref="claudeboy-capv3-iter4-t1",
            author_name="Vuk97",
            event_type="comment",
        )
        self.assertEqual(
            marker_peer,
            "codex",
            "Body marker must pin the comment to Codex even on a "
            "claudeboy branch.",
        )

        # No marker, just a plain comment on a claudeboy branch.
        # Old heuristic: "opus". New heuristic: "unknown" (never
        # "opus" on a comment, because Codex ALSO comments on these
        # shared branches).
        ambiguous_peer = tool._guess_peer(
            body="this LGTM",
            head_ref="claudeboy-capv3-iter4-t1",
            author_name="Vuk97",
            event_type="comment",
        )
        self.assertNotEqual(
            ambiguous_peer,
            "opus",
            "Unmarked comment on a claudeboy branch must not be "
            "confidently labelled Opus — blocker #8 regression.",
        )
        self.assertEqual(
            ambiguous_peer,
            "unknown",
            "Without richer signal, unmarked comments should be "
            "`unknown` (which the filter then includes).",
        )

        # Commits still use the branch as a signal — the fix is
        # scoped to comments/reviews.
        commit_peer = tool._guess_peer(
            body="Some commit subject without explicit marker",
            head_ref="claudeboy-capv3-iter4-t1",
            author_name="Vuk Tanaskovic",
            event_type="commit",
        )
        self.assertEqual(
            commit_peer,
            "opus",
            "Claudeboy-branch commits without markers still fall "
            "back to opus — the fix is scoped to comments/reviews.",
        )

        # And — critically — the full pipeline must surface an
        # ambiguous Codex-style comment as a peer event when Opus
        # is running the poll.
        payload = {
            "headRefName": "claudeboy-capv3-iter4-t1",
            "baseRefName": "main",
            "comments": [
                {
                    "author": {"login": "Vuk97"},
                    # Ambiguous body — no Opus/Codex marker.
                    "body": "LGTM, but double-check the nonce path.",
                    "createdAt": "2026-04-24T10:00:00Z",
                    "url": "https://example/1",
                }
            ],
            "reviews": [],
            "commits": [],
        }
        events = tool.build_events(
            pr_data=payload,
            git_commits=[],
            peer_name="opus",
            since="2026-04-24T00:00:00Z",
        )
        self.assertEqual(
            len(events),
            1,
            "An ambiguous comment on a claudeboy branch must NOT be "
            "filtered as self when Opus is polling — blocker #8.",
        )


if __name__ == "__main__":
    unittest.main()
