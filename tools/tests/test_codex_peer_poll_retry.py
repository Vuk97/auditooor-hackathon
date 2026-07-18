#!/usr/bin/env python3
"""capability-v3 iter-009 T4 — codex-peer-poll retry regression tests.

Locks the `_run_gh_with_retry` helper added in iter-v3-9 T4. The helper
wraps the single `gh pr view` subprocess.run call in
`tools/codex-peer-poll.py` and retries on transient failures:

  * HTTP 429 (rate-limit wording or the `429` substring in stderr)
  * HTTP 5xx (stderr matches `\\b5\\d\\d\\b`)
  * `subprocess.TimeoutExpired`
  * `ConnectionError`

Backoff: `time.sleep(min(backoff_base ** attempt, 8.0))` between
attempts (defaults: 2s, 4s, 8s). Max 3 retries after the initial call.
On exhaustion the tool emits honest-zero JSON with
`reason: "gh_api_rate_limit_exhausted"` and exits 0 — cron tick
continuity is more valuable than a single loud failure.

Hermetic: every test patches `subprocess.run` and `time.sleep`. No
live `gh`, no live network, no real wall-clock waiting.
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "codex-peer-poll.py"


def _load_tool():
    """Load codex-peer-poll.py as a module for direct unit testing."""
    spec = importlib.util.spec_from_file_location("codex_peer_poll", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ok_proc(stdout: str = "{}", stderr: str = "") -> MagicMock:
    rv = MagicMock(spec=subprocess.CompletedProcess)
    rv.returncode = 0
    rv.stdout = stdout
    rv.stderr = stderr
    return rv


def _err_proc(stderr: str, returncode: int = 1) -> MagicMock:
    rv = MagicMock(spec=subprocess.CompletedProcess)
    rv.returncode = returncode
    rv.stdout = ""
    rv.stderr = stderr
    return rv


_GOOD_PAYLOAD = {
    "headRefName": "claudeboy-capability-v3",
    "baseRefName": "main",
    "comments": [],
    "reviews": [],
    "commits": [],
}


class RetryHelperUnitTests(unittest.TestCase):
    """Direct unit tests on `_run_gh_with_retry`."""

    def test_429_then_success_returns_data_after_retry(self) -> None:
        """First call → 429 stderr. Second call → success. Final result
        must be the success CompletedProcess (retry worked)."""
        tool = _load_tool()

        seq = [
            _err_proc("API rate limit exceeded for user"),
            _ok_proc(stdout=json.dumps(_GOOD_PAYLOAD)),
        ]
        with patch.object(
            tool.subprocess, "run", side_effect=seq
        ), patch.object(tool.time, "sleep") as fake_sleep:
            result = tool._run_gh_with_retry(["pr", "view", "104"])

        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, json.dumps(_GOOD_PAYLOAD))
        # Exactly one backoff between the two attempts (2 ** 1 = 2s).
        self.assertEqual(fake_sleep.call_count, 1)
        self.assertAlmostEqual(fake_sleep.call_args_list[0][0][0], 2.0)

    def test_5xx_then_success_returns_data_after_retry(self) -> None:
        """First call → HTTP 502 stderr. Second call → success."""
        tool = _load_tool()

        seq = [
            _err_proc("HTTP 502 Bad Gateway from api.github.com"),
            _ok_proc(stdout=json.dumps(_GOOD_PAYLOAD)),
        ]
        with patch.object(
            tool.subprocess, "run", side_effect=seq
        ), patch.object(tool.time, "sleep") as fake_sleep:
            result = tool._run_gh_with_retry(["pr", "view", "104"])

        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(fake_sleep.call_count, 1)

    def test_timeout_then_success_returns_data_after_retry(self) -> None:
        """First call → TimeoutExpired. Second call → success."""
        tool = _load_tool()

        seq = [
            subprocess.TimeoutExpired(cmd=["gh"], timeout=30),
            _ok_proc(stdout=json.dumps(_GOOD_PAYLOAD)),
        ]
        with patch.object(
            tool.subprocess, "run", side_effect=seq
        ), patch.object(tool.time, "sleep") as fake_sleep:
            result = tool._run_gh_with_retry(["pr", "view", "104"])

        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(fake_sleep.call_count, 1)

    def test_connection_error_then_success_returns_data_after_retry(
        self,
    ) -> None:
        """First call → ConnectionError. Second call → success.

        Optional 5th-test slot from the T4 spec.
        """
        tool = _load_tool()

        seq = [
            ConnectionError("broken pipe"),
            _ok_proc(stdout=json.dumps(_GOOD_PAYLOAD)),
        ]
        with patch.object(
            tool.subprocess, "run", side_effect=seq
        ), patch.object(tool.time, "sleep") as fake_sleep:
            result = tool._run_gh_with_retry(["pr", "view", "104"])

        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(fake_sleep.call_count, 1)

    def test_persistent_429_returns_rate_limit_exhausted_sentinel(
        self,
    ) -> None:
        """All 4 attempts (1 + 3 retries) return 429 → helper returns
        the `_GH_RATE_LIMIT_EXHAUSTED` sentinel string."""
        tool = _load_tool()

        seq = [
            _err_proc("API rate limit exceeded for user (1)"),
            _err_proc("API rate limit exceeded for user (2)"),
            _err_proc("API rate limit exceeded for user (3)"),
            _err_proc("API rate limit exceeded for user (4)"),
        ]
        with patch.object(
            tool.subprocess, "run", side_effect=seq
        ), patch.object(tool.time, "sleep") as fake_sleep:
            result = tool._run_gh_with_retry(["pr", "view", "104"])

        self.assertEqual(result, tool._GH_RATE_LIMIT_EXHAUSTED)
        # Backoffs between attempts: 2s, 4s, 8s (ceilinged at 8s).
        self.assertEqual(fake_sleep.call_count, 3)
        waits = [c[0][0] for c in fake_sleep.call_args_list]
        self.assertEqual(waits, [2.0, 4.0, 8.0])

    def test_permanent_error_not_retried(self) -> None:
        """A non-retryable error (e.g. auth) returns after 1 attempt —
        the helper MUST NOT mask permanent failures behind retries."""
        tool = _load_tool()

        seq = [
            _err_proc("HTTP 403 Forbidden: auth required", returncode=1),
        ]
        with patch.object(
            tool.subprocess, "run", side_effect=seq
        ), patch.object(tool.time, "sleep") as fake_sleep:
            result = tool._run_gh_with_retry(["pr", "view", "104"])

        # Result is the CompletedProcess (caller decides what to do).
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.returncode, 1)
        # No backoff — permanent errors are returned immediately.
        self.assertEqual(fake_sleep.call_count, 0)

    def test_file_not_found_returns_gh_missing_sentinel(self) -> None:
        """`gh` binary missing → FileNotFoundError → `_GH_MISSING`."""
        tool = _load_tool()

        with patch.object(
            tool.subprocess,
            "run",
            side_effect=FileNotFoundError("gh not on PATH"),
        ), patch.object(tool.time, "sleep") as fake_sleep:
            result = tool._run_gh_with_retry(["pr", "view", "104"])

        self.assertEqual(result, tool._GH_MISSING)
        # No backoff — missing binary won't appear mid-loop.
        self.assertEqual(fake_sleep.call_count, 0)


class EndToEndRetryTests(unittest.TestCase):
    """End-to-end: `main(argv=…)` under various retry scenarios.

    Locks the full CLI contract — including the honest-zero JSON
    shape on retry exhaustion (exit 0, `reason:
    gh_api_rate_limit_exhausted`).
    """

    def _run_main(
        self, run_side_effect, *, extra_argv=None
    ) -> tuple[int, dict]:
        """Invoke `main([...])` with `subprocess.run` and `time.sleep`
        patched. Returns (rc, parsed-stdout-json)."""
        tool = _load_tool()
        extra_argv = extra_argv or []

        old_stdout = sys.stdout
        buf = io.StringIO()
        try:
            sys.stdout = buf
            with patch.object(
                tool.subprocess, "run", side_effect=run_side_effect
            ), patch.object(tool.time, "sleep"), patch.object(
                tool, "_git_log_since", return_value=[]
            ):
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

        parsed = json.loads(buf.getvalue())
        return rc, parsed

    def test_persistent_429_main_returns_honest_zero_rate_limit_exhausted(
        self,
    ) -> None:
        """Full-pipeline lock: 4 consecutive 429s → exit 0, empty events,
        `reason: "gh_api_rate_limit_exhausted"`."""
        seq = [_err_proc("API rate limit exceeded") for _ in range(4)]
        # Git-log is patched out, so the ONLY subprocess.run calls come
        # from _run_gh_with_retry.
        rc, out = self._run_main(seq)

        self.assertEqual(rc, 0, "Retry exhaustion must exit 0 for cron continuity")
        self.assertEqual(out["events"], [])
        self.assertEqual(
            out["reason"],
            "gh_api_rate_limit_exhausted",
            "Exhausted-retry reason must distinguish from `gh-missing`",
        )
        self.assertEqual(out["peer_name"], "opus")
        self.assertEqual(out["pr_number"], 104)
        # Counts are all zero.
        self.assertEqual(sum(out["counts"]["by_type"].values()), 0)
        self.assertEqual(sum(out["counts"]["by_classification"].values()), 0)


if __name__ == "__main__":
    unittest.main()
