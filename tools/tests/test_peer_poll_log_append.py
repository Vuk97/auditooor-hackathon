#!/usr/bin/env python3
"""capability-v3 iter-005 T4 — peer-poll log-append regression tests.

Hermetic: no live `gh`, no live `git`. All subprocess boundaries are
stubbed via `unittest.mock.patch`. Fixtures are built inline.

These tests lock the `--log-append` path of `tools/codex-peer-poll.py`
now that iter-v3-5 T4 has wired it into the cron peer-poll loop. Two
invariants matter for the cron caller:

1. Appending to a non-existent (or empty) log must produce a valid
   markdown tick section — both the file and its parent directory are
   created on demand.
2. Appending to an already-populated log must NOT rewrite or drop the
   existing entries; the new tick section is appended after whatever
   is already there.

If either invariant regresses the cron loop either silently nukes
operator-visible log history (regression #2) or quietly races on the
first tick of a new engagement (regression #1).
"""
from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "codex-peer-poll.py"


def _load_tool():
    """Load codex-peer-poll.py as a module for direct unit testing.

    The tool's filename contains a hyphen, which is not a valid Python
    identifier, so we go through importlib.
    """
    spec = importlib.util.spec_from_file_location("codex_peer_poll", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_EMPTY_PR_PAYLOAD = {
    "headRefName": "claudeboy-capability-v3",
    "baseRefName": "main",
    "comments": [],
    "reviews": [],
    "commits": [],
}


def _run_poll_with_log_append(log_path: Path) -> int:
    """Invoke the tool's `main(...)` with `--log-append <log_path>`.

    Hermetically stubs both subprocess boundaries (`_gh_pr_view` and
    `_git_log_since`) so the test does not shell out. Returns the
    tool's exit code.
    """
    tool = _load_tool()

    buf = io.StringIO()
    old_stdout = sys.stdout
    try:
        sys.stdout = buf
        with patch.object(
            tool, "_gh_pr_view", return_value=_EMPTY_PR_PAYLOAD
        ), patch.object(tool, "_git_log_since", return_value=[]):
            rc = tool.main(
                [
                    "--pr-number",
                    "104",
                    "--since",
                    "2026-04-20T00:00:00Z",
                    "--peer-name",
                    "opus",
                    "--log-append",
                    str(log_path),
                ]
            )
    finally:
        sys.stdout = old_stdout
    return rc


class LogAppendEmptyLogTests(unittest.TestCase):
    """Test 1: append to a non-existent log creates a valid markdown section."""

    def test_append_to_empty_log_creates_valid_markdown_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "new_subdir" / "codex_log.md"
            self.assertFalse(log_path.exists())

            rc = _run_poll_with_log_append(log_path)
            self.assertEqual(rc, 0)

            self.assertTrue(
                log_path.exists(),
                "Log file must be created by `--log-append` on a "
                "non-existent path.",
            )
            self.assertTrue(
                log_path.parent.is_dir(),
                "Parent directory must be created when missing.",
            )

            contents = log_path.read_text(encoding="utf-8")

            # A valid tick section has a `## <ts> — PR #N peer poll`
            # header, a `since:` line, an `events:` line. With zero
            # peer events we also expect the honest-zero line.
            tick_headers = [
                line
                for line in contents.splitlines()
                if line.startswith("## ") and "peer poll" in line
            ]
            self.assertEqual(
                len(tick_headers),
                1,
                f"Expected exactly 1 tick section header; got "
                f"{len(tick_headers)}. Contents:\n{contents!r}",
            )
            self.assertIn("- since: `2026-04-20T00:00:00Z`", contents)
            self.assertIn("- events: 0", contents)
            self.assertIn("_No peer events in window._", contents)


class LogAppendNonEmptyLogTests(unittest.TestCase):
    """Test 2: appending to a populated log preserves existing entries."""

    _PREEXISTING_LOG = (
        "# Capability v3 — Codex peer-poll log\n"
        "\n"
        "**Purpose.** Append-only telemetry log of Codex peer activity.\n"
        "\n"
        "## 2026-04-23T12:00:00Z — PR #104 peer poll (peer=opus)\n"
        "\n"
        "- since: `2026-04-22T00:00:00Z`\n"
        "- events: 1\n"
        "\n"
        "| type | class | author | route | preview |\n"
        "|---|---|---|---|---|\n"
        "| comment | suggestion | Vuk97 | file-as-T-candidate | "
        "Codex here — consider rebasing on main. |\n"
        "\n"
    )

    def test_append_to_non_empty_log_preserves_existing_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "codex_log.md"
            log_path.write_text(self._PREEXISTING_LOG, encoding="utf-8")

            original_size = log_path.stat().st_size
            self.assertGreater(original_size, 0)

            rc = _run_poll_with_log_append(log_path)
            self.assertEqual(rc, 0)

            contents = log_path.read_text(encoding="utf-8")

            # Invariant A — nothing from the pre-existing content was
            # dropped or rewritten. We check every non-empty line from
            # the seed survives verbatim.
            for preexisting_line in self._PREEXISTING_LOG.splitlines():
                if not preexisting_line.strip():
                    continue
                self.assertIn(
                    preexisting_line,
                    contents,
                    f"Pre-existing log line was dropped/rewritten: "
                    f"{preexisting_line!r}",
                )

            # Invariant B — the file grew (a new tick section was
            # appended, not substituted).
            self.assertGreater(
                log_path.stat().st_size,
                original_size,
                "Log file did not grow — new tick section was not appended.",
            )

            # Invariant C — there are now exactly 2 tick-section
            # headers (the pre-existing one + the new one).
            tick_headers = [
                line
                for line in contents.splitlines()
                if line.startswith("## ") and "peer poll" in line
            ]
            self.assertEqual(
                len(tick_headers),
                2,
                f"Expected 2 tick section headers (pre-existing + new); "
                f"got {len(tick_headers)}.",
            )

            # Invariant D — the pre-existing section's timestamp still
            # appears and the new section's `--since` timestamp is
            # reflected somewhere below it.
            seed_ts = "2026-04-23T12:00:00Z"
            new_since = "2026-04-20T00:00:00Z"
            self.assertIn(seed_ts, contents)
            # The new section's since-line is after the seed header's
            # position (append-only ordering).
            seed_pos = contents.index(seed_ts)
            since_pos = contents.find(f"- since: `{new_since}`")
            self.assertGreater(
                since_pos,
                seed_pos,
                "New tick section must be appended AFTER the "
                "pre-existing section (append-only ordering).",
            )


if __name__ == "__main__":
    unittest.main()
