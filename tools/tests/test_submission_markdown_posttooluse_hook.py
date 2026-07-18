#!/usr/bin/env python3
"""Tests for submission markdown PostToolUse hook routing."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
HOOK = REPO / "tools" / "hooks" / "submission-markdown-posttooluse.sh"


def _run_hook(
    payload: dict,
    *,
    dry_run: bool = True,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if dry_run:
        env["DRY_RUN"] = "1"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _draft_path(name: str = "candidate-HIGH.md") -> Path:
    root = Path(tempfile.mkdtemp(prefix="submission_hook_"))
    path = root / "audit" / "submissions" / "staging" / name
    path.parent.mkdir(parents=True)
    path.write_text("Severity: High\n", encoding="utf-8")
    return path


class SubmissionMarkdownHookTests(unittest.TestCase):
    def test_bash_syntax_valid(self) -> None:
        proc = subprocess.run(["bash", "-n", str(HOOK)], capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_read_tool_is_ignored(self) -> None:
        path = _draft_path()
        proc = _run_hook({"tool_name": "Read", "tool_input": {"file_path": str(path)}})
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("would-run", proc.stdout)

    def test_unrelated_file_is_ignored(self) -> None:
        unrelated = REPO / "tools" / "pre-submit-check.sh"
        proc = _run_hook({"tool_name": "Edit", "tool_input": {"file_path": str(unrelated)}})
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("would-run", proc.stdout)

    def test_staging_markdown_triggers_watchdog(self) -> None:
        path = _draft_path()
        proc = _run_hook({"tool_name": "Edit", "tool_input": {"file_path": str(path)}})
        self.assertEqual(proc.returncode, 0)
        self.assertIn("would-run:", proc.stdout)
        self.assertIn("pre-submit-watchdog.py", proc.stdout)
        self.assertIn(str(path), proc.stdout)
        self.assertIn("--advisory", proc.stdout)

    def test_paste_ready_markdown_triggers_watchdog(self) -> None:
        path = _draft_path()
        target = path.parents[1] / "paste_ready" / "candidate-HIGH.md"
        target.parent.mkdir(parents=True)
        target.write_text("Severity: High\n", encoding="utf-8")
        proc = _run_hook({"tool_name": "MultiEdit", "tool_input": {"file_path": str(target)}})
        self.assertEqual(proc.returncode, 0)
        self.assertIn("would-run:", proc.stdout)
        self.assertIn("pre-submit-watchdog.py", proc.stdout)
        self.assertNotIn("--advisory", proc.stdout)

    def test_solidity_changelog_ref_triggers_l33_check_in_dry_run(self) -> None:
        path = _draft_path()
        path.write_text(
            "Severity: High\nCHANGELOG.md:4 says ordering changed.\n`src/Vault.sol` still has a stale invariant.\n",
            encoding="utf-8",
        )
        proc = _run_hook({"tool_name": "Edit", "tool_input": {"file_path": str(path)}})
        self.assertEqual(proc.returncode, 0)
        self.assertIn("l33-changelog-drift-check.py", proc.stdout)
        self.assertIn("--write-sidecar", proc.stdout)

    def test_non_solidity_changelog_ref_does_not_trigger_l33_check(self) -> None:
        path = _draft_path()
        path.write_text(
            "Severity: Low\nCHANGELOG.md:4 updated the dashboard copy for support docs.\n",
            encoding="utf-8",
        )
        proc = _run_hook({"tool_name": "Edit", "tool_input": {"file_path": str(path)}})
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("l33-changelog-drift-check.py", proc.stdout)

    def test_strict_env_removes_advisory_for_staging_markdown(self) -> None:
        path = _draft_path()
        proc = _run_hook(
            {"tool_name": "Edit", "tool_input": {"file_path": str(path)}},
            extra_env={"AUDITOOOR_SUBMISSION_HOOK_STRICT": "1"},
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("would-run:", proc.stdout)
        self.assertNotIn("--advisory", proc.stdout)

    def test_advisory_env_overrides_paste_ready_default(self) -> None:
        path = _draft_path()
        target = path.parents[1] / "paste_ready" / "candidate-HIGH.md"
        target.parent.mkdir(parents=True)
        target.write_text("Severity: High\n", encoding="utf-8")
        proc = _run_hook(
            {"tool_name": "Write", "tool_input": {"file_path": str(target)}},
            extra_env={"AUDITOOOR_SUBMISSION_HOOK_ADVISORY": "1"},
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("would-run:", proc.stdout)
        self.assertIn("--advisory", proc.stdout)

    def test_malformed_json_exits_zero(self) -> None:
        proc = subprocess.run(
            ["bash", str(HOOK)],
            input="not json",
            capture_output=True,
            text=True,
            env={**os.environ, "DRY_RUN": "1"},
            check=False,
        )
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
