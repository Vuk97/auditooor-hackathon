#!/usr/bin/env python3
"""test_commit_completeness_hook_wired.py

Enforcement-gap orphan (2026-07-03): tools/commit-completeness-check.py (the L4
UNDER-commit dual of the R36 pathspec hook) had ZERO callers - a lane that
registered a pathspec then staged only a subset of its declared files, leaving
registered files with pending content behind, was never caught. This pins the
wiring in the pre-commit dispatcher: the under-commit check runs for the current
lane, ADVISORY-first, aborting only under AUDITOOOR_COMMIT_COMPLETENESS_STRICT,
and (crucially) UNDER-commit-only (--no-over-commit) so it never double-fires
with the R36 Gap #55 over-commit check.

Behavioral coverage of the tool itself lives in test_commit_completeness_check.py.
"""
import subprocess
import unittest
from pathlib import Path

_HOOK = Path(__file__).resolve().parents[2] / "git-hooks" / "pre-commit"
if not _HOOK.is_file():
    _HOOK = Path(__file__).resolve().parents[1] / "git-hooks" / "pre-commit"
_TEXT = _HOOK.read_text(encoding="utf-8", errors="replace")


class TestCommitCompletenessHookWired(unittest.TestCase):
    def test_tool_is_invoked(self):
        self.assertIn("commit-completeness-check.py", _TEXT,
                      "the pre-commit dispatcher must call the under-commit gate")

    def test_under_commit_only_no_double_fire(self):
        self.assertIn("--no-over-commit", _TEXT,
                      "must run under-commit-only so it does not double-fire with R36 Gap #55")

    def test_lane_resolved_like_r36(self):
        self.assertIn("R36_CURRENT_AGENT_ID", _TEXT)

    def test_advisory_first_gated_env(self):
        self.assertIn("AUDITOOOR_COMMIT_COMPLETENESS_STRICT", _TEXT,
                      "the abort path must be gated behind the named strict env (advisory-first)")

    def test_no_lane_is_noop(self):
        # the guard requires a non-empty CCC_LANE before invoking the tool
        self.assertIn('-n "$CCC_LANE"', _TEXT)

    def test_bash_syntax_ok(self):
        r = subprocess.run(["bash", "-n", str(_HOOK)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
