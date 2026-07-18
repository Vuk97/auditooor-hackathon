"""Tests for tools/claude-pre-source-read-hook.sh — Wave-6 Phase C."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK_PATH = REPO_ROOT / "tools" / "claude-pre-source-read-hook.sh"
FIXTURE_GO = REPO_ROOT / "tools" / "tests" / "fixtures" / "fn_sig_extractor_go" / "sample.go"


def _run_hook(*args: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(HOOK_PATH), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


class ClaudePreSourceReadHookTests(unittest.TestCase):
    def test_hook_is_executable(self) -> None:
        self.assertTrue(HOOK_PATH.is_file(), f"hook missing: {HOOK_PATH}")
        mode = HOOK_PATH.stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR, "hook must be executable by owner")

    def test_skips_when_empty_arg(self) -> None:
        proc = _run_hook("")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "")

    def test_skips_when_file_missing(self) -> None:
        proc = _run_hook("/tmp/definitely-not-here-abcxyz.go")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "")

    def test_skips_unsupported_extension(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            md = Path(td) / "notes.md"
            md.write_text("# md\n")
            proc = _run_hook(str(md))
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout.strip(), "")

    def test_emits_claude_hook_json_for_real_go_file(self) -> None:
        proc = _run_hook(
            str(FIXTURE_GO),
            env_extra={"TARGET_REPO": "dydxprotocol/v4-chain"},
        )
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
        self.assertTrue(proc.stdout.strip(), "expected Claude hook payload on stdout")
        data = json.loads(proc.stdout)
        self.assertEqual(data["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "allow")
        # additionalContext inside hookSpecificOutput is the canonical PreToolUse
        # injection field (Claude Code changelog: "Added support for PreToolUse
        # hooks to return additionalContext to the model"). systemMessage is
        # retained as a display-layer copy in the TUI transcript.
        self.assertIn("additionalContext", data["hookSpecificOutput"])
        self.assertIn("Auditooor pre-source-read hacker questions", data["hookSpecificOutput"]["additionalContext"])
        self.assertLessEqual(len(data["hookSpecificOutput"]["additionalContext"]), 2200)
        # systemMessage display copy is also present
        self.assertIn("systemMessage", data)
        self.assertIn("Auditooor pre-source-read hacker questions", data["systemMessage"])
        self.assertLessEqual(len(data["systemMessage"]), 2200)

    def test_outer_hook_emits_valid_hook_json_from_tool_call_payload(self) -> None:
        """The outer ~/.claude/hooks/auditooor-pre-source-read-hook.sh must emit
        valid hook JSON with additionalContext when given a Read tool-call payload
        on stdin. This validates the full delivery chain: outer hook -> inner hook
        -> injector -> additionalContext in agent context."""
        import os
        import subprocess

        outer_hook = Path("/Users/wolf/.claude/hooks/auditooor-pre-source-read-hook.sh")
        if not outer_hook.is_file():
            self.skipTest(f"outer hook not found at {outer_hook}")

        file_path = str(FIXTURE_GO)
        stdin_payload = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": file_path},
        })
        env = os.environ.copy()
        env["TARGET_REPO"] = "dydxprotocol/v4-chain"
        env["AUDITOOOR_PAYLOAD_GUARD_DISABLE"] = "1"

        proc = subprocess.run(
            ["bash", str(outer_hook)],
            input=stdin_payload,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, f"outer hook failed: stderr={proc.stderr}")
        self.assertTrue(proc.stdout.strip(), "outer hook must emit non-empty JSON on stdout")
        data = json.loads(proc.stdout)
        # Full delivery chain: additionalContext in hookSpecificOutput
        self.assertIn("hookSpecificOutput", data)
        self.assertIn("additionalContext", data["hookSpecificOutput"],
                      "additionalContext must be inside hookSpecificOutput for PreToolUse injection")
        card = data["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Auditooor pre-source-read hacker questions", card)
        self.assertIn("Advisory only", card)
        # 2KB bound (outer hook uses default 2000 chars)
        self.assertLessEqual(len(card), 2200, f"card too large ({len(card)} chars)")
        # systemMessage display copy also present
        self.assertIn("systemMessage", data)

    def test_raw_json_mode_preserves_machine_payload(self) -> None:
        proc = _run_hook(
            str(FIXTURE_GO),
            env_extra={
                "TARGET_REPO": "dydxprotocol/v4-chain",
                "AUDITOOOR_PRE_SOURCE_READ_RAW_JSON": "1",
            },
        )
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
        self.assertTrue(proc.stdout.strip(), "expected raw JSON payload on stdout")
        data = json.loads(proc.stdout)
        self.assertEqual(data["schema"], "auditooor.pre_source_read_injection.v1")
        self.assertGreaterEqual(data["functions_analyzed"], 1)


if __name__ == "__main__":
    unittest.main()
