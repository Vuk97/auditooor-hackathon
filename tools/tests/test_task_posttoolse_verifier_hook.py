#!/usr/bin/env python3
"""Regression tests for the Task PostToolUse MCP-citation verifier hook.

Hook under test: ~/.claude/hooks/auditooor-task-posttoolse-verifier.sh

Each test simulates a PostToolUse JSON payload (matcher=Task) and asserts:
  - hook always exits 0 (non-blocking)
  - verdict line is appended to <workspace>/.auditooor/task_verifier_log.jsonl
  - verdict matches PASS / FAIL / SKIP per the inline verifier rules

Empirical anchor: mirrors the rules in
  ~/.claude/hooks/auditooor-task-report-mcp-verifier.sh
which has been runtime-validated against all 12 hunt agent reports from
2026-05-15 (MCP_ENFORCEMENT_FIX_2026-05-15.md).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


HOOK = Path("/Users/wolf/.claude/hooks/auditooor-task-posttoolse-verifier.sh")


def _inject_workspace(payload: dict, ws_path: str) -> dict:
    """Ensure the prompt references the test workspace path so payload-guard
    proceeds. Does NOT modify tool_response — the verifier scans that text
    for verdict logic and we mustn't contaminate it with workspace tokens
    that contain hex-shaped chars or auditooor pack-id substrings."""
    p = json.loads(json.dumps(payload))  # deep copy
    ti = p.setdefault("tool_input", {})
    prompt = ti.get("prompt") or ""
    if ws_path not in prompt:
        ti["prompt"] = f"workspace: {ws_path}\n{prompt}"
    return p


def _run_hook(
    payload: dict,
    *,
    workspace_override: str | None = None,
    extra_env: dict | None = None,
) -> tuple[subprocess.CompletedProcess, Path]:
    env = os.environ.copy()
    # Force payload-guard active everywhere so tests don't depend on cwd.
    env["AUDITOOOR_PAYLOAD_GUARD_DISABLE"] = "1"
    if extra_env:
        env.update(extra_env)

    tmp_root = Path(tempfile.mkdtemp(prefix="task_verifier_test_"))
    if workspace_override:
        ws = Path(workspace_override)
        ws.mkdir(parents=True, exist_ok=True)
        # The hook's payload-derivation regex matches /Users/wolf/audits/<eng>
        # which won't hit our /var/folders tempdir. Run with cwd=ws so the
        # hook falls back to `cwd/.auditooor` and lands inside our sandbox.
        # Also inject the path into the payload anyway as a belt-and-braces.
        payload = _inject_workspace(payload, str(ws))
        cwd = ws
        log_dir = ws / ".auditooor"
    else:
        cwd = tmp_root
        log_dir = cwd / ".auditooor"

    proc = subprocess.run(
        ["bash", str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd),
        check=False,
    )
    return proc, log_dir


def _read_verdict_rows(log_dir: Path) -> list[dict]:
    log = log_dir / "task_verifier_log.jsonl"
    if not log.exists():
        return []
    rows = []
    for line in log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return rows


# ---------------- canned report fixtures ----------------------------------

GOOD_REPORT = """## Lane verdict: NEGATIVE

MCP-first recall block:
- pack_id: auditooor.vault_resume_context.v1:resume:9c22d5ca5ff71f09
- pack_hash: 9c22d5ca5ff71f09da8e93a09685549d22d84ef63d4419f7c73b07e6480d8aa6
- vault_attack_class_evidence: 0 verdicts

Workspace: /Users/wolf/audits/dydx
Verdict: NEGATIVE / DROP - no fileable signal.
"""

BAD_REPORT_NO_PACKID = """## Lane verdict: HOLD

Workspace /Users/wolf/audits/dydx
Hash: 9c22d5ca5ff71f09da8e93a09685549d22d84ef63d4419f7c73b07e6480d8aa6
(no MCP callable cited; no schema reference)
"""

BAD_REPORT_NO_HASH = """## Lane verdict: NEGATIVE

vault_resume_context invoked.
context_pack_id: auditooor.vault_resume_context.v1:resume:abcdef0123456789
(no 40+ hex hash)
"""

BAD_REPORT_HUNT_LANE_NO_CALLABLE = """## Lane verdict: HOLD

pack_id: auditooor.vault_remember.v1:1234567890abcdef
some_long_hex: 0123456789abcdef0123456789abcdef0123456789abcdef
No callable, no header, no receipts.
"""

EMPTY_REPORT = ""


# ---------------- test cases ----------------------------------------------

class TaskPostToolseVerifierTests(unittest.TestCase):
    def test_hook_file_exists_and_executable(self):
        self.assertTrue(HOOK.exists(), f"hook missing: {HOOK}")
        self.assertTrue(os.access(HOOK, os.X_OK), "hook not executable")

    def test_bash_syntax_valid(self):
        proc = subprocess.run(
            ["bash", "-n", str(HOOK)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_kill_switch_skips_silently(self):
        tmp = tempfile.mkdtemp(prefix="task_kill_")
        ws = Path(tmp) / "Users" / "wolf" / "audits" / "killtest"
        payload = {
            "tool_name": "Task",
            "tool_input": {"prompt": f"workspace: {ws} hunt"},
            "tool_response": GOOD_REPORT,
        }
        proc, log_dir = _run_hook(
            payload, workspace_override=str(ws),
            extra_env={"AUDITOOOR_TASK_POSTHOOK_VERIFIER_DISABLE": "1"},
        )
        self.assertEqual(proc.returncode, 0)
        # No log entry should have been written
        self.assertFalse((Path(log_dir) / "task_verifier_log.jsonl").exists())

    def test_non_task_tool_ignored(self):
        payload = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/Users/wolf/audits/dydx/foo.md"},
            "tool_response": GOOD_REPORT,
        }
        proc, log_dir = _run_hook(payload)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(_read_verdict_rows(log_dir), [])

    def test_good_report_logged_as_pass(self):
        tmp = tempfile.mkdtemp(prefix="task_pass_")
        ws = str(Path(tmp) / "Users" / "wolf" / "audits" / "passtest")
        payload = {
            "tool_name": "Task",
            "tool_input": {
                "subagent_type": "general-purpose",
                "prompt": (
                    "lane_id: LANE-DYDX-OBSERVE\n"
                    f"workspace: {ws}\n"
                    "Run MCP-first recall."
                ),
            },
            "tool_response": GOOD_REPORT,
        }
        proc, log_dir = _run_hook(payload, workspace_override=ws)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rows = _read_verdict_rows(log_dir)
        self.assertEqual(len(rows), 1, f"want 1 row, got rows={rows}")
        row = rows[0]
        self.assertEqual(row["verdict"], "PASS", row)
        self.assertEqual(row["tool"], "Task")
        self.assertEqual(row["subagent_type"], "general-purpose")
        self.assertEqual(row["lane_id"], "LANE-DYDX-OBSERVE")
        self.assertGreater(row["report_chars"], 0)

    def test_missing_packid_logged_as_fail(self):
        tmp = tempfile.mkdtemp(prefix="task_fail_packid_")
        ws = str(Path(tmp) / "Users" / "wolf" / "audits" / "packidtest")
        payload = {
            "tool_name": "Task",
            "tool_input": {
                "subagent_type": "general-purpose",
                "prompt": f"lane_id: LANE-BAD\nworkspace: {ws}",
            },
            "tool_response": BAD_REPORT_NO_PACKID,
        }
        proc, log_dir = _run_hook(payload, workspace_override=ws)
        self.assertEqual(proc.returncode, 0)  # non-blocking
        rows = _read_verdict_rows(log_dir)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "FAIL")
        self.assertIn("pack-id", rows[0]["reason"])
        # FAIL emits stderr warning
        self.assertIn("FAIL", proc.stderr, f"stderr={proc.stderr!r}")

    def test_missing_hash_logged_as_fail(self):
        tmp = tempfile.mkdtemp(prefix="task_fail_hash_")
        ws = str(Path(tmp) / "Users" / "wolf" / "audits" / "hashtest")
        payload = {
            "tool_name": "Task",
            "tool_input": {"prompt": f"workspace: {ws}"},
            "tool_response": BAD_REPORT_NO_HASH,
        }
        proc, log_dir = _run_hook(payload, workspace_override=ws)
        self.assertEqual(proc.returncode, 0)
        rows = _read_verdict_rows(log_dir)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "FAIL")
        self.assertIn("hash", rows[0]["reason"])

    def test_hunt_lane_without_callable_logged_as_fail(self):
        tmp = tempfile.mkdtemp(prefix="task_fail_callable_")
        ws = str(Path(tmp) / "Users" / "wolf" / "audits" / "callabletest")
        payload = {
            "tool_name": "Task",
            "tool_input": {"prompt": f"workspace: {ws} hunt"},
            "tool_response": BAD_REPORT_HUNT_LANE_NO_CALLABLE,
        }
        proc, log_dir = _run_hook(payload, workspace_override=ws)
        self.assertEqual(proc.returncode, 0)
        rows = _read_verdict_rows(log_dir)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "FAIL")
        self.assertIn("MCP", rows[0]["reason"])

    def test_empty_report_logged_as_skip(self):
        tmp = tempfile.mkdtemp(prefix="task_skip_")
        ws = str(Path(tmp) / "Users" / "wolf" / "audits" / "skiptest")
        payload = {
            "tool_name": "Task",
            "tool_input": {"prompt": f"workspace: {ws}"},
            "tool_response": "",
        }
        proc, log_dir = _run_hook(payload, workspace_override=ws)
        self.assertEqual(proc.returncode, 0)
        rows = _read_verdict_rows(log_dir)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "SKIP")

    def test_payload_guard_skips_non_audits(self):
        """Non-audits payload must NOT trigger logging."""
        tmp = tempfile.mkdtemp(prefix="task_noaudit_")
        payload = {
            "tool_name": "Task",
            "tool_input": {"prompt": "Build me a recipe app"},
            "tool_response": "## Recipe done\nlots of content",
        }
        # Don't disable payload-guard here; we want it active
        env = os.environ.copy()
        env.pop("AUDITOOOR_PAYLOAD_GUARD_DISABLE", None)
        proc = subprocess.run(
            ["bash", str(HOOK)],
            input=json.dumps(payload),
            capture_output=True, text=True,
            env=env, cwd=tmp, check=False,
        )
        self.assertEqual(proc.returncode, 0)
        # No log dir created
        self.assertFalse((Path(tmp) / ".auditooor"
                          / "task_verifier_log.jsonl").exists())

    def test_tool_response_as_content_list_shape(self):
        """tool_response can be {content: [{type:text, text:...}]} shape."""
        tmp = tempfile.mkdtemp(prefix="task_content_shape_")
        ws = str(Path(tmp) / "Users" / "wolf" / "audits" / "shapetest")
        payload = {
            "tool_name": "Task",
            "tool_input": {"prompt": f"workspace: {ws} hunt"},
            "tool_response": {
                "content": [
                    {"type": "text", "text": GOOD_REPORT},
                ]
            },
        }
        proc, log_dir = _run_hook(payload, workspace_override=ws)
        self.assertEqual(proc.returncode, 0)
        rows = _read_verdict_rows(log_dir)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
