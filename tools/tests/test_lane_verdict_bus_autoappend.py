#!/usr/bin/env python3
"""Tests for lane verdict bus PostToolUse hooks."""

from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
AUTOAPPEND = REPO / "tools" / "hooks" / "lane-verdict-bus-autoappend.sh"
AGGREGATE = REPO / "tools" / "hooks" / "session-end-aggregate-verdict-bus.sh"
BUS = REPO / "tools" / "lane-verdict-bus.py"


def _run_autoappend(payload: dict | str, ws: Path, bus_tool: Path = BUS) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AUDITOOOR_LANE_VERDICT_BUS_TOOL"] = str(bus_tool)
    env["CLAUDE_PROJECT_DIR"] = str(ws)
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(
        ["bash", str(AUTOAPPEND)],
        input=body,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ws),
        check=False,
    )


def _task_payload(ws: Path, lane_id: str = "LANE-M1-3", candidate_id: str = "CAND-1", reply: str = "VERDICT: DROP") -> dict:
    return {
        "tool_name": "Task",
        "tool_input": {
            "prompt": f"workspace: {ws}\nlane_id: {lane_id}\ncandidate_id: {candidate_id}",
            "workspace_path": str(ws),
        },
        "tool_response": reply,
    }


def _read_rows(ws: Path, lane_id: str) -> list[dict]:
    path = ws / ".auditooor" / "lane_verdict_bus" / f"{lane_id}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class LaneVerdictBusAutoappendTests(unittest.TestCase):
    def test_bash_syntax_valid(self) -> None:
        for script in (AUTOAPPEND, AGGREGATE):
            proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, f"{script}: {proc.stderr}")

    def test_reply_with_verdict_appends_one_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lane_bus_hook_") as td:
            root = Path(td)
            ws = root / "workspace"
            ws.mkdir()
            reply = "MCP context ok\nVERDICT: DROPPED-detector-false-positive\nfiles changed: none\n"
            proc = _run_autoappend(_task_payload(ws, reply=reply), ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = _read_rows(ws, "LANE-M1-3")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["candidate_id"], "CAND-1")
            self.assertEqual(rows[0]["verdict"], "DROPPED_DETECTOR_FALSE_POSITIVE")
            self.assertEqual(rows[0]["metadata"]["source"], "posttooluse:Task")
            self.assertIn("verdict_hash", rows[0]["metadata"])
            self.assertIn("reply_sha256", rows[0]["metadata"])

    def test_agent_reply_content_array_is_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lane_bus_hook_") as td:
            root = Path(td)
            ws = root / "workspace"
            ws.mkdir()
            payload = _task_payload(ws, lane_id="LANE-AGENT", candidate_id="AGENT-1")
            payload["tool_name"] = "Agent"
            payload["tool_response"] = {
                "content": [
                    {"type": "text", "text": "notes\n"},
                    {"type": "text", "text": "VERDICT: LANDED\n"},
                ]
            }
            proc = _run_autoappend(payload, ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = _read_rows(ws, "LANE-AGENT")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["metadata"]["source"], "posttooluse:Agent")
            self.assertEqual(rows[0]["verdict"], "LANDED")

    def test_reply_without_verdict_warns_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lane_bus_hook_") as td:
            root = Path(td)
            ws = root / "workspace"
            ws.mkdir()
            proc = _run_autoappend(_task_payload(ws, reply="No terminal line yet."), ws)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("lane-verdict-bus-missing-verdict", proc.stderr)
            self.assertEqual(_read_rows(ws, "LANE-M1-3"), [])

    def test_idempotent_double_fire_by_lane_candidate_and_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lane_bus_hook_") as td:
            root = Path(td)
            ws = root / "workspace"
            ws.mkdir()
            payload = _task_payload(ws, reply="VERDICT: HOLD - needs source proof\n")
            first = _run_autoappend(payload, ws)
            second = _run_autoappend(payload, ws)
            self.assertEqual(first.returncode, 0)
            self.assertEqual(second.returncode, 0)
            rows = _read_rows(ws, "LANE-M1-3")
            self.assertEqual(len(rows), 1)
            self.assertIn("duplicate", second.stderr)

    def test_parallel_sibling_lanes_write_separate_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lane_bus_hook_") as td:
            root = Path(td)
            ws = root / "workspace"
            ws.mkdir()
            payloads = [
                _task_payload(ws, lane_id="LANE-A", candidate_id="A-1", reply="VERDICT: DROP\n"),
                _task_payload(ws, lane_id="LANE-B", candidate_id="B-1", reply="VERDICT: PROMOTE\n"),
            ]
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda payload: _run_autoappend(payload, ws), payloads))
            self.assertTrue(all(proc.returncode == 0 for proc in results))
            self.assertEqual(len(_read_rows(ws, "LANE-A")), 1)
            self.assertEqual(len(_read_rows(ws, "LANE-B")), 1)

    def test_malformed_payload_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lane_bus_hook_") as td:
            root = Path(td)
            ws = root / "workspace"
            ws.mkdir()
            proc = _run_autoappend("not json", ws)
            self.assertEqual(proc.returncode, 0)
            bus_dir = ws / ".auditooor" / "lane_verdict_bus"
            self.assertFalse(bus_dir.exists())

    def test_session_end_aggregate_invokes_bus_tool(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lane_bus_hook_") as td:
            root = Path(td)
            ws = root / "workspace"
            ws.mkdir()
            for payload in (
                _task_payload(ws, lane_id="LANE-A", candidate_id="A-1", reply="VERDICT: DROP\n"),
                _task_payload(ws, lane_id="LANE-B", candidate_id="B-1", reply="VERDICT: PROMOTE\n"),
            ):
                proc = _run_autoappend(payload, ws)
                self.assertEqual(proc.returncode, 0, proc.stderr)
            env = os.environ.copy()
            env["AUDITOOOR_LANE_VERDICT_BUS_TOOL"] = str(BUS)
            env["CLAUDE_PROJECT_DIR"] = str(ws)
            proc = subprocess.run(
                ["bash", str(AGGREGATE)],
                capture_output=True,
                text=True,
                env=env,
                cwd=str(ws),
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            aggregate = ws / ".auditooor" / "lane_verdict_bus" / "aggregated.json"
            data = json.loads(aggregate.read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], "auditooor.lane_verdict_bus.aggregate.v1")
            self.assertEqual(data["record_count"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
