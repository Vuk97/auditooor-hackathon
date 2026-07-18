from __future__ import annotations

import importlib.util
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-capability-adoption.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_capability_adoption", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanCapabilityAdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory(prefix="hackerman-capability-adoption-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_log(self, ws: Path, rows: list[dict]) -> Path:
        path = ws / ".auditooor" / "mcp_call_log.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        return path

    def test_v3_callables_are_tracked_and_counted(self) -> None:
        ws = self.root / "ws"
        self._write_log(
            ws,
            [
                {
                    "ts": "2026-05-19T00:00:00Z",
                    "workspace": str(ws),
                    "callable": "vault_resume_context",
                    "args_hash": "a",
                    "verdict": "ok",
                    "duration_ms": 1,
                    "degraded": False,
                },
                {
                    "ts": "2026-05-19T00:01:00Z",
                    "workspace": str(ws),
                    "callable": "vault_hackerman_novel_vector_context",
                    "args_hash": "b",
                    "verdict": "ok",
                    "duration_ms": 2,
                    "degraded": False,
                },
                {
                    "ts": "2026-05-19T00:02:00Z",
                    "workspace": str(ws),
                    "callable": "vault_exploit_queue_context",
                    "args_hash": "c",
                    "verdict": "ok",
                    "duration_ms": 3,
                    "degraded": False,
                },
                {
                    "ts": "2026-05-19T00:03:00Z",
                    "workspace": str(ws),
                    "callable": "vault_hacker_brief_for_lane_v3",
                    "args_hash": "d",
                    "verdict": "ok",
                    "duration_ms": 4,
                    "degraded": False,
                },
                {
                    "ts": "2026-05-19T00:04:00Z",
                    "workspace": str(ws),
                    "callable": "vault_loop_finalization_check",
                    "args_hash": "e",
                    "verdict": "ok",
                    "duration_ms": 5,
                    "degraded": False,
                },
            ],
        )

        report = self.tool.build_report(workspaces=[str(ws)], iterations=7)

        self.assertGreaterEqual(report["tracked_callable_count"], 35)
        self.assertEqual(report["counts"]["vault_hackerman_novel_vector_context"], 1)
        self.assertEqual(report["counts"]["vault_exploit_queue_context"], 1)
        self.assertEqual(report["counts"]["vault_hacker_brief_for_lane_v3"], 1)
        self.assertEqual(report["counts"]["vault_loop_finalization_check"], 1)
        self.assertIn("vault_hackerman_novel_vector_context", report["observed_tracked_callables"])
        self.assertIn("vault_exploit_queue_context", report["observed_tracked_callables"])
        self.assertIn("vault_hacker_brief_for_lane_v3", report["observed_tracked_callables"])
        self.assertIn("vault_loop_finalization_check", report["observed_tracked_callables"])
        self.assertNotIn("vault_hackerman_novel_vector_context", report["other_counts"])
        self.assertNotIn("vault_exploit_queue_context", report["other_counts"])
        self.assertNotIn("vault_hacker_brief_for_lane_v3", report["other_counts"])
        self.assertNotIn("vault_loop_finalization_check", report["other_counts"])

    def test_untracked_vault_callables_are_reported_separately(self) -> None:
        ws = self.root / "ws"
        self._write_log(
            ws,
            [
                {
                    "ts": "2026-05-19T00:00:00Z",
                    "workspace": str(ws),
                    "callable": "vault_resume_context",
                    "args_hash": "a",
                    "verdict": "ok",
                    "duration_ms": 1,
                    "degraded": False,
                },
                {
                    "ts": "2026-05-19T00:01:00Z",
                    "workspace": str(ws),
                    "callable": "vault_future_callable",
                    "args_hash": "b",
                    "verdict": "ok",
                    "duration_ms": 2,
                    "degraded": False,
                },
            ],
        )

        report = self.tool.build_report(workspaces=[str(ws)], iterations=7)

        self.assertEqual(report["other_counts"]["vault_future_callable"], 1)
        self.assertIn("vault_future_callable", report["untracked_vault_callables"])

    def test_iteration_window_is_per_workspace_not_global(self) -> None:
        ws_a = self.root / "ws-a"
        ws_b = self.root / "ws-b"
        rows_a = []
        for minute in range(10):
            rows_a.append(
                {
                    "ts": f"2026-05-19T10:{minute:02d}:00Z",
                    "workspace": str(ws_a),
                    "callable": "vault_resume_context",
                    "args_hash": f"a{minute}",
                    "verdict": "ok",
                    "duration_ms": 1,
                    "degraded": False,
                }
            )
        self._write_log(ws_a, rows_a)
        self._write_log(
            ws_b,
            [
                {
                    "ts": "2026-05-19T09:00:00Z",
                    "workspace": str(ws_b),
                    "callable": "vault_resume_context",
                    "args_hash": "b0",
                    "verdict": "ok",
                    "duration_ms": 1,
                    "degraded": False,
                },
                {
                    "ts": "2026-05-19T09:01:00Z",
                    "workspace": str(ws_b),
                    "callable": "vault_toolsite_context",
                    "args_hash": "b1",
                    "verdict": "ok",
                    "duration_ms": 1,
                    "degraded": False,
                },
            ],
        )

        report = self.tool.build_report(workspaces=[str(ws_a), str(ws_b)], iterations=3)

        self.assertEqual(report["counts"]["vault_toolsite_context"], 1)
        by_ws = {row["workspace"]: row for row in report["workspace_breakdown"]}
        self.assertEqual(by_ws[str(ws_a)]["rows_in_window"], 3)
        self.assertEqual(by_ws[str(ws_b)]["rows_in_window"], 2)
        self.assertEqual(report["rows_in_window"], 5)

    def test_cli_json_is_parseable(self) -> None:
        ws = self.root / "ws"
        self._write_log(
            ws,
            [
                {
                    "ts": "2026-05-19T00:00:00Z",
                    "workspace": str(ws),
                    "callable": "vault_resume_context",
                    "args_hash": "a",
                    "verdict": "ok",
                    "duration_ms": 1,
                    "degraded": False,
                }
            ],
        )

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.tool.main(["--workspace", str(ws), "--format", "json"])

        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["schema"], "auditooor.hackerman_capability_adoption.v1")
        self.assertEqual(payload["counts"]["vault_resume_context"], 1)


if __name__ == "__main__":
    unittest.main()
