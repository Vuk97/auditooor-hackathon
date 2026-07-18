"""Tests for agent-artifact-mine-all.py."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "agent-artifact-mine-all.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("agent_artifact_mine_all", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_artifact_mine_all"] = module
    spec.loader.exec_module(module)
    return module


class FakeMiner:
    def mine_workspace(self, workspace: Path) -> dict:
        return {
            "schema_version": "auditooor.agent_artifact_mining.v2",
            "workspace": str(workspace),
            "generated_at": "2026-05-21T00:00:00+00:00",
            "total_artifacts": 1,
            "no_learning_reason": False,
            "artifact_type_counts": {"known_limitation": 1},
            "artifacts": [
                {
                    "artifact_id": "aam-test",
                    "artifact_type": "known_limitation",
                    "title": "test lesson",
                    "content": "lesson",
                    "provenance_ref": "agent_outputs/round1/REPORT.md",
                }
            ],
        }


class ExplodingMiner:
    def mine_workspace(self, workspace: Path) -> dict:
        raise RuntimeError(f"boom: {workspace.name}")


class AgentArtifactMineAllTests(unittest.TestCase):
    def test_discovers_workspace_inputs_and_writes_report_plus_state(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "nuva"
            report = ws / "agent_outputs" / "round1" / "REPORT.md"
            report.parent.mkdir(parents=True)
            report.write_text("VERDICT: NEGATIVE\nKILL: not reachable from production path\n", encoding="utf-8")

            row = tool.mine_one(ws, root, FakeMiner(), generated_at="2026-05-21T00:00:00+00:00")

            self.assertEqual(row["status"], "mined")
            self.assertTrue(row["fresh_inventory"])
            self.assertIn("agent_outputs", row["artifact_input_evidence"])
            report_path = ws / "agent_artifact_mining_report.json"
            state_path = ws / ".auditooor" / "agent_artifacts" / "state.json"
            self.assertTrue(report_path.is_file())
            self.assertTrue(state_path.is_file())
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["schema"], "auditooor.agent_artifact_mining_state.v1")
            self.assertEqual(state["schema_version"], "auditooor.agent_artifact_mining_state.v1")
            self.assertEqual(state["status"], "mined")
            self.assertEqual(state["total_artifacts"], 1)
            self.assertEqual(state["report_sha256"], row["report_sha256"])
            self.assertTrue(state["input_summary"]["has_artifact_inputs"])
            self.assertEqual(state["input_summary"]["input_file_count"], 1)
            self.assertEqual(state["input_summary"]["latest_input_path"], "agent_outputs/round1/REPORT.md")

    def test_workspace_without_inputs_gets_typed_skip_reason(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "empty"
            ws.mkdir()

            row = tool.mine_one(ws, root, FakeMiner(), generated_at="2026-05-21T00:00:00+00:00")

            self.assertEqual(row["status"], "skipped")
            self.assertEqual(row["skip_reason"], "NO_ARTIFACT_INPUTS")
            self.assertFalse(row["fresh_inventory"])
            state = json.loads((ws / ".auditooor" / "agent_artifacts" / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["skip_reason"], "NO_ARTIFACT_INPUTS")

    def test_build_payload_counts_statuses(self) -> None:
        tool = load_tool()
        rows = [
            {"status": "mined"},
            {"status": "skipped"},
            {"status": "error"},
        ]
        payload = tool.build_payload(Path("/tmp/audits"), rows, "2026-05-21T00:00:00+00:00")
        self.assertEqual(payload["schema"], "auditooor.agent_artifact_mine_all.v1")
        self.assertEqual(payload["workspace_count"], 3)
        self.assertEqual(payload["mined_count"], 1)
        self.assertEqual(payload["skipped_count"], 1)
        self.assertEqual(payload["error_count"], 1)

    def test_error_state_is_written_and_reported(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "broken"
            out = ws / "agent_outputs" / "round1" / "REPORT.md"
            out.parent.mkdir(parents=True)
            out.write_text("VERDICT: NEGATIVE\nKILL: malformed fixture\n", encoding="utf-8")

            row = tool.mine_one(ws, root, ExplodingMiner(), generated_at="2026-05-21T00:00:00+00:00")

            self.assertEqual(row["status"], "error")
            self.assertEqual(row["skip_reason"], "MINER_EXCEPTION")
            self.assertIn("boom: broken", row["error"])
            state = json.loads((ws / ".auditooor" / "agent_artifacts" / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["status"], "error")

    def test_cli_writes_aggregate_and_dry_run_skips_writes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audits_root = root / "audits"
            ws = audits_root / "ws"
            report = ws / "agent_outputs" / "round1" / "REPORT.md"
            report.parent.mkdir(parents=True)
            report.write_text("VERDICT: NEGATIVE\nKILL: no attacker control\n", encoding="utf-8")
            out = root / "aggregate.json"

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = tool.main(["--audits-root", str(audits_root), "--out", str(out), "--json"])

            self.assertEqual(rc, 0)
            emitted = json.loads(buf.getvalue())
            self.assertEqual(emitted["workspace_count"], 1)
            self.assertTrue(out.is_file())
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["workspace_count"], 1)
            self.assertTrue((ws / "agent_artifact_mining_report.json").is_file())
            self.assertTrue((ws / ".auditooor" / "agent_artifacts" / "state.json").is_file())

            dry_ws = audits_root / "dry"
            dry_report = dry_ws / "agent_outputs" / "round1" / "REPORT.md"
            dry_report.parent.mkdir(parents=True)
            dry_report.write_text("VERDICT: NEGATIVE\nKILL: no production reachability\n", encoding="utf-8")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = tool.main(["--workspace", str(dry_ws), "--dry-run", "--json"])

            self.assertEqual(rc, 0)
            emitted = json.loads(buf.getvalue())
            self.assertEqual(emitted["rows"][0]["status"], "mined")
            self.assertFalse((dry_ws / "agent_artifact_mining_report.json").exists())
            self.assertFalse((dry_ws / ".auditooor" / "agent_artifacts" / "state.json").exists())

    def test_discover_workspaces_uses_direct_children_or_explicit_list(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "--help").mkdir()
            (root / ".hidden").mkdir()
            (root / "file.txt").write_text("x", encoding="utf-8")

            discovered = [path.name for path in tool.discover_workspaces(root)]
            self.assertEqual(discovered, ["a", "b"])
            explicit = tool.discover_workspaces(root, [root / "b"])
            self.assertEqual([path.name for path in explicit], ["b"])


if __name__ == "__main__":
    unittest.main()
