#!/usr/bin/env python3
"""Tests for tools/poc-execution-record.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "poc-execution-record.py"


class PocExecutionRecordTest(unittest.TestCase):
    def test_records_run_output_and_graph_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "semantic_graph.json").write_text('{"ok": true}\n', encoding="utf-8")
            brief = ws / "source_mining" / "run" / "poc_task_briefs" / "001-demo.md"
            brief.parent.mkdir(parents=True)
            brief.write_text("# brief\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--brief",
                    str(brief),
                    "--candidate-id",
                    "demo",
                    "--assigned-model",
                    "claude",
                    "--cwd",
                    str(ws),
                    "--run",
                    "printf exploit-ok",
                    "--impact-assertion",
                    "exploit_impact",
                    "--final-result",
                    "proved",
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema_version"], "auditooor.poc_execution_manifest.v1")
            self.assertEqual(payload["candidate_id"], "demo")
            self.assertEqual(payload["assigned_model"], "claude")
            self.assertEqual(payload["final_result"], "proved")
            self.assertEqual(payload["impact_assertion"], "exploit_impact")
            self.assertTrue(payload["source_graph_sha256"])
            self.assertEqual(payload["commands_attempted"][0]["exit_code"], 0)
            self.assertEqual(
                payload["foundry_version_inventory"]["schema_version"],
                "auditooor.foundry_version_inventory.v1",
            )
            self.assertEqual(
                payload["foundry_version_inventory"]["planned_target"]["foundry_version"],
                "v1.7.1",
            )
            self.assertFalse(payload["foundry_version_inventory"]["planned_target"]["upgrade_performed"])
            stdout_path = Path(payload["commands_attempted"][0]["stdout_path"])
            self.assertEqual(stdout_path.read_text(encoding="utf-8"), "exploit-ok")
            # Item #14: a manifest with at least one real run reaches
            # ``executed_with_manifest``.
            self.assertEqual(payload["evidence_class"], "executed_with_manifest")

    def test_binds_workspace_source_and_harness_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            source = ws / "src" / "agent.oscript"
            harness = ws / "test" / "agent.test.oscript.js"
            source.parent.mkdir()
            harness.parent.mkdir()
            source.write_text("{ messages: {} }\n", encoding="utf-8")
            harness.write_text("describe('agent', () => {});\n", encoding="utf-8")
            brief = ws / "brief.md"
            brief.write_text("# brief\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--brief", str(brief),
                 "--bound-source", str(source), "--bound-source", str(harness), "--print-json"],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = json.loads(proc.stdout)["bound_sources"]
            self.assertEqual([row["path"] for row in rows], ["src/agent.oscript", "test/agent.test.oscript.js"])
            self.assertTrue(all(len(row["sha256"]) == 64 and row["size"] > 0 for row in rows))

    def test_refuses_bound_source_outside_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside_tmp:
            ws = Path(tmp)
            brief = ws / "brief.md"
            brief.write_text("# brief\n", encoding="utf-8")
            outside = Path(outside_tmp) / "outside.oscript"
            outside.write_text("{}\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--brief", str(brief), "--bound-source", str(outside)],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("bound source outside workspace", proc.stderr)

    def test_refuses_proved_without_exploit_impact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            brief = ws / "source_mining" / "run" / "poc_task_briefs" / "001-demo.md"
            brief.parent.mkdir(parents=True)
            brief.write_text("# brief\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--brief",
                    str(brief),
                    "--candidate-id",
                    "demo",
                    "--impact-assertion",
                    "setup_or_branch_only",
                    "--final-result",
                    "proved",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("requires --impact-assertion exploit_impact", proc.stderr + proc.stdout)

    def test_accepts_optional_bridge_and_proof_queue_join_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            graph = ws / ".auditooor" / "detector_action_graphs" / "hit_000_withdraw.json"
            graph.parent.mkdir(parents=True)
            graph.write_text('{"detector_hit":{"detector_slug":"withdraw-reentrancy-no-guard"}}\n', encoding="utf-8")
            brief = ws / "source_mining" / "run" / "poc_task_briefs" / "003-proof.md"
            brief.parent.mkdir(parents=True)
            brief.write_text("# brief\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--brief",
                    str(brief),
                    "--candidate-id",
                    "manual-rerun-001",
                    "--bridge-row-id",
                    "BASE-SC-I07",
                    "--proof-task-id",
                    "POQ-001",
                    "--detector-slug",
                    "withdraw-reentrancy-no-guard",
                    "--detector-obligation",
                    "P-001",
                    "--detector-action-graph",
                    str(graph),
                    "--cwd",
                    str(ws),
                    "--command",
                    "forge test --match-test testWithdrawReentrancy",
                    "--impact-assertion",
                    "exploit_impact",
                    "--final-result",
                    "proved",
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["bridge_row_id"], "BASE-SC-I07")
            self.assertEqual(
                payload["bridge_relationship"],
                "addresses_high_impact_execution_bridge_row",
            )
            self.assertEqual(payload["proof_task_id"], "POQ-001")
            self.assertEqual(payload["detector_slug"], "withdraw-reentrancy-no-guard")
            self.assertEqual(payload["detector_obligation"], "P-001")
            self.assertEqual(
                payload["detector_action_graph"],
                ".auditooor/detector_action_graphs/hit_000_withdraw.json",
            )
            serialized = json.dumps(
                {
                    "bridge_row_id": payload["bridge_row_id"],
                    "proof_task_id": payload["proof_task_id"],
                    "detector_slug": payload["detector_slug"],
                    "detector_obligation": payload["detector_obligation"],
                    "detector_action_graph": payload["detector_action_graph"],
                },
                sort_keys=True,
            )
            self.assertNotIn(str(ws), serialized)
            self.assertNotIn("/private/", serialized)
            self.assertNotIn("/Users/", serialized)


class EvidenceClassDerivationTest(unittest.TestCase):
    """Item #14: a manifest with no commands attempted is at most
    ``scaffolded_unverified``; a manifest with real run output reaches
    ``executed_with_manifest``.
    """

    def test_no_commands_stays_scaffolded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            brief = ws / "source_mining" / "run" / "poc_task_briefs" / "002-empty.md"
            brief.parent.mkdir(parents=True)
            brief.write_text("# brief\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--brief",
                    str(brief),
                    "--candidate-id",
                    "empty",
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["commands_attempted"], [])
            self.assertEqual(payload["evidence_class"], "scaffolded_unverified")


if __name__ == "__main__":
    unittest.main()
