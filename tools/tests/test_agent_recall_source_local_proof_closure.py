#!/usr/bin/env python3
"""Tests for agent recall source/local proof closure."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "agent-recall-source-local-proof-closure.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("agent_recall_source_local_proof_closure", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load_tool()


class AgentRecallSourceLocalProofClosureTests(unittest.TestCase):
    def make_ws(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="agent_recall_source_local_proof_closure_"))
        (ws / ".auditooor").mkdir()
        (ws / ".audit_logs" / "worker").mkdir(parents=True)
        (ws / "agent_outputs").mkdir()
        return ws

    def test_terminalizes_provider_source_and_local_manifest_rows(self):
        ws = self.make_ws()
        provider = ws / ".audit_logs" / "worker" / "provider_result_local_verification.json"
        provider.write_text(
            json.dumps(
                {
                    "rows": [
                        {
                            "task_id": "worker-am-044",
                            "evidence_class": "generated_hypothesis",
                            "local_status": "source_symbol_confirmed",
                            "classifications": ["local_grep_advisory"],
                            "symbols": ["_load_detectors"],
                            "source_paths": ["tools/circom-detect.py"],
                            "source_hits": [{"path": "tools/circom-detect.py", "matched_symbols": ["_load_detectors"]}],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        manifest = ws / "agent_outputs" / "bounded.manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "status": "no-counterexample",
                    "tests_passed": 2,
                    "tests_failed": 0,
                    "engine": "halmos",
                    "harness": "bounded",
                    "mapping_strength": "strong",
                    "workspace_harness_path": "~/audits/demo/test/bounded.sym.t.sol",
                }
            ),
            encoding="utf-8",
        )
        queue = {
            "rows": [
                {
                    "queue_id": "ARDQ-001",
                    "source": "provider_local_verification",
                    "source_id": "worker-am-044",
                    "source_artifact": str(provider),
                    "terminal_state": "source_proof_queue_ready",
                },
                {
                    "queue_id": "ARDQ-002",
                    "source": "agent_recall",
                    "source_id": "local-row",
                    "source_artifact": str(manifest),
                    "terminal_state": "local_proof_required",
                },
            ]
        }
        proof = {
            "remaining_open_tasks": [
                {
                    "task_id": "ARDT-001",
                    "queue_id": "ARDQ-001",
                    "source": "provider_local_verification",
                    "source_id": "worker-am-044",
                    "task_type": "source_proof_task",
                },
                {
                    "task_id": "ARDT-002",
                    "queue_id": "ARDQ-002",
                    "source": "agent_recall",
                    "source_id": "local-row",
                    "task_type": "local_proof_task",
                },
            ]
        }
        (ws / ".auditooor" / "agent_recall_detector_queue_full_corpus.json").write_text(json.dumps(queue), encoding="utf-8")
        (ws / ".auditooor" / "agent_recall_full_corpus_proof.json").write_text(json.dumps(proof), encoding="utf-8")

        payload = tool.build_closure(ws)

        self.assertEqual(payload["rows_evaluated"], 2)
        self.assertEqual(payload["closed_for_recall_count"], 2)
        decisions = {row["decision"] for row in payload["rows"]}
        self.assertIn("terminal_internal_tool_or_generated_hypothesis", decisions)
        self.assertIn("local_proof_recorded_no_counterexample", decisions)
        local = next(row for row in payload["rows"] if row["task_type_before"] == "local_proof_task")
        self.assertEqual(local["terminal_state"], "local_proof_recorded_terminal")
        self.assertEqual(local["tests_passed"], 2)
        self.assertEqual(local["tests_failed"], 0)


if __name__ == "__main__":
    unittest.main()
