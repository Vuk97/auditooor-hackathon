from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "semantic-live-depth-blockers.py"


def _run(*args: Path | str) -> None:
    proc = subprocess.run(
        [str(arg) for arg in args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr or proc.stdout)


def _write_graph(audit_dir: Path, count: int = 3) -> None:
    relation_edges = []
    for idx in range(count):
        relation_edges.append(
            {
                "source_contract": f"Portal{idx}",
                "source_function": "finalizeWithdrawal",
                "kind": "bridge-finalizer-call",
                "target": f"Bridge{idx}",
                "target_type": f"Bridge{idx}",
                "method": "finalizeWithdrawal",
                "file": f"src/Portal{idx}.sol",
                "line": idx + 10,
            }
        )
    (audit_dir / "semantic_graph.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.semantic_graph.v1",
                "entrypoints": [],
                "relation_edges": relation_edges,
                "multi_hop_paths": [],
            }
        ),
        encoding="utf-8",
    )


class SemanticLiveDepthBlockersTest(unittest.TestCase):
    def test_missing_live_pairs_become_strict_named_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_graph(audit_dir)

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_live_depth_blockers.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.semantic_live_depth_blockers.v1")
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(payload["evidence_class"], "generated_hypothesis")
            self.assertFalse(payload["promotion_allowed"])
            self.assertEqual(payload["severity"], "none")
            self.assertGreaterEqual(payload["blocker_counts"]["semantic-cross-contract-proof"], 1)
            self.assertGreaterEqual(payload["blocker_counts"]["semantic-live-proof-pairs"], 1)
            self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in payload["items"]))
            self.assertTrue(all(row["evidence_class"] == "generated_hypothesis" for row in payload["items"]))
            self.assertTrue(any("live-checks" in row["next_command"] for row in payload["items"]))
            md = (audit_dir / "semantic_live_depth_blockers.md").read_text(encoding="utf-8")
            self.assertIn("Semantic/Live Depth Blockers", md)
            self.assertIn("semantic-live-proof-pairs", md)

    def test_same_block_live_pair_is_accounted_without_submit_ready_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_graph(audit_dir, count=1)
            (ws / "live_topology_checks.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "id": "edge",
                                "status": "pass",
                                "contract": "Portal0",
                                "evidence_class": "topology-relation",
                                "block": "123",
                            },
                            {
                                "id": "authority",
                                "status": "pass",
                                "contract": "Bridge0",
                                "evidence_class": "topology-relation",
                                "block": "123",
                            },
                        ],
                        "proof_pairs": [
                            {
                                "id": "pair-portal-bridge",
                                "status": "proved",
                                "row_ids": ["edge", "authority"],
                                "shared_block": "123",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_live_depth_blockers.json").read_text(encoding="utf-8"))
            row = payload["items"][0]
            self.assertTrue(row["live_evidence"]["has_executed_same_block_pair"])
            self.assertIn("pair-portal-bridge", row["live_evidence"]["proved_pair_ids"])
            self.assertNotIn("semantic-live-proof-pairs", row["blocker_ids"])
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(row["promotion_allowed"])

    def test_default_limit_keeps_four_hundred_concrete_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_graph(audit_dir, count=420)

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_live_depth_blockers.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["limit"], 400)
            self.assertEqual(payload["item_count"], 400)
            self.assertTrue(payload["truncated"])
            self.assertTrue(all(row["item_id"].startswith("SLD-") for row in payload["items"]))

    def test_missing_repo_graph_uses_scoped_sidecar_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            relation_edges = []
            for idx in range(420):
                relation_edges.append(
                    {
                        "source_contract": f"Portal{idx}",
                        "source_function": "finalizeWithdrawal",
                        "kind": "bridge-finalizer-call",
                        "target": f"Bridge{idx}",
                        "target_type": f"Bridge{idx}",
                        "method": "finalizeWithdrawal",
                        "file": f"src/Portal{idx}.sol",
                        "line": idx + 10,
                    }
                )
            (audit_dir / "callgraph_de_semantic_graph_fixtures.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.semantic_graph.v1",
                        "workspace": str(ws),
                        "contracts": [],
                        "entrypoints": [],
                        "relation_edges": relation_edges,
                        "multi_hop_paths": [],
                    }
                ),
                encoding="utf-8",
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_live_depth_blockers.json").read_text(encoding="utf-8"))
            scoped = json.loads((audit_dir / "semantic_graph.scoped.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["source_semantic_graph_mode"], "generated_scoped_graph")
            self.assertEqual(payload["item_count"], 400)
            self.assertEqual(scoped["selection_mode"], "scoped_semantic_live_depth")
            self.assertEqual(scoped["selection_metadata"]["target_range"], "300-500")
            self.assertEqual(scoped["selection_metadata"]["selected_semantic_item_count"], 420)


if __name__ == "__main__":
    unittest.main()
