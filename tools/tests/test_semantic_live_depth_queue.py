from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BLOCKERS_TOOL = ROOT / "tools" / "semantic-live-depth-blockers.py"
QUEUE_TOOL = ROOT / "tools" / "semantic-live-depth-queue.py"


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


def _write_graph(audit_dir: Path, count: int = 1) -> None:
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


def _write_live_topology(ws: Path, *, authority_block: str = "123", count: int = 1) -> None:
    results = []
    pairs = []
    for idx in range(count):
        results.extend(
            [
                {
                    "id": f"edge-{idx}",
                    "status": "pass",
                    "contract": f"Portal{idx}",
                    "evidence_class": "topology-relation",
                    "block": "123",
                    "proof_pair_id": f"pair-{idx}",
                },
                {
                    "id": f"authority-{idx}",
                    "status": "pass",
                    "contract": f"Bridge{idx}",
                    "evidence_class": "topology-relation",
                    "block": authority_block,
                    "proof_pair_id": f"pair-{idx}",
                },
            ]
        )
        pair_blocks = sorted({"123", authority_block})
        pairs.append(
            {
                "id": f"pair-{idx}",
                "status": "proved" if len(pair_blocks) == 1 else "conflicting",
                "row_ids": [f"edge-{idx}", f"authority-{idx}"],
                "shared_block": "123" if len(pair_blocks) == 1 else None,
                "pair_blocks": pair_blocks,
            }
        )
    (ws / "live_topology_checks.json").write_text(
        json.dumps({"results": results, "proof_pairs": pairs}),
        encoding="utf-8",
    )


def _rewrite_first_authority_evidence_class(ws: Path, evidence_class: str) -> None:
    payload = json.loads((ws / "live_topology_checks.json").read_text(encoding="utf-8"))
    for row in payload["results"]:
        if row["id"] == "authority-0":
            row["evidence_class"] = evidence_class
    (ws / "live_topology_checks.json").write_text(json.dumps(payload), encoding="utf-8")


class SemanticLiveDepthQueueTest(unittest.TestCase):
    def test_exact_same_block_pair_closes_depth_accounting_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_graph(audit_dir)
            _write_live_topology(ws)

            _run(sys.executable, BLOCKERS_TOOL, "--workspace", ws)
            _run(sys.executable, QUEUE_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_live_depth_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.semantic_live_depth_queue.v1")
            self.assertEqual(payload["processed_count"], 1)
            self.assertEqual(payload["depth_closed_count"], 1)
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(payload["evidence_class"], "generated_hypothesis")
            self.assertFalse(payload["promotion_allowed"])
            row = payload["rows"][0]
            self.assertEqual(row["status"], "semantic_live_depth_closed_by_same_block_pair")
            self.assertTrue(row["depth_closure_allowed"])
            self.assertEqual(row["exact_pair_ids"], ["pair-0"])
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(row["evidence_class"], "generated_hypothesis")
            self.assertFalse(row["promotion_allowed"])
            self.assertEqual(row["severity"], "none")

    def test_cross_block_pair_remains_queued_and_not_submit_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_graph(audit_dir)
            _write_live_topology(ws, authority_block="124")

            _run(sys.executable, BLOCKERS_TOOL, "--workspace", ws)
            _run(sys.executable, QUEUE_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_live_depth_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["depth_closed_count"], 0)
            self.assertEqual(payload["blocking_count"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["status"], "queued_missing_exact_same_block_pair")
            self.assertFalse(row["depth_closure_allowed"])
            self.assertIn("missing exact proved same-block live proof pair for semantic route", row["blockers"])
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(row["promotion_allowed"])

    def test_non_topology_pair_does_not_close_depth_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_graph(audit_dir)
            _write_live_topology(ws)
            _rewrite_first_authority_evidence_class(ws, "balance-proof")

            _run(sys.executable, BLOCKERS_TOOL, "--workspace", ws)
            _run(sys.executable, QUEUE_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_live_depth_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["depth_closed_count"], 0)
            row = payload["rows"][0]
            self.assertFalse(row["depth_closure_allowed"])
            self.assertIn("proof pair rows are not all topology-relation evidence", row["blockers"])

    def test_default_limit_keeps_four_hundred_concrete_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_graph(audit_dir, count=420)
            _write_live_topology(ws, count=420)

            _run(sys.executable, BLOCKERS_TOOL, "--workspace", ws)
            _run(sys.executable, QUEUE_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "semantic_live_depth_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["limit"], 400)
            self.assertEqual(payload["processed_count"], 400)
            self.assertEqual(payload["depth_closed_count"], 400)
            self.assertTrue(all(row["queue_id"].startswith("SLD-") for row in payload["rows"]))


if __name__ == "__main__":
    unittest.main()
