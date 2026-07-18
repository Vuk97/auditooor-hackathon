from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BLOCKERS_TOOL = ROOT / "tools" / "semantic-live-depth-blockers.py"
REQ_TOOL = ROOT / "tools" / "live-topology-proof-requirements.py"


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


def _write_graph(audit_dir: Path, count: int = 420) -> None:
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


class LiveTopologyProofRequirementsTest(unittest.TestCase):
    def test_missing_live_topology_gets_four_hundred_offline_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_graph(audit_dir)

            _run(sys.executable, BLOCKERS_TOOL, "--workspace", ws)
            _run(sys.executable, REQ_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_requirements.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.live_topology_proof_requirements.v1")
            self.assertEqual(payload["limit"], 400)
            self.assertEqual(payload["requirement_count"], 400)
            self.assertFalse(payload["truncated"])
            self.assertEqual(payload["source_item_count"], 400)
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(payload["promotion_allowed"])
            first = payload["requirements"][0]
            self.assertEqual(first["requirement_id"], "LTPR-001")
            self.assertEqual(first["required_evidence_class"], "topology-relation")
            self.assertTrue(first["same_block_required"])
            self.assertEqual(len(first["required_live_rows"]), 2)
            self.assertEqual(
                first["live_topology_pair_skeleton"]["status"],
                "required_not_collected",
            )
            md = (audit_dir / "live_topology_proof_requirements.md").read_text(encoding="utf-8")
            self.assertIn("Live Topology Proof Requirements", md)
            self.assertIn("LTPR-001", md)


if __name__ == "__main__":
    unittest.main()
