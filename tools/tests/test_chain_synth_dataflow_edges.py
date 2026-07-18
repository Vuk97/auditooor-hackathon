# <!-- r36-rebuttal: lane df-wire registered via agent-pathspec-register.py -->
"""Guard: chain-synth-driver additive dataflow_edges source (df-wire).

- collect_dataflow_edges([]) when slice absent -> [] (no shape change).
- collect_dataflow_edges projects non-degraded DefUsePaths into source_backed edges
  with real source/sink anchors + engine provenance; degraded records are skipped.
- The _terminal_observability block only carries dataflow_edges when the slice exists.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "chain-synth-driver.py"


def _load():
    spec = importlib.util.spec_from_file_location("chain_synth_driver_dftest", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def _rec(path_id, degraded=False):
    return {
        "schema": "dataflow_path.v1", "path_id": path_id, "language": "solidity",
        "direction": "forward", "engine": "evm-ssa" if not degraded else "unsupported-or-compile-fail-degrade",
        "source": {"kind": "param", "fn": "entry", "var": "amt", "file": "a.sol", "line": 10},
        "sink": {"kind": "call", "callee": "transfer", "arg_pos": 1, "fn": "_move", "file": "a.sol", "line": 22},
        "hops": [{"from_var": "amt", "to_var": "v", "fn": "entry", "via": "internal_call",
                  "file": "a.sol", "line": 11, "ir": "", "guarded": False}],
        "call_depth": 1, "unguarded": True, "guard_nodes": [],
        "source_unit_ids": ["u1"], "sink_unit_ids": ["u2"],
        "confidence": "semantic-ssa", "degraded": degraded,
    }


class DataflowEdgesTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)

    def _write(self, recs):
        (self.ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")

    def test_absent_slice_returns_empty(self):
        self.assertEqual(self.m.collect_dataflow_edges(self.ws), [])

    def test_projects_real_anchors_and_provenance(self):
        self._write([_rec("p1")])
        edges = self.m.collect_dataflow_edges(self.ws)
        self.assertEqual(len(edges), 1)
        e = edges[0]
        self.assertEqual(e["edge_kind"], "dataflow")
        self.assertEqual(e["path_id"], "p1")
        self.assertEqual(e["provenance"], "dataflow-slice.v1")
        self.assertEqual(e["confidence"], "semantic-ssa")
        self.assertEqual(e["source"]["file_line"], "a.sol:10")
        self.assertEqual(e["sink"]["file_line"], "a.sol:22")
        self.assertIn("a.sol:10", e["real_evidence"])
        self.assertIn("a.sol:22", e["real_evidence"])

    def test_degraded_records_skipped(self):
        self._write([_rec("good"), _rec("bad", degraded=True)])
        edges = self.m.collect_dataflow_edges(self.ws)
        self.assertEqual([e["path_id"] for e in edges], ["good"])

    def test_terminal_observability_omits_block_when_absent(self):
        block = self.m._terminal_observability(
            workspace=self.ws, input_fingerprints={}, current_queue_lead_ids=set(),
            current_queue_lead_invariant_ids={}, all_source_link_entries=[],
            source_link_entries=[], rejected_source_link_entries=0,
            source_link_artifacts=[], broken_ids=[], max_chains=10,
            require_hop_evidence=False, dry_run=True, template_match_status="x")
        self.assertNotIn("dataflow_edges", block)
        self.assertNotIn("dataflow_edges", block["input_counts"])

    def test_terminal_observability_adds_block_when_present(self):
        self._write([_rec("p1")])
        block = self.m._terminal_observability(
            workspace=self.ws, input_fingerprints={}, current_queue_lead_ids=set(),
            current_queue_lead_invariant_ids={}, all_source_link_entries=[],
            source_link_entries=[], rejected_source_link_entries=0,
            source_link_artifacts=[], broken_ids=[], max_chains=10,
            require_hop_evidence=False, dry_run=True, template_match_status="x")
        self.assertIn("dataflow_edges", block)
        self.assertEqual(len(block["dataflow_edges"]), 1)
        self.assertEqual(block["input_counts"]["dataflow_edges"], 1)


if __name__ == "__main__":
    unittest.main()
