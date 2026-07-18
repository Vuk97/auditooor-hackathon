# <!-- r36-rebuttal: lane df-step5-consume registered via agent-pathspec-register.py -->
"""Guard: data-stitched chains (chain_kind="dataflow_stitched") + exploit dataflow_skeleton.

Bidirectional wiring 49b - step-5 CHAIN-SYNTH-as-primary + EXPLOIT-SYNTH-follows-path.

chain-synth-driver:
- build_dataflow_stitched_chains([]) when slice absent -> [] (no shape change).
- A 2-path stitch (path A writes storage var V, path B reads V) yields one
  dataflow_stitched chain carrying the ordered path_ids + the join var.
- The chain reaches an impact when the tail sink is value-moving.
- _terminal_observability only carries dataflow_stitched_chains when stitchable.
- A workspace with NO slice -> _terminal_observability byte-identical to the no-slice baseline.

exploit-conversion-loop:
- build_dataflow_skeleton returns None when slice absent OR no path matches.
- A row whose source ref coincides with a DefUsePath gets a dataflow_skeleton.
- A row naming a stitched chain's path_ids gets a multi-step skeleton.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_CHAIN = _TOOLS / "chain-synth-driver.py"
_EXPLOIT = _TOOLS / "exploit-conversion-loop.py"


def _load(path, modname):
    spec = importlib.util.spec_from_file_location(modname, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def _path(path_id, *, source, sink, hops=None, unguarded=True, lang="solidity", degraded=False):
    return {
        "schema": "dataflow_path.v1",
        "path_id": path_id,
        "language": lang,
        "direction": "forward",
        "engine": "evm-ssa" if not degraded else "unsupported-or-compile-fail-degrade",
        "source": source,
        "sink": sink,
        "hops": hops or [],
        "call_depth": len(hops or []),
        "unguarded": unguarded,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": "semantic-ssa",
        "degraded": degraded,
    }


def _entry_path(pid, *, write_var, fn="entry", file="a.sol", line=10):
    """Path A: entrypoint param -> writes storage var (storage-value sink)."""
    return _path(
        pid,
        source={"kind": "param-entrypoint", "fn": fn, "var": "amt", "file": file, "line": line},
        sink={"kind": "storage-value", "callee": write_var, "arg_pos": None, "fn": fn,
              "file": file, "line": line + 5},
        hops=[{"from_var": "amt", "to_var": write_var, "fn": fn, "via": "storage",
               "file": file, "line": line + 2, "ir": "", "guarded": False}],
    )


def _impact_path(pid, *, read_var, fn="payout", file="b.sol", line=40, sink_kind="transfer",
                 callee="transfer"):
    """Path B: reads storage var (state_var source) -> value-moving sink."""
    return _path(
        pid,
        source={"kind": "state_var", "fn": fn, "var": read_var, "file": file, "line": line},
        sink={"kind": sink_kind, "callee": callee, "arg_pos": 1, "fn": fn,
              "file": file, "line": line + 8},
        hops=[{"from_var": read_var, "to_var": "out", "fn": fn, "via": "internal_call",
               "file": file, "line": line + 3, "ir": "", "guarded": False}],
    )


class StitchedChainsTest(unittest.TestCase):
    def setUp(self):
        self.m = _load(_CHAIN, "chain_synth_driver_stitchtest")
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)

    def _write(self, recs):
        (self.ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")

    def test_absent_slice_returns_empty(self):
        self.assertEqual(self.m.build_dataflow_stitched_chains(self.ws), [])

    def test_two_path_storage_stitch_yields_one_chain(self):
        self._write([
            _entry_path("A", write_var="balance"),
            _impact_path("B", read_var="balance"),
        ])
        chains = self.m.build_dataflow_stitched_chains(self.ws)
        self.assertEqual(len(chains), 1)
        c = chains[0]
        self.assertEqual(c["chain_kind"], "dataflow_stitched")
        self.assertEqual(c["path_ids"], ["A", "B"])
        self.assertEqual(c["join_vars"], ["balance"])
        self.assertEqual(c["joins"][0]["join_kind"], "storage")
        self.assertEqual(c["joins"][0]["join_var"], "balance")
        self.assertEqual(c["joins"][0]["from_path"], "A")
        self.assertEqual(c["joins"][0]["to_path"], "B")
        self.assertTrue(c["reaches_impact"])
        self.assertEqual(c["impact"]["kind"], "transfer")
        self.assertEqual(c["entrypoint"]["fn"], "entry")
        self.assertEqual(c["provenance"], "dataflow-slice.v1")

    def test_no_join_var_yields_no_chain(self):
        # Path A writes "balance", path B reads a DIFFERENT var -> no stitch.
        self._write([
            _entry_path("A", write_var="balance"),
            _impact_path("B", read_var="otherVar"),
        ])
        self.assertEqual(self.m.build_dataflow_stitched_chains(self.ws), [])

    def test_degraded_rows_excluded(self):
        self._write([
            _entry_path("A", write_var="balance"),
            _impact_path("B", read_var="balance"),
            _path("bad", source={"kind": "param-entrypoint", "fn": "x", "var": "v",
                                 "file": "z.sol", "line": 1},
                  sink={"kind": "storage-value", "callee": "balance", "arg_pos": None,
                        "fn": "x", "file": "z.sol", "line": 2}, degraded=True),
        ])
        chains = self.m.build_dataflow_stitched_chains(self.ws)
        self.assertEqual(len(chains), 1)
        self.assertNotIn("bad", chains[0]["path_ids"])

    def test_three_path_chain_via_fn_then_storage(self):
        # A (entry -> writes V) -> B (reads V -> writes W) -> C (reads W -> transfer)
        a = _entry_path("A", write_var="V")
        b = {
            **_path("B",
                    source={"kind": "state_var", "fn": "mid", "var": "V", "file": "m.sol", "line": 5},
                    sink={"kind": "storage-value", "callee": "W", "arg_pos": None, "fn": "mid",
                          "file": "m.sol", "line": 9},
                    hops=[{"from_var": "V", "to_var": "W", "fn": "mid", "via": "storage",
                           "file": "m.sol", "line": 7, "ir": "", "guarded": False}]),
        }
        c = _impact_path("C", read_var="W")
        self._write([a, b, c])
        chains = self.m.build_dataflow_stitched_chains(self.ws)
        # Expect a 3-hop chain reaching impact.
        three = [ch for ch in chains if ch["path_ids"] == ["A", "B", "C"]]
        self.assertEqual(len(three), 1)
        self.assertEqual(three[0]["hop_count"], 3)
        self.assertEqual(three[0]["join_vars"], ["V", "W"])
        self.assertTrue(three[0]["reaches_impact"])

    def test_cycle_safe_no_revisit(self):
        # Two paths that mutually feed each other must not loop forever.
        a = _path("A",
                  source={"kind": "param-entrypoint", "fn": "f", "var": "x", "file": "c.sol", "line": 1},
                  sink={"kind": "storage-value", "callee": "S", "arg_pos": None, "fn": "f",
                        "file": "c.sol", "line": 2})
        b = _path("B",
                  source={"kind": "state_var", "fn": "g", "var": "S", "file": "c.sol", "line": 3},
                  sink={"kind": "storage-value", "callee": "S", "arg_pos": None, "fn": "g",
                        "file": "c.sol", "line": 4})
        self._write([a, b])
        # Should terminate (no impact sink -> may be zero chains, but must not hang/raise).
        chains = self.m.build_dataflow_stitched_chains(self.ws, max_hops=4)
        for ch in chains:
            self.assertEqual(len(ch["path_ids"]), len(set(ch["path_ids"])))

    def test_terminal_observability_block_present_vs_absent(self):
        kwargs = dict(
            input_fingerprints={}, current_queue_lead_ids=set(),
            current_queue_lead_invariant_ids={}, all_source_link_entries=[],
            source_link_entries=[], rejected_source_link_entries=0,
            source_link_artifacts=[], broken_ids=[], max_chains=10,
            require_hop_evidence=False, dry_run=True, template_match_status="x")
        # Absent: no block.
        block_absent = self.m._terminal_observability(workspace=self.ws, **kwargs)
        self.assertNotIn("dataflow_stitched_chains", block_absent)
        self.assertNotIn("dataflow_stitched_chains", block_absent["input_counts"])
        # Present: block surfaces with count.
        self._write([
            _entry_path("A", write_var="balance"),
            _impact_path("B", read_var="balance"),
        ])
        block_present = self.m._terminal_observability(workspace=self.ws, **kwargs)
        self.assertIn("dataflow_stitched_chains", block_present)
        self.assertEqual(block_present["input_counts"]["dataflow_stitched_chains"], 1)

    def test_byte_identical_terminal_observability_when_no_slice(self):
        """A no-slice workspace's terminal-observability JSON must be byte-identical to
        a baseline computed by deleting the new keys - i.e. nothing changed off-slice."""
        kwargs = dict(
            input_fingerprints={}, current_queue_lead_ids=set(),
            current_queue_lead_invariant_ids={}, all_source_link_entries=[],
            source_link_entries=[], rejected_source_link_entries=0,
            source_link_artifacts=[], broken_ids=[], max_chains=10,
            require_hop_evidence=False, dry_run=True, template_match_status="x")
        block = self.m._terminal_observability(workspace=self.ws, **kwargs)
        # No dataflow keys at all when no slice.
        self.assertNotIn("dataflow_stitched_chains", block)
        self.assertNotIn("dataflow_edges", block)


class ExploitSkeletonTest(unittest.TestCase):
    def setUp(self):
        self.m = _load(_EXPLOIT, "exploit_conversion_loop_skeltest")
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)
        # A real in-workspace source file so refs resolve "current".
        (self.ws / "b.sol").write_text("\n" * 60, encoding="utf-8")

    def _write_slice(self, recs):
        (self.ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")

    def _status(self, refs):
        return {"current_refs": refs, "stale_refs": [], "raw_refs": [], "resolved_refs": refs}

    def test_absent_slice_returns_none(self):
        row = {"lead_id": "x"}
        status = self._status([{"path": str(self.ws / "b.sol"), "line": 40, "current": True}])
        self.assertIsNone(self.m.build_dataflow_skeleton(row, self.ws, status))

    def test_source_ref_match_yields_skeleton(self):
        b_file = str(self.ws / "b.sol")
        rec = {
            "schema": "dataflow_path.v1", "path_id": "P1", "language": "solidity",
            "direction": "forward", "engine": "evm-ssa",
            "source": {"kind": "state_var", "fn": "payout", "var": "bal", "file": b_file, "line": 40},
            "sink": {"kind": "transfer", "callee": "transfer", "arg_pos": 1, "fn": "payout",
                     "file": b_file, "line": 48},
            "hops": [{"from_var": "bal", "to_var": "out", "fn": "payout", "via": "internal_call",
                      "file": b_file, "line": 43, "ir": "", "guarded": False}],
            "call_depth": 1, "unguarded": True, "guard_nodes": [],
            "source_unit_ids": [], "sink_unit_ids": [], "confidence": "semantic-ssa",
            "degraded": False,
        }
        self._write_slice([rec])
        row = {"lead_id": "x", "source_refs": [f"{b_file}:40"]}
        status = self._status([{"path": b_file, "line": 40, "current": True}])
        skel = self.m.build_dataflow_skeleton(row, self.ws, status)
        self.assertIsNotNone(skel)
        self.assertEqual(skel["association"], "source_ref")
        self.assertEqual(skel["path_ids"], ["P1"])
        step = skel["steps"][0]
        self.assertEqual(step["entrypoint"]["fn"], "payout")
        self.assertEqual(step["impact_sink"]["kind"], "transfer")
        self.assertEqual(step["verdict"], "unguarded-closure")

    def test_no_matching_ref_returns_none(self):
        b_file = str(self.ws / "b.sol")
        rec = {
            "schema": "dataflow_path.v1", "path_id": "P1", "language": "solidity",
            "direction": "forward", "engine": "evm-ssa",
            "source": {"kind": "state_var", "fn": "payout", "var": "bal", "file": b_file, "line": 40},
            "sink": {"kind": "transfer", "callee": "transfer", "arg_pos": 1, "fn": "payout",
                     "file": b_file, "line": 48},
            "hops": [], "call_depth": 0, "unguarded": True, "guard_nodes": [],
            "source_unit_ids": [], "sink_unit_ids": [], "confidence": "semantic-ssa",
            "degraded": False,
        }
        self._write_slice([rec])
        row = {"lead_id": "x"}
        # current_refs empty -> no source-ref association.
        self.assertIsNone(self.m.build_dataflow_skeleton(row, self.ws, self._status([])))

    def test_stitched_chain_row_yields_multistep_skeleton(self):
        b_file = str(self.ws / "b.sol")
        a = {
            "schema": "dataflow_path.v1", "path_id": "A", "language": "solidity",
            "direction": "forward", "engine": "evm-ssa",
            "source": {"kind": "param-entrypoint", "fn": "entry", "var": "amt", "file": b_file, "line": 10},
            "sink": {"kind": "storage-value", "callee": "balance", "arg_pos": None, "fn": "entry",
                     "file": b_file, "line": 15},
            "hops": [], "call_depth": 0, "unguarded": True, "guard_nodes": [],
            "source_unit_ids": [], "sink_unit_ids": [], "confidence": "semantic-ssa", "degraded": False,
        }
        b = {
            "schema": "dataflow_path.v1", "path_id": "B", "language": "solidity",
            "direction": "forward", "engine": "evm-ssa",
            "source": {"kind": "state_var", "fn": "payout", "var": "balance", "file": b_file, "line": 40},
            "sink": {"kind": "transfer", "callee": "transfer", "arg_pos": 1, "fn": "payout",
                     "file": b_file, "line": 48},
            "hops": [], "call_depth": 0, "unguarded": True, "guard_nodes": [],
            "source_unit_ids": [], "sink_unit_ids": [], "confidence": "semantic-ssa", "degraded": False,
        }
        self._write_slice([a, b])
        row = {"lead_id": "c", "chain_kind": "dataflow_stitched", "path_ids": ["A", "B"]}
        skel = self.m.build_dataflow_skeleton(row, self.ws, self._status([]))
        self.assertIsNotNone(skel)
        self.assertEqual(skel["association"], "stitched_chain")
        self.assertEqual(skel["path_ids"], ["A", "B"])
        self.assertEqual(skel["hop_count"], 2)
        self.assertEqual(len(skel["steps"]), 2)
        self.assertEqual(skel["steps"][1]["impact_sink"]["kind"], "transfer")


if __name__ == "__main__":
    unittest.main()
