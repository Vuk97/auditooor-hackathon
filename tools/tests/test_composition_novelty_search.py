#!/usr/bin/env python3
"""Tests for tools/composition-novelty-search.py (CNS).

Hermetic: each test builds a minimal workspace substrate (value_moving_functions
.json + state_coupling_edges.jsonl + pisvs/derived_invariants.jsonl) in a tmp dir,
so the composition query is exercised over a REAL (if synthetic) substrate, never
mocked. The NON-VACUOUS mutation tests prove the finding dissolves when a
dominating node is added or when op_b stops touching the invariant's state - i.e.
CNS is a per-invariant single-op-safe-vs-composition difference, not a two-name
grep.
"""
import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "composition-novelty-search.py"
_spec = importlib.util.spec_from_file_location("cns", _TOOL)
cns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cns)


def _ws(tmp: str) -> Path:
    ws = Path(tmp)
    (ws / ".auditooor" / "pisvs").mkdir(parents=True, exist_ok=True)
    return ws


def _write_invariant(ws: Path, symbols):
    """A D1-style ratio invariant over the given coupled symbols."""
    row = {
        "form": "D1_RATIO_AUTHORITY_CONSISTENCY",
        "statement": "the ratio must move under one authority",
        "numerator": symbols[0],
        "denominator": symbols[1],
        "file": "src/vault.go",
        "line": 42,
        "corpus_verdict": "NOVEL",
        "site": {"file": "src/vault.go", "line": 42,
                 "numerator": symbols[0], "denominator": symbols[1]},
        "invariant_id": "inv-ratio-1",
    }
    (ws / ".auditooor" / "pisvs" / "derived_invariants.jsonl").write_text(
        json.dumps(row) + "\n")


def _write_vmf(ws: Path, funcs):
    (ws / ".auditooor" / "value_moving_functions.json").write_text(
        json.dumps({"functions": funcs}))


def _write_edges(ws: Path, edges):
    (ws / ".auditooor" / "state_coupling_edges.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in edges))


def _base_funcs(op_a_extra=None, op_b_extra=None):
    """Two functions that BOTH write the same coupled cell (TotalShares) - the
    real share-price structure (deposit and redeem both mutate TotalShares). op_a
    (redeem) is a boundary-mover."""
    a = {"function": "triggerRedeem", "file": "src/vault.go", "line": 10,
         "ledger_write_evidence": ["TotalShares"], "transfer_evidence": []}
    b = {"function": "SwapIn", "file": "src/vault.go", "line": 20,
         "ledger_write_evidence": ["TotalShares"], "transfer_evidence": []}
    if op_a_extra:
        a.update(op_a_extra)
    if op_b_extra:
        b.update(op_b_extra)
    return [a, b]


def _ratio_edge(writers=("triggerRedeem", "SwapIn"), **extra):
    """A coupled edge that makes {tvv, TotalShares} graph cells and both ops
    graph-writers of TotalShares (cell_a)."""
    e = {"cell_a": "TotalShares", "cell_b": "tvv", "edge_id": "e1",
         "writers_a": list(writers), "writers_b": [], "evidence": {}}
    e.update(extra)
    return e


class TestCompositionNovelty(unittest.TestCase):

    def test_survivor_fires_on_sequential_pair(self):
        with TemporaryDirectory() as tmp:
            ws = _ws(tmp)
            _write_invariant(ws, ["tvv", "TotalShares"])
            _write_vmf(ws, _base_funcs())
            _write_edges(ws, [_ratio_edge()])
            res = cns.analyse(ws)
            self.assertEqual(res["substrate_status"], "survivors")
            self.assertGreaterEqual(res["census"]["survivors"], 1)
            # the surviving pair breaks the ratio invariant over TotalShares
            s = res["survivors"][0]
            self.assertIn("totalshares", [x.lower() for x in s["shared_state_node"]])

    def test_static_differential_from_boundary_mover(self):
        with TemporaryDirectory() as tmp:
            ws = _ws(tmp)
            _write_invariant(ws, ["tvv", "TotalShares"])
            _write_vmf(ws, _base_funcs())  # triggerRedeem is a boundary-mover
            _write_edges(ws, [_ratio_edge()])
            res = cns.analyse(ws)
            confs = {s["effect_confidence"] for s in res["survivors"]}
            self.assertIn("static-differential", confs)

    def test_novelty_label_promotes_to_composition_novel(self):
        with TemporaryDirectory() as tmp:
            ws = _ws(tmp)
            _write_invariant(ws, ["tvv", "TotalShares"])  # NOVEL corpus_verdict
            _write_vmf(ws, _base_funcs())
            _write_edges(ws, [_ratio_edge()])
            res = cns.analyse(ws)
            self.assertTrue(any(s["novelty"] == "COMPOSITION-NOVEL"
                                for s in res["survivors"]))

    # ---- NON-VACUOUS mutation #1: a shared lock dominates -> survivor gone ----
    def test_shared_lock_dominator_kills_survivor(self):
        with TemporaryDirectory() as tmp:
            ws = _ws(tmp)
            _write_invariant(ws, ["tvv", "TotalShares"])
            funcs = _base_funcs(
                op_a_extra={"transfer_evidence": ["nonReentrant"]},
                op_b_extra={"transfer_evidence": ["nonReentrant"]})
            _write_vmf(ws, funcs)
            _write_edges(ws, [_ratio_edge()])
            res = cns.analyse(ws)
            self.assertEqual(res["census"]["survivors"], 0)
            self.assertEqual(res["substrate_status"], "cited-empty")

    # ---- NON-VACUOUS mutation #2: op_b stops touching I's state -> gone ----
    def test_op_b_not_touching_invariant_state_kills_survivor(self):
        with TemporaryDirectory() as tmp:
            ws = _ws(tmp)
            _write_invariant(ws, ["tvv", "TotalShares"])
            _write_vmf(ws, _base_funcs(
                op_b_extra={"ledger_write_evidence": ["unrelatedField"]}))
            # op_b (SwapIn) is NOT a writer of TotalShares in the graph now: only
            # op_a writes the coupled cell -> no shared-node pair -> no survivor.
            _write_edges(ws, [_ratio_edge(writers=("triggerRedeem",))])
            res = cns.analyse(ws)
            self.assertEqual(res["census"]["survivors"], 0)

    # ---- NON-VACUOUS mutation #3: post-composition assertion dominates ----
    def test_post_composition_assertion_kills_survivor(self):
        with TemporaryDirectory() as tmp:
            ws = _ws(tmp)
            _write_invariant(ws, ["tvv", "TotalShares"])
            _write_vmf(ws, _base_funcs())
            # guarded_readers include both ops -> a post-composition assertion node
            # dominates the pair -> KILL.
            _write_edges(ws, [_ratio_edge(
                evidence={"guarded_readers": ["triggerRedeem", "SwapIn"]})])
            res = cns.analyse(ws)
            self.assertEqual(res["census"]["survivors"], 0)

    def test_single_op_violator_excluded_not_composition_novel(self):
        # An op that in ISOLATION mutates a member and omits its coupled sibling is
        # the already-covered coupled-state class, not composition-novel: it must
        # NOT be counted as single-op-safe.
        with TemporaryDirectory() as tmp:
            ws = _ws(tmp)
            _write_invariant(ws, ["tvv", "TotalShares"])
            _write_vmf(ws, _base_funcs())
            _write_edges(ws, [_ratio_edge(violators=[
                {"fn": "triggerRedeem", "file": "src/vault.go", "line": 10,
                 "mutates": ["TotalShares"], "omits": ["tvv"]}])])
            res = cns.analyse(ws)
            # triggerRedeem is a single-op violator of the coupling -> every pair
            # using it is excluded; surviving pairs must credit only safe ops.
            for s in res["survivors"]:
                self.assertNotIn("triggerRedeem", (s["op_a"], s["op_b"]))
                self.assertTrue(s["single_op_safe"]["op_a"])
                self.assertTrue(s["single_op_safe"]["op_b"])

    def test_substrate_vacuous_when_no_producers_ran(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            res = cns.analyse(ws)
            self.assertEqual(res["substrate_status"], "substrate_vacuous")
            # the fail-loud message names BOTH absent producer arms + the remedy
            reason = res["substrate_reason"]
            self.assertIn("substrate dependency UNMET", reason)
            self.assertIn("derived_invariants.jsonl", reason)
            self.assertIn("state_coupling_edges.jsonl", reason)
            self.assertIn("--autorun-producers", reason)

    def test_missing_producers_helper_keys_on_file_presence(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            # nothing on disk -> both arms missing
            self.assertEqual(len(cns._missing_producers(ws)), 2)
            # a present-but-empty PISVS ledger materializes ONE arm -> not vacuous
            (ws / ".auditooor" / "pisvs").mkdir(parents=True, exist_ok=True)
            (ws / ".auditooor" / "pisvs" / "derived_invariants.jsonl").write_text("")
            self.assertEqual(cns._missing_producers(ws), [])

    def test_root_fallback_novelty_obligations_counts_as_substrate(self):
        # PISVS also publishes novelty_obligations.jsonl at the .auditooor root;
        # its presence alone means the producer ran -> NOT vacuous.
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            (ws / ".auditooor" / "novelty_obligations.jsonl").write_text("")
            self.assertEqual(cns._missing_producers(ws), [])
            res = cns.analyse(ws)
            self.assertNotEqual(res["substrate_status"], "substrate_vacuous")

    def test_fail_closed_exit_2_on_vacuous(self):
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            rc = cns._main(["-w", str(ws), "--fail-closed"])
            self.assertEqual(rc, 2)

    def test_autorun_producers_attempts_all_configured(self):
        # the autorun helper attempts EVERY configured producer and reports each.
        with TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            log = cns._autorun_producers(ws)
            names = {r["producer"] for r in log}
            self.assertIn("protocol-invariant-synth-violation-search.py", names)
            self.assertIn("coupled-state-completeness-graph.py", names)
            self.assertIn("state-coupling-graph.py", names)

    def test_emit_writes_ledgers(self):
        with TemporaryDirectory() as tmp:
            ws = _ws(tmp)
            _write_invariant(ws, ["tvv", "TotalShares"])
            _write_vmf(ws, _base_funcs())
            _write_edges(ws, [_ratio_edge()])
            res = cns.analyse(ws)
            out = cns.emit(ws, res)
            self.assertTrue((out / "composition_survivors.jsonl").is_file())
            self.assertTrue((out / "composition_novelty_manifest.json").is_file())
            root = ws / ".auditooor" / "composition_novelty_obligations.jsonl"
            self.assertTrue(root.is_file())
            # obligations carry open/needs-search + the queue schema
            rows = [json.loads(l) for l in root.read_text().splitlines() if l.strip()]
            self.assertTrue(rows)
            for r in rows:
                self.assertEqual(r["proof_status"], "open")
                self.assertEqual(r["search_status"], "needs-search")
                self.assertEqual(r["schema"], cns.SCHEMA)
                self.assertEqual(r["attack_class"], "novel-composition-violation")


if __name__ == "__main__":
    unittest.main()
