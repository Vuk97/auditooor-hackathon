#!/usr/bin/env python3
"""Regression for invariant-ledger.py ingest_state_couplings (P5 - cross-ws lift).
Only PROMOTABLE semantic-ssa / probe-confirmed SCG edges enter the durable ledger.
2026-07-08 (SCC framework, box P5 - last)."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


scs = _load("state_coupling_schema", "state_coupling_schema.py")
il = _load("invariant_ledger", "invariant-ledger.py")


def _edge(eid, kind="conserved-with", confidence="semantic-ssa",
          promotable=True, verdict=None):
    e = scs.new_edge(eid, "solidity", kind, "a", "b", ["fa"], ["fb"],
                     [{"fn": "fb", "file": "V.sol", "line": 1,
                       "mutates": ["b"], "omits": ["a"]}], confidence=confidence)
    e["evidence"]["promotable"] = promotable
    if verdict:
        e["evidence"]["probe_verdict"] = verdict
    return e


def _ws(edges):
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    scs.write_edges(ws, edges)
    return ws


class T(unittest.TestCase):
    def test_promotable_semantic_ingested(self):
        ws = _ws([_edge("e1")])
        n = il.ingest_state_couplings(ws, now="2026-07-08T00:00:00Z")
        self.assertEqual(n, 1)
        rows = il.load_rows(ws)
        scg_rows = [r for r in rows if r.id.startswith("SCG-")]
        self.assertEqual(len(scg_rows), 1)
        self.assertEqual(scg_rows[0].invariant_family, "state-coupling-completeness")
        # lift sidecar written
        lift = ws / ".auditooor" / "state_coupling_lift.jsonl"
        recs = [json.loads(l) for l in lift.read_text().splitlines() if l.strip()]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["kind"], "conserved-with")

    def test_syntactic_and_nonpromotable_excluded(self):
        ws = _ws([
            _edge("syn", confidence="syntactic", promotable=True),   # not semantic
            _edge("nonprom", confidence="semantic-ssa", promotable=False),
        ])
        n = il.ingest_state_couplings(ws, now="t")
        self.assertEqual(n, 0)
        self.assertEqual([r for r in il.load_rows(ws) if r.id.startswith("SCG-")], [])

    def test_probe_confirmed_syntactic_included(self):
        # a syntactic edge that a probe CONFIRMED is citable -> ingested.
        ws = _ws([_edge("fresh", kind="freshness-coupled-to-external-clock",
                        confidence="syntactic", promotable=False,
                        verdict="REAL-stale-consumed")])
        n = il.ingest_state_couplings(ws, now="t")
        self.assertEqual(n, 1)

    def test_probed_negative_excluded(self):
        ws = _ws([_edge("neg", verdict="NEGATIVE-guarded")])
        self.assertEqual(il.ingest_state_couplings(ws, now="t"), 0)

    def test_idempotent(self):
        ws = _ws([_edge("e1")])
        il.ingest_state_couplings(ws, now="t")
        n2 = il.ingest_state_couplings(ws, now="t2")  # re-run
        self.assertEqual(n2, 0)  # no NEW rows
        self.assertEqual(
            len([r for r in il.load_rows(ws) if r.id.startswith("SCG-")]), 1)

    def test_preserves_existing_rows(self):
        ws = _ws([_edge("e1")])
        # seed a non-SCG row first
        pre = il.Row(id="MANUAL-1", scope_asset="X.sol",
                     invariant_family="cl_el_parity", statement="pre-existing")
        il.save_rows(ws, [pre], write_md=False)
        il.ingest_state_couplings(ws, now="t")
        ids = {r.id for r in il.load_rows(ws)}
        self.assertIn("MANUAL-1", ids)
        self.assertIn("SCG-e1", ids)


if __name__ == "__main__":
    unittest.main()
