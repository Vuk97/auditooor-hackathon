#!/usr/bin/env python3
"""Not-bypassable regression (SCC capability-depth loop 2026-07-08): the exploit-queue
consumer `_gather_from_state_coupling` must promote ONLY citable edges - a PROMOTABLE
semantic-ssa edge OR a probe-CONFIRMED advisory edge - and must REFUSE a raw syntactic /
non-promotable edge and DROP a probed-NEGATIVE edge. Without this test the promotion gate
(exploit-queue.py:1680-1683) is bypassable-by-refactor: a future edit could silently drop
the semantic-ssa check and flood the exploit queue with regex FPs. Locks the invariant."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


scs = _load("state_coupling_schema", "state_coupling_schema.py")
eq = _load("eq_scg", "exploit-queue.py")


def _ws_with_edges(edges):
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    with (ws / ".auditooor" / "state_coupling_edges.jsonl").open("w") as fh:
        for e in edges:
            fh.write(json.dumps(e) + "\n")
    return ws


def _edge(eid, confidence, promotable, probe_verdict=None, kind="conserved-with"):
    e = scs.new_edge(eid, "solidity", kind, "cellA", "cellB",
                     ["wA"], ["wB"],
                     [{"fn": "partialFlush", "file": "V.sol", "line": 12,
                       "mutates": ["cellB"], "omits": ["cellA"]}],
                     confidence=confidence)
    e["evidence"]["promotable"] = promotable
    if probe_verdict is not None:
        e["evidence"]["probe_verdict"] = probe_verdict
        # a real probe carries a citable rationale (required to CONFIRM-promote an advisory
        # edge; the hand-green rejection is tested separately with a bare sidecar verdict).
        e["evidence"]["note"] = "probe: source-cited @ V.sol:1"
    return e


class TestPromotionGateNotBypassable(unittest.TestCase):
    def _ids(self, ws):
        return {r.get("lead_id", "") for r in eq._gather_from_state_coupling(ws)}

    def test_semantic_ssa_promotable_is_promoted(self):
        ws = _ws_with_edges([_edge("e_sem", "semantic-ssa", True)])
        self.assertTrue(any("e_sem" in i for i in self._ids(ws)),
                        "a promotable semantic-ssa edge MUST reach the queue")

    def test_syntactic_nonpromotable_is_refused(self):
        ws = _ws_with_edges([_edge("e_syn", "syntactic", False)])
        self.assertEqual(self._ids(ws), set(),
                         "a raw syntactic/non-promotable edge must NEVER be promoted")

    def test_syntactic_even_if_promotable_flag_set_without_semantic_is_refused(self):
        # promotable True but confidence != semantic-ssa and no probe -> still refused
        # (both conditions are load-bearing; neither alone opens the gate).
        ws = _ws_with_edges([_edge("e_syn2", "syntactic", True)])
        self.assertEqual(self._ids(ws), set(),
                         "promotable alone (non-semantic, unprobed) must not promote")

    def test_probed_negative_is_dropped(self):
        ws = _ws_with_edges([_edge("e_neg", "semantic-ssa", True,
                                   probe_verdict="ruled-out")])
        self.assertEqual(self._ids(ws), set(),
                         "a probed-NEGATIVE edge is the coupling the probe CLEARED")

    def test_probe_confirmed_advisory_reaches_queue(self):
        # a freshness/advisory edge (non-promotable, non-semantic) reaches the queue
        # ONLY once a probe CONFIRMS it.
        ws = _ws_with_edges([_edge("e_fresh", "syntactic", False,
                                   probe_verdict="confirmed",
                                   kind="freshness-coupled-to-external-clock")])
        self.assertTrue(any("e_fresh" in i for i in self._ids(ws)),
                        "a probe-confirmed advisory edge MUST reach the queue")

    def test_probe_sidecar_negative_drops_a_promotable_edge(self):
        # serving-join fix: a promotable semantic-ssa edge that was PROBED-NEGATIVE in
        # state_coupling_probes.jsonl (the canonical box-G record) must NOT reach the
        # exploit queue - the SCG is regenerated fresh so the verdict lives only in the
        # sidecar. Without the join a cited-NEGATIVE edge floods the queue forever.
        ws = _ws_with_edges([_edge("e_probed", "semantic-ssa", True)])
        (ws / ".auditooor" / "state_coupling_probes.jsonl").write_text(
            json.dumps({"edge_id": "e_probed",
                        "verdict": "NEGATIVE-intentional-guarded-design"}) + "\n")
        self.assertEqual(self._ids(ws), set(),
                         "a probe-sidecar NEGATIVE must drop the edge from the queue")

    def test_probe_sidecar_confirmed_keeps_the_edge(self):
        # a non-NEGATIVE sidecar verdict (confirmed) leaves a promotable edge promoted.
        ws = _ws_with_edges([_edge("e_ok", "semantic-ssa", True)])
        (ws / ".auditooor" / "state_coupling_probes.jsonl").write_text(
            json.dumps({"edge_id": "e_ok", "verdict": "confirmed-reachable"}) + "\n")
        self.assertTrue(any("e_ok" in i for i in self._ids(ws)),
                        "a confirmed sidecar verdict keeps the promotable edge")

    def test_bare_confirmed_verdict_does_not_hand_green_syntactic(self):
        # HAND-GREEN GUARD (2026-07-08): a bare sidecar {edge_id, verdict:"confirmed"} with NO
        # rationale must NOT promote a raw syntactic/advisory edge - confirm-promotion requires
        # a citable rationale (note/evidence/source_cites), else it is a silent hand-green.
        ws = _ws_with_edges([_edge("e_bare", "syntactic", False,
                                   kind="freshness-coupled-to-external-clock")])
        (ws / ".auditooor" / "state_coupling_probes.jsonl").write_text(
            json.dumps({"edge_id": "e_bare", "verdict": "confirmed"}) + "\n")
        self.assertEqual(self._ids(ws), set(),
                         "a rationale-less confirmed verdict must NOT promote a syntactic edge")

    def test_confirmed_with_rationale_promotes_syntactic(self):
        # the legitimate counterpart: a confirmed verdict WITH a rationale promotes.
        ws = _ws_with_edges([_edge("e_ok2", "syntactic", False,
                                   kind="freshness-coupled-to-external-clock")])
        (ws / ".auditooor" / "state_coupling_probes.jsonl").write_text(
            json.dumps({"edge_id": "e_ok2", "verdict": "confirmed",
                        "note": "reachable PoC @ V.sol:2"}) + "\n")
        self.assertTrue(any("e_ok2" in i for i in self._ids(ws)),
                        "a confirmed verdict WITH rationale must promote")

    def test_mixed_batch_promotes_only_the_citable(self):
        ws = _ws_with_edges([
            _edge("keep_sem", "semantic-ssa", True),
            _edge("drop_syn", "syntactic", False),
            _edge("drop_neg", "semantic-ssa", True, probe_verdict="false-positive"),
            _edge("keep_conf", "syntactic", False, probe_verdict="confirmed"),
        ])
        ids = self._ids(ws)
        self.assertTrue(any("keep_sem" in i for i in ids))
        self.assertTrue(any("keep_conf" in i for i in ids))
        self.assertFalse(any("drop_syn" in i for i in ids))
        self.assertFalse(any("drop_neg" in i for i in ids))


if __name__ == "__main__":
    unittest.main()
