#!/usr/bin/env python3
"""SCC NOT-BYPASSABLE AUDIT - a single consolidated tripwire over ALL four State-Coupling
consumers' fail-closed guarantees (SCC loop priority-1). The per-consumer regressions live in
their own files; this test asserts the four properties TOGETHER so the "not-bypassable audit
passes" DoD is one named guard that trips if ANY consumer's fail-closed is weakened:

  (a) exploit-queue promotes ONLY promotable semantic-ssa (or probe-confirmed) edges, never
      raw syntactic/regex.
  (b) state-coupling-completeness-check HARD-FAILs rc1 under STRICT on an open promotable
      edge, WARN rc0 otherwise.
  (c) audit-complete's check_state_coupling is COMPUTED and in _SIGNAL_ORDER (bijection) so
      its failure can never be silently dropped from the terminal verdict.
  (d) the partial-Go-degrade scope classifier blocks an IN-SCOPE degraded module, passes an
      out-of-scope one (anti-silent-suppression)."""
import importlib.util
import json
import os
import re
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


_SCS = _load("_nb_scs", "state_coupling_schema.py")
_EQ = _load("_nb_eq", "exploit-queue.py")
_CHK = _load("_nb_chk", "state-coupling-completeness-check.py")
_ACC = _load("_nb_acc", "audit-completeness-check.py")
_SCG = _load("_nb_scg", "state-coupling-graph.py")


def _edge(eid, confidence, promotable, probe_verdict=None):
    e = _SCS.new_edge(eid, "solidity", "conserved-with", "cellA", "cellB", ["wA"], ["wB"],
                      [{"fn": "partialFlush", "file": "V.sol", "line": 12,
                        "mutates": ["cellB"], "omits": ["cellA"]}], confidence=confidence)
    e["evidence"]["promotable"] = promotable
    if probe_verdict is not None:
        e["evidence"]["probe_verdict"] = probe_verdict
    return e


def _ws_edges(edges):
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    with (ws / ".auditooor" / "state_coupling_edges.jsonl").open("w") as fh:
        for e in edges:
            fh.write(json.dumps(e) + "\n")
    return ws


class TestSCCNotBypassableAudit(unittest.TestCase):
    # (a) exploit-queue promotion gate
    def test_a_exploit_queue_promotes_semantic_refuses_syntactic(self):
        sem = _ws_edges([_edge("e_sem", "semantic-ssa", True)])
        syn = _ws_edges([_edge("e_syn", "syntactic", True)])  # promotable flag but not semantic
        sem_ids = {r.get("lead_id", "") for r in _EQ._gather_from_state_coupling(sem)}
        syn_ids = {r.get("lead_id", "") for r in _EQ._gather_from_state_coupling(syn)}
        self.assertTrue(any("e_sem" in i for i in sem_ids), "semantic-ssa promotable must promote")
        self.assertEqual(syn_ids, set(), "syntactic (even promotable-flagged) must NEVER promote")

    # (b) completeness-check rc1 STRICT / rc0 WARN
    def test_b_completeness_check_rc1_strict_rc0_warn(self):
        ws = _ws_edges([_edge("e_open", "semantic-ssa", True)])
        rc_warn = _CHK.main(["--workspace", str(ws), "--no-emit"])
        self.assertEqual(rc_warn, 0, "advisory-first: WARN rc0 without STRICT")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            rc_strict = _CHK.main(["--workspace", str(ws), "--no-emit"])
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        self.assertEqual(rc_strict, 1, "STRICT: HARD-FAIL rc1 on an open promotable edge")

    # (c) audit-complete: state-coupling computed AND in _SIGNAL_ORDER (bijection = no silent drop)
    def test_c_state_coupling_computed_and_in_signal_order(self):
        order = {sig for sig, _ in _ACC._SIGNAL_ORDER}
        self.assertIn("state-coupling", order)
        src = (_T / "audit-completeness-check.py").read_text()
        blk = src[src.index("by_signal = {"):]
        blk = blk[:blk.index("\n    }")]
        computed = set(re.findall(r'"([a-z0-9-]+)":\s*check_', blk))
        self.assertEqual(computed, order,
                         "by_signal vs _SIGNAL_ORDER must be a bijection (no computed-then-dropped "
                         "and no ordered-but-uncomputed signal); state-coupling included")

    # (d) partial-Go-degrade scope classifier (anti-silent-suppression)
    def test_d_partial_go_degrade_scope_classifier(self):
        self.assertFalse(_SCG._degraded_module_is_inscope(
            None, "src/vault/simapp", ["src/vault/keeper/reconcile.go"]),
            "an OOS degraded module must NOT be treated as in-scope surface")
        self.assertTrue(_SCG._degraded_module_is_inscope(
            None, "src/vault/keeper", ["src/vault/keeper/reconcile.go"]),
            "a degraded module holding an in-scope unit MUST be flagged in-scope")


if __name__ == "__main__":
    unittest.main()
