#!/usr/bin/env python3
"""Regression (2026-07-08): the State-Coupling Graph is WIRED into audit-complete as a
fail-closed, self-generating gate. Before this the SCG was an ORPHAN - no make target /
audit driver ever ran state-coupling-graph --emit, and check_state_coupling was NOT in the
audit-completeness-check signal set, so on a real audit the SCG produced nothing and fed
neither the gate nor the exploit-queue (measured: 0 SCG rows in NUVA's exploit_queue).

Locks: (1) the check AUTO-EMITS the SCG (regenerates state_coupling_edges.jsonl from VMF
even when deleted); (2) it FAILS-CLOSED under AUDITOOOR_L37_STRICT=1 when an unprobed
promotable coupled-state edge exists; (3) advisory-WARN (ok=True) otherwise."""
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("acc_scc", _T / "audit-completeness-check.py")
_m = importlib.util.module_from_spec(_spec)
sys.modules["acc_scc"] = _m
_spec.loader.exec_module(_m)


def _ws_with_promotable_coupling():
    # a cross-domain dual-accounting asymmetry -> a promotable semantic-ssa edge.
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("")
    (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({"functions": [
        {"file": "msg_server.go", "function": "BridgeBurnShares", "language": "go",
         "transfer_hit": True, "ledger_write_evidence": []},
        {"file": "vault.go", "function": "SwapIn", "language": "go",
         "transfer_hit": True, "ledger_write_evidence": ["TotalShares"]},
    ]}))
    return ws


def _ws_with_degraded_go_feeder():
    # a Go value-mover whose slice has a state-write SINK but NO sink.cell (the degraded /
    # starved go-dataflow feeder signature - e.g. a toolchain build failure).
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("")
    (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({"functions": [
        {"file": "k.go", "function": "(*x.Keeper).Reconcile", "language": "go",
         "transfer_hit": True, "ledger_write_evidence": ["vaultShares", "stakingShares"]},
    ]}))
    dfs = importlib.util.spec_from_file_location("_dfs", _T / "dataflow_schema.py")
    _dfmod = importlib.util.module_from_spec(dfs)
    dfs.loader.exec_module(_dfmod)
    rec = _dfmod.new_path(
        "g0", "go", "backward", "go-ssa",
        source={"kind": "none", "fn": None, "var": None, "file": None, "line": None},
        sink={"kind": "none", "callee": None, "arg_pos": None, "fn": None,
              "file": None, "line": None},
        hops=[])
    rec["degraded"] = True  # the ROBUST degraded-feeder signal: an actual go-arm degrade record
    rec["degrade_reason"] = "load/build failure: packages.Load: err"
    _dfmod.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [rec])
    return ws


def _ws_with_dataflow(records):
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    with (ws / ".auditooor" / "dataflow_paths.jsonl").open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return ws


class TestDataflowSubstrateHealthGate(unittest.TestCase):
    """GENERALIZATION (2026-07-08): the step-1c dataflow slice is the shared substrate under
    EVERY dataflow-dependent lens (path-mode hunt, guard-reachability, chain-synth, SCC). A
    starved arm silently downgrades ALL of them; this gate fails-closed under STRICT for ANY
    language whose arm is starved (genuine build/load failures + near-zero real paths)."""

    def setUp(self):
        os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def _rec(self, lang, degraded=False, reason=None):
        return {"schema": "dataflow_path.v1", "language": lang, "degraded": degraded,
                "degrade_reason": reason, "sink": {"kind": "state-write"}, "hops": []}

    def test_starved_go_arm_fails_closed_under_strict(self):
        recs = [self._rec("go", degraded=True, reason="run failure: go-dataflow run timed out (900s)")]
        recs += [self._rec("go") for _ in range(3)]  # <10 real
        ws = _ws_with_dataflow(recs)
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _m.check_dataflow_substrate_health(ws)
        self.assertFalse(r.ok, "a starved go arm must FAIL under STRICT")
        self.assertIn("go", r.detail["starved"])

    def test_starved_arm_is_advisory_without_strict(self):
        recs = [self._rec("go", degraded=True, reason="packages.Load: err")] + [self._rec("go")]
        r = _m.check_dataflow_substrate_health(_ws_with_dataflow(recs))
        self.assertTrue(r.ok, "advisory-first: WARN-pass without STRICT")

    def test_healthy_arm_with_few_file_failures_NOT_starved(self):
        # nuva-go-now / morpho-sol shape: many real paths + a FEW individual compile fails.
        recs = [self._rec("go", degraded=True, reason="panic during analysis: ForEachElement")]
        recs += [self._rec("go") for _ in range(1436)]
        ws = _ws_with_dataflow(recs)
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _m.check_dataflow_substrate_health(ws)
        self.assertTrue(r.ok, "a healthy arm with a few file-fails (real>>10) is NOT starved")
        self.assertEqual(r.detail["starved"], [])

    def test_benign_absence_degrade_NOT_starved(self):
        # no-cargo-toml on a Sol-only ws is a benign absence, NOT a genuine failure.
        recs = [self._rec("rust", degraded=True, reason="morpho:no-cargo-toml")]
        recs += [self._rec("solidity") for _ in range(400)]
        ws = _ws_with_dataflow(recs)
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _m.check_dataflow_substrate_health(ws)
        self.assertTrue(r.ok, "benign no-cargo-toml absence must NOT trip the gate")

    def test_multilanguage_any_starved_arm_fails(self):
        # generality across languages: a starved RUST arm alongside a healthy Sol arm fails.
        recs = [self._rec("rust", degraded=True, reason="load/build failure: compile error")]
        recs += [self._rec("rust") for _ in range(2)]  # <10 real
        recs += [self._rec("solidity") for _ in range(500)]
        ws = _ws_with_dataflow(recs)
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _m.check_dataflow_substrate_health(ws)
        self.assertFalse(r.ok, "a starved rust arm must FAIL even with a healthy sol arm")
        self.assertIn("rust", r.detail["starved"])


class TestStateCouplingGateWired(unittest.TestCase):
    def setUp(self):
        os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def test_signal_registered_in_audit_complete(self):
        self.assertTrue(hasattr(_m, "check_state_coupling"),
                        "check_state_coupling must exist and be an audit-complete signal")

    def test_state_coupling_is_in_SIGNAL_ORDER_not_silently_dropped(self):
        # NOT-BYPASSABLE AUDIT (2026-07-08): the terminal audit-complete verdict is
        # aggregated by ITERATING _SIGNAL_ORDER; a signal computed in by_signal but ABSENT
        # from _SIGNAL_ORDER is SILENTLY DROPPED from the failure set - check_state_coupling
        # returned ok=False under STRICT yet the verdict stayed pass-audit-complete. Lock
        # membership so the coupled-state axis can never be dropped from the terminal AND.
        order = {sig for sig, _ in _m._SIGNAL_ORDER}
        self.assertIn("state-coupling", order,
                      "state-coupling MUST be in _SIGNAL_ORDER or its failure is dropped")

    def test_no_by_signal_key_is_dropped_from_SIGNAL_ORDER(self):
        # GENERIC bypass-class guard: EVERY computed by_signal key must appear in
        # _SIGNAL_ORDER (else it is computed then dropped from the terminal verdict) and
        # every _SIGNAL_ORDER entry must be computed (else the aggregation KeyErrors).
        # This is the invariant that would have caught the state-coupling drop for ALL
        # signals, present and future.
        src = (_T / "audit-completeness-check.py").read_text()
        blk = src[src.index("by_signal = {"):]
        blk = blk[:blk.index("\n    }")]
        computed = set(re.findall(r'"([a-z0-9-]+)":\s*check_', blk))
        order = {sig for sig, _ in _m._SIGNAL_ORDER}
        self.assertEqual(computed, order,
                         f"by_signal vs _SIGNAL_ORDER mismatch - dropped: {sorted(computed - order)}; "
                         f"uncomputed: {sorted(order - computed)}")

    def test_gate_auto_emits_the_scg(self):
        ws = _ws_with_promotable_coupling()
        edges = ws / ".auditooor" / "state_coupling_edges.jsonl"
        self.assertFalse(edges.exists())
        _m.check_state_coupling(ws)  # must AUTO-EMIT
        self.assertTrue(edges.exists(), "the gate must regenerate the SCG from VMF")

    def test_gate_fails_closed_under_strict_on_unprobed_edge(self):
        ws = _ws_with_promotable_coupling()
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _m.check_state_coupling(ws)
        self.assertFalse(r.ok,
                         "an unprobed promotable coupled-state edge must FAIL audit-complete under STRICT")

    def test_gate_advisory_when_not_strict(self):
        ws = _ws_with_promotable_coupling()
        r = _m.check_state_coupling(ws)  # no STRICT
        self.assertTrue(r.ok, "advisory-first: WARN-pass (ok=True) without the strict umbrella")

    def test_gate_fails_closed_under_strict_on_degraded_go_feeder(self):
        # ENFORCEMENT (2026-07-08): a STARVED go-dataflow feeder (Go state-write sinks present
        # but 0 sink.cell) produces almost no coupled-state edges, so "0 open edges" is FALSE
        # completeness - the axis was never covered (NUVA: 35 sinks/0 cells yet the gate
        # PASSED). check_state_coupling must FAIL-CLOSED under STRICT on a degraded feeder, so
        # a starved feeder can no longer masquerade as a clean coupled-state 0.
        ws = _ws_with_degraded_go_feeder()
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _m.check_state_coupling(ws)
        self.assertFalse(r.ok,
                         "a degraded Go coupled-state feeder must FAIL audit-complete under STRICT")
        self.assertEqual(r.detail.get("feeder_status"), "0-go-feeder-degraded")

    def test_gate_advisory_warn_pass_on_degraded_feeder_without_strict(self):
        # advisory-first: the degraded feeder WARNs but does not block without the strict umbrella.
        ws = _ws_with_degraded_go_feeder()
        r = _m.check_state_coupling(ws)
        self.assertTrue(r.ok, "degraded feeder is advisory-WARN (ok=True) without STRICT")

    def test_gate_passes_strict_when_edge_probed_negative(self):
        ws = _ws_with_promotable_coupling()
        _m.check_state_coupling(ws)  # emit to learn the edge_id
        eids = [json.loads(l)["edge_id"] for l in
                (ws / ".auditooor" / "state_coupling_edges.jsonl").read_text().splitlines()
                if '"cross-domain-conservation"' in l]
        (ws / ".auditooor" / "state_coupling_probes.jsonl").write_text(
            "\n".join(json.dumps({"edge_id": e, "verdict": "NEGATIVE-guarded",
                                  "note": "source-cited: guarded @ V.sol:1"}) for e in eids) + "\n")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        r = _m.check_state_coupling(ws)
        self.assertTrue(r.ok, "a probed-NEGATIVE edge must not block under STRICT")


if __name__ == "__main__":
    unittest.main()
