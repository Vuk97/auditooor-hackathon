#!/usr/bin/env python3
"""Regression: a PARTIAL Go dataflow degrade must not be silently swallowed by the
resolved status (anti-silent-suppression, operator-caught NUVA 2026-07-08). NUVA's
src/vault/simapp panicked on a golang.org/x/tools generics bug while the vault keeper
sliced 1463 pairs - the degrade was masked because name2cell>0 forced status "resolved"
and the gate only failed-closed on a TOTAL degrade ("0-go-feeder-degraded").

The fix attributes each degraded module (module_rel + reason) and classifies it by SCOPE:
- a degrade in an OOS module (simapp / test / genesis wiring) => WARN-surface, does NOT block
- a degrade in a module carrying an IN-SCOPE unit => BLOCK under STRICT (the coupled-state
  surface we are obliged to cover was NOT sliced)
The decision is scope (inscope_units.jsonl), not a name heuristic.

Each gate case builds a REAL slice: one resolving go state-write record (so name2cell>0 ->
status "resolved", the healthy modules) PLUS a degraded record attributed to a module. The
gate re-emits the SCG from this slice, so the accounting is genuinely recomputed."""
import importlib.util
import json
import os
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


_SCG = _load("_pd_scg", "state-coupling-graph.py")
_ACC = _load("_pd_acc", "audit-completeness-check.py")
_DFS = _load("_pd_dfs", "dataflow_schema.py")

_INSCOPE_FILE = "src/vault/keeper/reconcile.go"


def _build_ws(degraded_module: str) -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    (ws / ".auditooor" / "inscope_units.jsonl").write_text(
        json.dumps({"file": _INSCOPE_FILE, "unit": "reconcilePair"}) + "\n")
    # a VMF file so _conservation_edges runs its resolver/accounting block (it early-returns
    # without one) - the accounting is where slice_resolution_status + degraded attribution
    # are computed.
    (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({"functions": [
        {"file": _INSCOPE_FILE, "function": "reconcilePair", "language": "go",
         "transfer_hit": True, "ledger_write_evidence": ["vaultShares", "stakingShares"]}]}))
    # a resolving go state-write record -> name2cell>0 -> status "resolved" (healthy module)
    resolving = _DFS.new_path(
        "g1", "go", "backward", "go-ssa",
        source={"kind": "param", "fn": "reconcilePair", "var": "vaultShares",
                "file": _INSCOPE_FILE, "line": 2},
        sink={"kind": "state-write", "callee": "(collections.Map).Set", "arg_pos": 2,
              "fn": "reconcilePair", "cell": "Vaults", "file": _INSCOPE_FILE, "line": 3},
        hops=[])
    resolving["sink"]["cell"] = "Vaults"
    # a degraded record attributed to `degraded_module` (a panic'd module)
    degrade = {"schema": "dataflow_path.v1", "path_id": "degrade-0", "language": "go",
               "degraded": True, "degrade_reason": "panic during analysis",
               "module_rel": degraded_module}
    _DFS.write_jsonl(str(ws / ".auditooor" / "dataflow_paths.jsonl"), [resolving, degrade])
    return ws


class TestPartialGoDegradeScope(unittest.TestCase):
    def test_degraded_modules_are_attributed(self):
        ws = _build_ws("src/vault/simapp")
        mods = _SCG._go_degraded_modules(ws)
        self.assertEqual([m["module_rel"] for m in mods], ["src/vault/simapp"])
        self.assertIn("panic", mods[0]["reason"])
        self.assertTrue(_SCG._go_arm_degraded(ws))

    def test_scope_classifier(self):
        self.assertFalse(_SCG._degraded_module_is_inscope(
            None, "src/vault/simapp", [_INSCOPE_FILE]))
        self.assertTrue(_SCG._degraded_module_is_inscope(
            None, "src/vault/keeper", [_INSCOPE_FILE]))

    def _run_gate_strict(self, ws: Path):
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            return _ACC.check_state_coupling(ws)
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def test_oos_partial_degrade_passes_but_is_named(self):
        ws = _build_ws("src/vault/simapp")  # OOS module (no in-scope unit)
        r = self._run_gate_strict(ws)
        # status must be "resolved" (the healthy module resolved), and the degrade named
        acct = json.loads((ws / ".auditooor" / "state_coupling_conserved_accounting.json").read_text())
        self.assertEqual(acct["slice_resolution_status"], "resolved")
        self.assertFalse(acct["slice_go_degraded_inscope"])
        self.assertTrue(r.ok, "OOS partial degrade must NOT block")
        self.assertIn("PARTIAL DEGRADE", r.reason)
        self.assertIn("out-of-scope", r.reason)

    def test_inscope_partial_degrade_blocks_under_strict(self):
        # THE anti-silent-suppression proof: a degraded module holding in-scope surface makes
        # the gate fail-closed under STRICT even though status=="resolved" (name2cell>0).
        ws = _build_ws("src/vault/keeper")  # in-scope module (holds reconcile.go)
        r = self._run_gate_strict(ws)
        acct = json.loads((ws / ".auditooor" / "state_coupling_conserved_accounting.json").read_text())
        self.assertEqual(acct["slice_resolution_status"], "resolved")
        self.assertTrue(acct["slice_go_degraded_inscope"])
        self.assertFalse(r.ok, "in-scope partial Go degrade must block under STRICT")
        self.assertIn("PARTIAL DEGRADE", r.reason)
        self.assertIn("IN-SCOPE", r.reason)


if __name__ == "__main__":
    unittest.main()
