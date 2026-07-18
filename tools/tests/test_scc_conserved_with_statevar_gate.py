#!/usr/bin/env python3
"""Regression: a Solidity conserved-with edge is PROMOTABLE only when both coupled cells are
contract-level STATE VARIABLES (SCC loop, 2026-07-08). Measured FP: 77/87 promotable
conserved-with edges across 7 real ws rested on function-LOCAL snapshots/deltas
(initialBalance, eEthSharesMoved, feeTaken...) that VMF's ledger-write regex captured but which
have no conserved persistent invariant. When the dataflow slice does not ground the cells
(cell_resolution=local-name-fallback), the state-var scan decides: both cells declared at
contract scope -> promotable; a local -> demoted to advisory (demoted_reason set)."""
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


# both coupled cells are contract-level STATE VARIABLES -> a real conservation obligation.
_STORAGE = """contract Vault {
  uint256 public reserveAsset;
  uint256 public reserveNav;
  function accrue(uint256 a, uint256 n) external {
    reserveAsset = a;
    reserveNav = n;
  }
  function reduce(uint256 n) external {
    reserveNav = n;
  }
}
"""

# the coupled fields are function-LOCALS (a balance snapshot + a computed delta), not storage.
_LOCALS = """contract Vault {
  function accrue(uint256 a) external returns (uint256 reserveNav) {
    uint256 reserveAsset = a * 2;
    reserveNav = reserveAsset - 1;
  }
  function reduce(uint256 a) external returns (uint256 reserveNav) {
    reserveNav = a;
  }
}
"""


def _build(src: str) -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    (ws / "Vault.sol").write_text(src)
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("")
    (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({"functions": [
        {"file": "Vault.sol", "function": "accrue", "language": "sol",
         "transfer_hit": True, "ledger_write_evidence": ["reserveAsset", "reserveNav"]},
        {"file": "Vault.sol", "function": "reduce", "language": "sol",
         "transfer_hit": True, "ledger_write_evidence": ["reserveNav"]}]}))
    scg = _load("_sv_scg_" + ws.name, "state-coupling-graph.py")
    scg.main(["--workspace", str(ws), "--emit"])
    return ws


def _cw(ws: Path):
    p = ws / ".auditooor" / "state_coupling_edges.jsonl"
    edges = [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
    return [e for e in edges if e["kind"] == "conserved-with" and e["confidence"] == "semantic-ssa"]


def _acct(ws: Path) -> dict:
    p = ws / ".auditooor" / "state_coupling_conserved_accounting.json"
    return json.loads(p.read_text()) if p.exists() else {}


class TestConservedWithStateVarGate(unittest.TestCase):
    def test_state_var_cells_are_promotable(self):
        cw = _cw(_build(_STORAGE))
        self.assertTrue(cw, "conserved-with must still fire when cells are real state vars")
        self.assertTrue(any(e["evidence"].get("promotable") for e in cw),
                        "both-storage conserved-with must stay promotable")

    def test_local_cells_are_demoted(self):
        cw = _cw(_build(_LOCALS))
        # the edge may still exist as advisory, but must NOT be promotable
        self.assertFalse(any(e["evidence"].get("promotable") for e in cw),
                         "local-only coupled cells must NOT be promotable")
        for e in cw:
            self.assertEqual(e["evidence"].get("demoted_reason"), "local-only-not-state-var")

    # NUVA 2026-07-09 cry-wolf drain: a Solidity surviving set whose cells are ALL
    # function-locals must be counted in surviving_local_pipeline_sets (a quiet, provably
    # not-partial-flushable value pipeline), NOT surviving_conserved_sets (which drives the
    # alarming "re-probe the surviving set(s)" WARN).
    def test_local_pipeline_set_not_counted_as_conserved(self):
        acct = _acct(_build(_LOCALS))
        self.assertEqual(acct.get("surviving_conserved_sets", 0), 0,
                         "an all-local surviving set must NOT inflate surviving_conserved_sets")
        self.assertGreaterEqual(acct.get("surviving_local_pipeline_sets", 0), 1,
                                "an all-local surviving set must land in the local-pipeline bucket")

    def test_state_var_set_still_counted_as_conserved(self):
        acct = _acct(_build(_STORAGE))
        self.assertGreaterEqual(acct.get("surviving_conserved_sets", 0), 1,
                                "a storage-backed surviving set must stay in surviving_conserved_sets")
        self.assertEqual(acct.get("surviving_local_pipeline_sets", 0), 0,
                         "a storage-backed set must NOT be reclassified as a local pipeline")


if __name__ == "__main__":
    unittest.main()
