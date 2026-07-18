#!/usr/bin/env python3
"""Regression: a Solidity cross-domain-conservation edge is PROMOTABLE only when its INTERNAL
cell (cell_a, the share/supply accounting field) is a declared contract-level state variable
(SCC loop, 2026-07-08). Measured FP via the cross-ws sweep: etherfi/morpho cross-domain edges
keyed on function-LOCALS (`uint256 amountForShares = pool.amountForShare(...)`, `repaidShares`)
- a computed local is not a conserved persistent quantity, so pairing it against the external
asset balance is a false coupling. The cross-domain (10th-kind) detector was not state-var
gated like conserved-with (tick-38); this locks the gate."""
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


_SCG = _load("_xd_scg", "state-coupling-graph.py")

# cell_a `shares` is a declared contract STATE VARIABLE -> a real cross-domain obligation.
_STORAGE = """contract Pool {
  uint256 public shares;
  function mint(address to, uint256 amt) external {
    IERC20(asset).transferFrom(msg.sender, address(this), amt);
    shares = shares + amt;
  }
  function badMint(uint256 amt) external {
    shares = shares + amt;
  }
}
"""

# cell_a `shares` only ever appears as a function-LOCAL (never declared at contract scope).
_LOCAL = """contract Pool {
  function mint(address to, uint256 amt) external {
    IERC20(asset).transferFrom(msg.sender, address(this), amt);
    uint256 shares = amt * 2;
    emit Minted(shares);
  }
  function badMint(uint256 amt) external {
    uint256 shares = amt * 2;
    emit Minted(shares);
  }
}
"""


def _build(src: str) -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    (ws / "Pool.sol").write_text(src)
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("")
    (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({"functions": [
        {"file": "Pool.sol", "function": "mint", "language": "sol",
         "transfer_hit": True, "ledger_write_evidence": ["shares"]},
        {"file": "Pool.sol", "function": "badMint", "language": "sol",
         "transfer_hit": False, "ledger_write_evidence": ["shares"]}]}))
    return ws


def _xd(ws: Path):
    edges = _SCG._cross_domain_conservation_edges(ws, acct={})
    return [e for e in edges if e["cell_a"] == "shares"]


class TestCrossDomainStateVarGate(unittest.TestCase):
    def test_state_var_internal_cell_is_promotable(self):
        xd = _xd(_build(_STORAGE))
        self.assertTrue(xd, "a cross-domain edge must fire on the share/transfer asymmetry")
        self.assertTrue(xd[0]["evidence"].get("promotable"),
                        "a state-var internal cell must stay promotable")

    def test_local_internal_cell_is_demoted(self):
        xd = _xd(_build(_LOCAL))
        # the edge may still exist as advisory, but must NOT be promotable
        self.assertTrue(all(not e["evidence"].get("promotable") for e in xd),
                        "a function-local internal cell must NOT be promotable")
        for e in xd:
            self.assertEqual(e["evidence"].get("demoted_reason"), "internal-cell-not-state-var")


if __name__ == "__main__":
    unittest.main()
