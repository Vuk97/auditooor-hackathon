#!/usr/bin/env python3
"""Plant-a-bug regression for the SEMANTIC ORDERING shape (SCC loop, 2026-07-08) - the last
canonical shape at semantic tier. Anchored on corpus tier-2 INV-ORD-001 ("W1,W2 where W2
depends on W1 committed MUST have no intervening external call"), INV-ORD-005 (CEI),
INV-BRIDGE-003. The detector fires when a Solidity fn writes TWO COUPLED persistent cells
with an EXTERNAL CALL textually between the writes and NO nonReentrant guard - a reentrant
callee observes the coupled invariant transiently half-updated (reentrancy-on-coupled-invariant).

Asserts from SOURCE (real VMF -> SCG): the non-atomic plant fires a promotable semantic-ssa
`ordering` edge that reaches the exploit-queue; the nonReentrant variant and the
writes-before-call variant emit ZERO ordering edges (no FP - the reason a naive write-order
heuristic was deferred). Distinct from generic CEI: fires ONLY on a conserved/coupled set."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent

_FIRE = """contract Vault {
  uint256 public reserveShares;
  uint256 public stakedShares;
  function redeem(address to, uint256 amt) external {
    reserveShares = reserveShares - amt;
    (bool ok,) = to.call{value: amt}("");
    require(ok);
    stakedShares = stakedShares - amt;
  }
}
"""

_SAFE_NONREENTRANT = _FIRE.replace("external {", "external nonReentrant {")

_SAFE_WRITES_BEFORE_CALL = """contract Vault {
  uint256 public reserveShares;
  uint256 public stakedShares;
  function redeem(address to, uint256 amt) external {
    reserveShares = reserveShares - amt;
    stakedShares = stakedShares - amt;
    (bool ok,) = to.call{value: amt}("");
    require(ok);
  }
}
"""

# FP class drained 2026-07-08 (etherfi LiquidRefer.deposit): the "coupled cells" were a NAMED
# RETURN (`returns (uint256 shares)`) and a LOCAL declaration (`address vault = teller.vault()`),
# not persistent storage - no cross-tx invariant a reentrant callee can observe. Must NOT fire.
_FP_LOCALS = """contract Refer {
  function deposit(address teller, uint256 amt) external returns (uint256 shares) {
    address vault = ITeller(teller).vault();
    IERC20(vault).safeTransferFrom(msg.sender, address(this), amt);
    shares = ITeller(teller).deposit(amt);
    IERC20(vault).safeTransfer(msg.sender, shares);
  }
}
"""


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


def _build_ws(src: str, fn: str = "redeem",
              cells=("reserveShares", "stakedShares")) -> Path:
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir()
    (ws / "src").mkdir()
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("")
    (ws / "src" / "Vault.sol").write_text(src)
    (ws / ".auditooor" / "value_moving_functions.json").write_text(json.dumps({"functions": [
        {"file": "src/Vault.sol", "function": fn, "language": "sol",
         "transfer_hit": True, "ledger_write_evidence": list(cells)}]}))
    scg = _load("_ord_scg_" + ws.name, "state-coupling-graph.py")
    scg.main(["--workspace", str(ws), "--emit"])
    return ws


def _ordering_edges(ws: Path):
    p = ws / ".auditooor" / "state_coupling_edges.jsonl"
    edges = [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
    return [e for e in edges if e["kind"] == "ordering" and e["confidence"] == "semantic-ssa"]


class TestOrderingSemanticPlant(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fire = _build_ws(_FIRE)
        cls.safe_nr = _build_ws(_SAFE_NONREENTRANT)
        cls.safe_ord = _build_ws(_SAFE_WRITES_BEFORE_CALL)
        cls.fp_locals = _build_ws(_FP_LOCALS, fn="deposit", cells=("shares", "vault"))

    def test_1_fires_promotable_semantic_ordering_edge(self):
        e = _ordering_edges(self.fire)
        self.assertTrue(e, "external call between two coupled writes must fire a semantic ordering edge")
        self.assertEqual({e[0]["cell_a"], e[0]["cell_b"]}, {"reserveShares", "stakedShares"})
        self.assertTrue(e[0]["evidence"]["promotable"])
        self.assertEqual(e[0]["evidence"]["tier"], "reentrancy-ordering-coupled-writes")
        self.assertTrue(any(v["fn"] == "redeem" for v in e[0]["violators"]))

    def test_2_nonreentrant_does_not_fire(self):
        self.assertEqual(_ordering_edges(self.safe_nr), [],
                         "a nonReentrant fn closes the reentrancy window - must NOT fire")

    def test_3_writes_before_call_does_not_fire(self):
        self.assertEqual(_ordering_edges(self.safe_ord), [],
                         "both coupled writes committed BEFORE the external call - must NOT fire")

    def test_5_local_and_named_return_cells_do_not_fire(self):
        # etherfi LiquidRefer FP: named return `shares` + local `address vault = ...` are not
        # persistent storage, so there is no reentrancy-observable coupled invariant.
        self.assertEqual(_ordering_edges(self.fp_locals), [],
                         "local/named-return 'cells' must NOT fire (etherfi FP class)")

    def test_4_lead_reaches_exploit_queue(self):
        eq = _load("_ord_eq", "exploit-queue.py")
        rows = [r for r in eq._gather_from_state_coupling(self.fire) if "SCG" in r.get("lead_id", "")]
        ordering = [r for r in rows if "ordering" in json.dumps(r).lower()]
        self.assertTrue(ordering, "the planted ordering lead must reach the exploit-queue (not an orphan)")


if __name__ == "__main__":
    unittest.main()
