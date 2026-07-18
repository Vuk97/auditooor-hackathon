#!/usr/bin/env python3
"""B1-inc2 residual: CONTRACT-LEVEL (Slither state_variables_written) accumulations must
emit a DISTINCT-flow storage hop (from_var != to_var, capturing the base delta as the flow
source), not an identity hop, so distinct_flow_hops>0 and state-coupling-graph promotes the
co-accumulation conserved-with edge to semantic-ssa.

The committed B1-inc2 (73f30affa3) only populated wexpr for the struct-member (Track-2)
shape; the plain ERC20-shape `totalShares += n; balances[a] += n;` (canonical
sum(balances)==totalShares) was starved because the Track-1 writer tuple passes wexpr=None
(dataflow-slice.py:1096). This test drives the REAL tool over real Solidity (Slither) and
asserts the fix end-to-end.

NON-VACUOUS mutation-pair (a single fixture, both directions bracket the change):
  (A) the co-accumulation cells (`balances[to] += amount; totalShares += amount;`) emit
      distinct-flow storage hops AND the co-accumulation edge promotes to semantic-ssa.
      -> a REGRESSION of the fix (wexpr=None -> _delta=None) drops both hops, the slice's
         distinct_flow_hops go to 0, and the edge falls back to 'syntactic' == this FAILS.
  (B) a plain identity copy `owner = who;` / alias `mirror = totalShares;` gets NO
      distinct-flow hop (it stays an identity hop, silent). -> an OVER-firing variant that
      emitted a distinct hop for a non-accumulation write == this FAILS.
Also exercises the desugared self-accumulation `total = total + amount;` (the `X = X + d`
shape) at the hop-emission level.

Needs solc + slither (skips cleanly if absent). 2026-07-10 (B1-inc2 contract-level track)."""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent
TOOL = _T / "dataflow-slice.py"

_FIXTURE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalShares;
    uint256 public total;
    address public owner;
    uint256 public mirror;
    // A braced block between the mapping decls and mint() so the source-side function
    // parser attributes the accum statements to mint (a `mapping(...) x;` decl otherwise
    // reads as a pseudo-function that swallows the next real function).
    function _noop() internal {}
    function mint(address to, uint256 amount) external {
        balances[to] += amount;   // mapping-indexed member accumulation
        totalShares += amount;    // scalar aggregate accumulation (SAME delta)
        total = total + amount;   // desugared self-accumulation `X = X + delta`
    }
    function readAll(address a) external view returns (uint256, uint256, uint256) {
        return (balances[a], totalShares, total);
    }
    function setRefs(address who) external {
        owner = who;              // identity copy -> must stay identity (silent)
        mirror = totalShares;     // alias copy -> must stay identity (silent)
    }
    function readRefs() external view returns (address, uint256) {
        return (owner, mirror);
    }
}
"""


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _have_toolchain() -> bool:
    if shutil.which("solc") is None or shutil.which("slither") is None:
        return False
    return importlib.util.find_spec("slither") is not None


def _distinct_storage_hops(recs) -> set:
    """(from_var, to_var) of every DISTINCT storage flow hop (from_var != to_var)."""
    out = set()
    for r in recs:
        for h in (r.get("hops") or []):
            if h.get("via") == "storage":
                fv, tv = str(h.get("from_var")), str(h.get("to_var"))
                if fv != tv:
                    out.add((fv, tv))
    return out


def _identity_storage_cells(recs) -> set:
    """to_var of every IDENTITY storage hop (from_var == to_var) - proves the cell IS in
    the slice, so a 'no distinct hop for it' assertion is non-vacuous."""
    out = set()
    for r in recs:
        for h in (r.get("hops") or []):
            if h.get("via") == "storage":
                fv, tv = str(h.get("from_var")), str(h.get("to_var"))
                if fv == tv:
                    out.add(tv)
    return out


@unittest.skipUnless(_have_toolchain(), "requires solc + slither")
class TContractLevelAccumDistinctFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = Path(tempfile.mkdtemp(prefix="b1inc2_"))
        (cls.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (cls.ws / "src").mkdir(parents=True, exist_ok=True)
        cls.sol = cls.ws / "src" / "Vault.sol"
        cls.sol.write_text(_FIXTURE, encoding="utf-8")
        (cls.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            '{"file": "src/Vault.sol"}\n', encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(cls.ws),
             "--target", str(cls.sol), "--mode", "storage", "--json"],
            capture_output=True, text=True, timeout=300)
        assert proc.returncode == 0, f"tool rc={proc.returncode}\n{proc.stderr}\n{proc.stdout}"
        out = cls.ws / ".auditooor" / "dataflow_paths.jsonl"
        assert out.is_file(), f"no slice written: {out}"
        cls.recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        cls.distinct = _distinct_storage_hops(cls.recs)
        cls.identity_cells = _identity_storage_cells(cls.recs)
        cls.scg = _load("state_coupling_graph", "state-coupling-graph.py")

    # ---- (A) the co-accumulation cells emit DISTINCT-flow hops ---------------------
    def test_contract_level_coaccum_emits_distinct_flow_hops(self):
        """`balances[to] += amount; totalShares += amount;` -> two distinct storage hops
        capturing the base delta `amount` as the flow source (NOT identity `X -> X`)."""
        self.assertIn(("amount", "balances"), self.distinct, self.distinct)
        self.assertIn(("amount", "totalShares"), self.distinct, self.distinct)

    def test_desugared_self_accumulation_emits_distinct_flow_hop(self):
        """`total = total + amount;` (the `X = X + delta` shape) also emits (amount,total)."""
        self.assertIn(("amount", "total"), self.distinct, self.distinct)

    # ---- (B) an identity / alias copy stays IDENTITY (silent) ----------------------
    def test_identity_copy_stays_identity_no_distinct_flow(self):
        """`owner = who;` and `mirror = totalShares;` are NOT accumulations: they must get
        NO distinct-flow hop. (Non-vacuous: both cells DO appear as identity storage hops,
        so they were processed - the fix simply did not over-fire a distinct hop.)"""
        distinct_targets = {t for (_f, t) in self.distinct}
        self.assertNotIn("owner", distinct_targets, self.distinct)
        self.assertNotIn("mirror", distinct_targets, self.distinct)
        # proves the assertion is non-vacuous: the cells are present in the slice
        self.assertIn("owner", self.identity_cells, self.identity_cells)
        self.assertIn("mirror", self.identity_cells, self.identity_cells)
        # and no distinct hop names either cell as the flow SOURCE
        distinct_sources = {f for (f, _t) in self.distinct}
        self.assertNotIn("who", distinct_sources, self.distinct)

    # ---- end-to-end: the co-accumulation edge PROMOTES to semantic-ssa -------------
    def test_coaccumulation_edge_promotes_to_semantic_ssa(self):
        """Over the REAL tool-generated slice, the state-coupling-graph co-accumulation
        edge (balances <-> totalShares) is promoted to semantic-ssa (distinct_flow_hops>0
        witnessing the SAME delta `amount` into both cells). A regression of the emit fix
        leaves distinct_flow_hops==0 -> this edge falls back to 'syntactic' and FAILS."""
        scg = self.scg
        links = scg._slice_delta_links(self.ws)
        self.assertIn("mint", links, links)
        self.assertIn(("amount", "balances"), links["mint"], links["mint"])
        self.assertIn(("amount", "totalShares"), links["mint"], links["mint"])
        edges = [e for e in scg._coaccumulation_edges(self.ws)
                 if e["evidence"].get("subtype") == "co-accumulation"]
        by_pair = {(e["evidence"]["member_cell"],
                    e["evidence"]["aggregate_cell"]): e for e in edges}
        self.assertIn(("balances", "totalShares"), by_pair, by_pair.keys())
        e = by_pair[("balances", "totalShares")]
        self.assertEqual(e["confidence"], "semantic-ssa", e)
        self.assertTrue(e["evidence"]["promotable"], e)


if __name__ == "__main__":
    unittest.main()
