#!/usr/bin/env python3
"""A13 CROSS-CONTRACT CONSERVATION (12th SCG kind) regression.

The ACCOUNTED-TOTAL identity that SPANS CONTRACTS: a cell fed by an EXTERNAL-call return
(strategy.totalAssets / cdo.totalStrategyAssets) that ONE fn splits into >=2 PERSISTENT
tranche/reserve state cells; the whole-system invariant is sum(split) == external total,
and a writer touching a strict subset desyncs the tranches from the total.

DEDUP BOUNDARY (A1): the intra-contract conserved-with lane (VMF ledger_write_evidence)
STRUCTURALLY misses this - measured on strata, VMF sees updateAccountingInner's writes as
just ['reserveNav'], never the jrtNav/srtNav/nav split nor the external-call origination.

Covers:
  1. SYNTHETIC clean/vulnerable pair (primary mutation-kill): the clean full-writer emits an
     edge with ZERO subset-violators; the vulnerable variant (a strict-subset skim writer)
     emits the SAME edge WITH a violator -> the promotable desync lead.
  2. FP-guards: a non-total external read (vault.deposit) does NOT seed a total; a rate/config
     split cell (feeBps) is dropped; a view/pure split (named returns) does NOT fire.
  3. NATURAL instance on the real strata WS (read-only): fires on Accounting.sol with
     total_cell=nav, split={jrtNav,srtNav,reserveNav}, param-fed external origin.
  4. MUTATION-VERIFY on a mkdtemp COPY of the real strata target file (shared WS never
     git-mutated): the CLEAN copy does NOT list the full-set writer updateAccountingInner as
     a violator; the MUTANT copy (a behaviour-changing partial-flush that drops the reserveNav
     write) DOES -> mutation-kill.
  5. DEDUP: the A13 conserved_set is NOT emitted by the conserved-with VMF lane.
"""
import importlib.util
import json
import os
import shutil
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


scg = _load("state_coupling_graph", "state-coupling-graph.py")
scs = _load("state_coupling_schema", "state_coupling_schema.py")

_REAL_STRATA = Path("/Users/wolf/audits/strata")
_STRATA_ACCT = _REAL_STRATA / "src/contracts/contracts/tranches/Accounting.sol"


def _mk_ws(files: dict) -> Path:
    """Build a throwaway ws with .auditooor/inscope_units.jsonl + the given rel->src files."""
    ws = Path(tempfile.mkdtemp())
    (ws / ".auditooor").mkdir(parents=True)
    lines = []
    for rel, src in files.items():
        fp = ws / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(src, encoding="utf-8")
        lines.append(json.dumps({"file": rel, "unit": f"{rel}::fn"}))
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("\n".join(lines) + "\n")
    return ws


# ---- SYNTHETIC clean/vulnerable pair (a faithful tranche-splitter idiom) --------------
_CLEAN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrategy { function totalAssets() external view returns (uint256); }

contract TrancheSplitter {
    IStrategy public strategy;
    uint256 public seniorAssets;
    uint256 public juniorAssets;
    uint256 public totalAssetsMirror;

    // ACCOUNTED-TOTAL split: t (external total) -> senior + junior; sum == t.
    function sync() external {
        uint256 t = strategy.totalAssets();
        totalAssetsMirror = t;
        seniorAssets = t / 2;
        juniorAssets = t - seniorAssets;
    }
}
"""

# vulnerable = clean + a STRICT-SUBSET writer that skims senior without touching junior.
_VULN = _CLEAN.replace(
    "}\n",
    """
    // partial-update: touches seniorAssets only -> desyncs sum(senior+junior) from total.
    function skimSenior(uint256 amt) external {
        seniorAssets = seniorAssets - amt;
    }
}
""", 1)

# FP fixture: external read is NOT a total (vault.deposit), and a rate split cell (feeBps).
_FP = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVault { function deposit(uint256 a) external returns (uint256); }

contract NotAConservation {
    IVault public vault;
    uint256 public shares;
    uint256 public feeBps;

    function pull(uint256 a) external {
        uint256 r = vault.deposit(a);      // NOT a total-read -> no accounted-total seed
        shares = r;
        feeBps = r / 100;                  // rate field -> dropped by the value-cell guard
    }
}
"""


def _acct_edge(edges):
    """The single cross-contract edge (there is one per fixture)."""
    xs = [e for e in edges if e.get("evidence", {}).get("tier") == "cross-contract-conservation"]
    return xs


class A13CrossContractConservation(unittest.TestCase):

    def test_clean_emits_edge_with_no_subset_violator(self):
        ws = _mk_ws({"src/TrancheSplitter.sol": _CLEAN})
        edges = _acct_edge(scg._cross_contract_conservation_edges(ws))
        self.assertEqual(len(edges), 1, "clean must still detect the conservation coupling")
        e = edges[0]
        self.assertEqual(sorted(e["evidence"]["conserved_set"]),
                         ["juniorAssets", "seniorAssets"])
        self.assertEqual(e["evidence"]["total_mirror_cell"], "totalAssetsMirror")
        self.assertTrue(e["evidence"]["promotable"])
        self.assertEqual(e["evidence"]["verdict"], "needs-fuzz")
        self.assertFalse(e["evidence"]["auto_credit"])
        # BENIGN CLEAN: no writer touches a STRICT subset -> zero desync leads.
        self.assertEqual(e["evidence"]["nviol"], 0, "clean has no subset-writer desync")
        self.assertEqual(e["violators"], [])
        # schema-valid + surfaced by read_edges (kind registered).
        ok, errs = scs.validate(e)
        self.assertTrue(ok, errs)
        shutil.rmtree(ws, ignore_errors=True)

    def test_vulnerable_fires_subset_violator(self):
        ws = _mk_ws({"src/TrancheSplitter.sol": _VULN})
        edges = _acct_edge(scg._cross_contract_conservation_edges(ws))
        self.assertEqual(len(edges), 1)
        e = edges[0]
        # MUTATION FIRED: the skim writer is a strict-subset violator.
        self.assertGreaterEqual(e["evidence"]["nviol"], 1)
        viol_fns = {v["fn"] for v in e["violators"]}
        self.assertIn("skimSenior", viol_fns)
        sk = [v for v in e["violators"] if v["fn"] == "skimSenior"][0]
        self.assertEqual(sk["mutates"], ["seniorAssets"])
        self.assertEqual(sk["omits"], ["juniorAssets"])
        shutil.rmtree(ws, ignore_errors=True)

    def test_fp_guards_non_total_read_and_rate_cell(self):
        ws = _mk_ws({"src/NotAConservation.sol": _FP})
        edges = _acct_edge(scg._cross_contract_conservation_edges(ws))
        self.assertEqual(edges, [], "non-total external read + rate cell must not fire")
        shutil.rmtree(ws, ignore_errors=True)

    def test_view_split_named_returns_do_not_fire(self):
        # a pure/view fn that "splits" a total into NAMED RETURNS is not a persistent split.
        src = _CLEAN.replace(
            "function sync() external {",
            "function preview() external view returns (uint256 a, uint256 b) {\n"
            "        uint256 tv = strategy.totalAssets();\n"
            "        a = tv / 2; b = tv - a; return (a, b);\n"
            "    }\n\n    function sync() external {")
        ws = _mk_ws({"src/TrancheSplitter.sol": src})
        edges = _acct_edge(scg._cross_contract_conservation_edges(ws))
        # only the real persistent `sync` split fires; the view `preview` (named returns) does not.
        fns = {e["evidence"]["split_fn"] for e in edges}
        self.assertNotIn("preview", fns)
        self.assertIn("sync", fns)
        shutil.rmtree(ws, ignore_errors=True)

    @unittest.skipUnless(_STRATA_ACCT.is_file(), "real strata ws not present")
    def test_natural_instance_strata(self):
        """Read-only confirmation on the real ws (never mutated)."""
        edges = _acct_edge(scg._cross_contract_conservation_edges(_REAL_STRATA))
        acct = [e for e in edges
                if e["violators"] and "tranches/Accounting.sol" in e["violators"][0]["file"]]
        self.assertTrue(acct, "A13 must fire on the real strata Accounting split")
        e = acct[0]
        self.assertEqual(sorted(e["evidence"]["conserved_set"]),
                         ["jrtNav", "reserveNav", "srtNav"])
        self.assertEqual(e["evidence"]["total_mirror_cell"], "nav")
        self.assertEqual(e["evidence"]["external_total_origin"], "param-fed")
        self.assertTrue(e["evidence"]["promotable"])
        # the full-set writer is NOT a violator; the asymmetric updateBalanceFlow IS.
        vfns = {v["fn"] for v in e["violators"]}
        self.assertNotIn("updateAccountingInner", vfns)
        self.assertIn("updateBalanceFlow", vfns)

    @unittest.skipUnless(_STRATA_ACCT.is_file(), "real strata ws not present")
    def test_mutation_verify_on_mkdtemp_copy(self):
        """cp the shared-ws target to a mkdtemp, inject a behaviour-changing partial-flush and
        confirm the MUTANT fires (the mutated writer becomes a subset-violator) while the CLEAN
        copy does NOT. The shared strata ws is NEVER git-mutated (only the mkdtemp copy).

        MUTATION: reduceReserve credits BOTH tranches (jrtNav += / srtNav +=) plus reserveNav,
        so on the clean copy it is a FULL-set writer (not a desync). Dropping its jrtNav credit
        makes it write a STRICT subset {srtNav,reserveNav} of the coupled set defined by the
        untouched master writer updateAccountingInner -> a real cross-contract-conservation
        desync (reduce credits senior+reserve but drops junior). The coupled set is stable
        (updateAccountingInner is untouched), so the discriminator is clean."""
        clean_src = _STRATA_ACCT.read_text()
        self.assertIn("        jrtNav += jrtAmountIn;\n", clean_src)
        mutant_src = clean_src.replace("        jrtNav += jrtAmountIn;\n", "", 1)
        self.assertNotEqual(clean_src, mutant_src, "mutation must change the source")

        rel = "Accounting.sol"

        def _reduce_is_violator(src_text):
            ws = _mk_ws({rel: src_text})
            edges = _acct_edge(scg._cross_contract_conservation_edges(ws))
            hit = [e for e in edges
                   if sorted(e["evidence"]["conserved_set"]) == ["jrtNav", "reserveNav", "srtNav"]]
            self.assertTrue(hit, "the nav split edge must be present in both copies")
            vfns = {v["fn"] for v in hit[0]["violators"]}
            shutil.rmtree(ws, ignore_errors=True)
            return "reduceReserve" in vfns

        clean_fires = _reduce_is_violator(clean_src)
        mutant_fires = _reduce_is_violator(mutant_src)
        self.assertFalse(clean_fires, "CLEAN: full-set writer reduceReserve must NOT be a violator")
        self.assertTrue(mutant_fires, "MUTANT: partial-flush reduceReserve MUST be a violator")

    @unittest.skipUnless(
        (_REAL_STRATA / ".auditooor" / "value_moving_functions.json").is_file(),
        "strata VMF not present")
    def test_dedup_distinct_from_conserved_with(self):
        """The A13 conserved_set {jrtNav,srtNav,reserveNav} is NOT re-derived by the
        conserved-with VMF lane (which sees updateAccountingInner as only ['reserveNav'])."""
        vmf = json.loads((_REAL_STRATA / ".auditooor" / "value_moving_functions.json")
                         .read_text())
        uai = [f for f in vmf["functions"] if f.get("function") == "updateAccountingInner"]
        self.assertTrue(uai)
        # VMF cannot see the full split -> the conserved-with lane structurally misses it.
        self.assertLess(len(uai[0].get("ledger_write_evidence", [])), 3,
                        "if VMF saw the whole split this dimension would not be net-new")


if __name__ == "__main__":
    unittest.main()
