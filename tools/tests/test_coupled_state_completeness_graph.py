#!/usr/bin/env python3
"""Regression tests for tools/coupled-state-completeness-graph.py.

Proves the coupled-state completeness set/closure-difference query
(FLUSHED(P) proper-subset FULL(G) across sibling paths) is:
  - a SET relation whose predicate DISCRIMINATES: a path that flushes only a
    SUBSET of a coupled must-move-together group is a SURVIVOR; the SAME path once
    the missing coupled write is added is NO LONGER a survivor (the NON-VACUITY
    MUTATION case - the asymmetry is load-bearing, not the trivial "all touchers");
  - TRANSITIVE: a coupled member flushed N hops deep in a helper credits FLUSHED(P)
    and removes the survivor (impossible for a body-scoped regex);
  - GROUNDED: a group is only formed with a full-flush WITNESS sibling; two
    independent fields with no full-flush witness produce NO survivor;
  - HONEST on class-absence: a repo with no witnessed coupled group reports
    class_present False + a cited-empty (distinct from a vacuous 0-fn substrate).
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "coupled-state-completeness-graph.py"
_spec = importlib.util.spec_from_file_location("coupled_state", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# A synthetic Solidity-style vault. The coupled group is {totalShares, totalAssets}
# (stem-seed "total" + co-write across siblings). deposit() and withdraw() flush
# BOTH (full-flush witnesses). skim() flushes ONLY totalAssets -> SURVIVOR
# (missing totalShares). syncShares() flushes ONLY totalShares.
_VAULT_SUBSET = """
contract Vault {
    uint256 totalShares;
    uint256 totalAssets;
    uint256 unrelated;

    function deposit(uint256 a) external {
        totalAssets = totalAssets + a;
        totalShares = totalShares + a;
    }

    function withdraw(uint256 a) external {
        totalAssets = totalAssets - a;
        totalShares = totalShares - a;
    }

    function skim(uint256 a) external {
        totalAssets = totalAssets + a;
    }

    function poke(uint256 u) external {
        unrelated = u;
    }
}
"""

# The MUTATION: skim now ALSO writes totalShares (full flush) -> survivor gone.
_VAULT_FULLFLUSH = _VAULT_SUBSET.replace(
    "    function skim(uint256 a) external {\n"
    "        totalAssets = totalAssets + a;\n"
    "    }",
    "    function skim(uint256 a) external {\n"
    "        totalAssets = totalAssets + a;\n"
    "        totalShares = totalShares + a;\n"
    "    }")

# Transitive: skim flushes the missing member via a HELPER N hops deep.
_VAULT_TRANSITIVE = _VAULT_SUBSET.replace(
    "    function skim(uint256 a) external {\n"
    "        totalAssets = totalAssets + a;\n"
    "    }",
    "    function skim(uint256 a) external {\n"
    "        totalAssets = totalAssets + a;\n"
    "        _bumpShares(a);\n"
    "    }\n"
    "    function _bumpShares(uint256 a) internal {\n"
    "        totalShares = totalShares + a;\n"
    "    }")

# No full-flush witness: totalShares and totalAssets are never both written by any
# single path (each sibling writes exactly one) -> group has no witness -> NO
# survivor (grounding guard: an asymmetry needs a canonical full-flush proof).
_VAULT_NO_WITNESS = """
contract Vault {
    uint256 totalShares;
    uint256 totalAssets;
    function a1() external { totalAssets = 1; }
    function a2() external { totalAssets = 2; }
    function s1() external { totalShares = 1; }
    function s2() external { totalShares = 2; }
}
"""


def _run(src_text, fname="Vault.sol", **kw):
    with tempfile.TemporaryDirectory() as d:
        ws = Path(d)
        (ws / fname).write_text(src_text)
        emit = ws / "out.jsonl"
        argv = ["--workspace", str(ws), "--src-root", str(ws),
                "--emit", str(emit), "--json"]
        summary = mod.run(argv)
        obs = []
        if emit.is_file():
            obs = [json.loads(l) for l in emit.read_text().splitlines() if l.strip() and "examined_record" not in l]
        return summary, obs


class CoupledStateCompletenessTest(unittest.TestCase):

    def test_proper_subset_path_is_survivor(self):
        summary, obs = _run(_VAULT_SUBSET)
        surv_fns = {s["fn"] for s in summary["survivors"]}
        self.assertIn("skim", surv_fns,
                      "skim flushes only totalAssets of a coupled group -> survivor")
        self.assertTrue(summary["class_present"])
        skim_ob = next(o for o in obs if o["function"] == "skim")
        self.assertIn("totalShares", skim_ob["missing_components"])
        self.assertIn("totalAssets", skim_ob["flushed_subset"])
        self.assertEqual(skim_ob["schema"], "auditooor.coupled_state_completeness.v1")
        self.assertTrue(skim_ob["source_refs"])
        self.assertIn("Vault.sol", skim_ob["source_refs"][0])

    def test_full_flush_mutation_removes_survivor(self):
        # NON-VACUITY: add the missing coupled write to skim -> survivor disappears.
        base, _ = _run(_VAULT_SUBSET)
        mutated, _ = _run(_VAULT_FULLFLUSH)
        self.assertIn("skim", {s["fn"] for s in base["survivors"]})
        self.assertNotIn("skim", {s["fn"] for s in mutated["survivors"]},
                         "once skim flushes the full group it is no longer a survivor")

    def test_transitive_helper_flush_removes_survivor(self):
        # A coupled member flushed via a helper N hops deep credits FLUSHED(P).
        summary, _ = _run(_VAULT_TRANSITIVE)
        self.assertNotIn("skim", {s["fn"] for s in summary["survivors"]},
                         "transitive flush through _bumpShares kills the survivor")

    def test_no_full_flush_witness_yields_no_survivor(self):
        # Grounding: without a full-flush witness the group is not proven coupled-as-
        # unit, so no asymmetry is claimed (honest, not a false positive).
        summary, obs = _run(_VAULT_NO_WITNESS)
        self.assertEqual(summary["n_survivors"], 0)
        self.assertEqual(obs, [])
        self.assertFalse(summary["class_present"])
        self.assertTrue(summary["honest_empty_class_not_present"])

    def test_unrelated_field_not_in_group(self):
        # A field a single fn writes and no sibling co-writes must not join a group.
        summary, _ = _run(_VAULT_SUBSET)
        for g in summary["groups"]:
            self.assertNotIn("unrelated", g["members"])

    def test_vacuous_substrate_flagged_not_honest_empty(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)  # no source files at all
            argv = ["--workspace", str(ws), "--src-root", str(ws),
                    "--emit", str(ws / "o.jsonl"), "--json"]
            summary = mod.run(argv)
            self.assertTrue(summary["substrate_vacuous"])
            self.assertEqual(summary["n_functions_indexed"], 0)


if __name__ == "__main__":
    unittest.main()
