#!/usr/bin/env python3
"""test_per_fn_hacker_questions_inscope_fallback.py

Guard test for the L2/L3 RESIDUAL fix on the in-scope supplemental pass.

The supplemental pass calls ``_render_impact_for_fn`` for in-scope units not
covered by an invariant row. But ``_render_impact_for_fn`` returns [] for an
unclassified internal-pure leaf helper (e.g. UD60x18Ext.max,
RoundingGuard / AccountingLib leaf math, ChainlinkAprProviderLib). Without the
fix those in-scope value-mover-adjacent helpers STILL reached the hunt with ZERO
questions.

After the fix, when ``_render_impact_for_fn`` attaches nothing for an in-scope
unit that is NOT scope-excluded, the supplemental pass emits at least ONE generic
impact-methodology fallback row (``question_source: impact-methodology-fallback``,
empty ``impact_id`` / ``kill_condition``). This test asserts:

  1. an in-scope leaf math helper that ``_render_impact_for_fn`` classifies as []
     STILL gets >=1 fallback question (keyed to the unit);
  2. an OOS / mutation-artifact unit still gets NONE;
  3. an invariant-covered unit is unaffected (no fallback row, invariant rows
     still emit).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent


def _load_tool():
    modname = "per_function_hacker_questions_fallback_under_test"
    if modname in sys.modules:
        return sys.modules[modname]
    spec = importlib.util.spec_from_file_location(
        modname, TOOLS / "per-function-hacker-questions.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


_SCOPE_MD = "# Scope\nERC-4626 vault tranche accounting. NAV split, deposit, redeem.\n"

# A value-moving function (covered by the one invariant row).
_INVAR_SIG = ("function deposit(uint256 assets, address receiver) "
              "external returns (uint256 shares)")
# An internal-pure leaf math helper the impact renderer classifies as [] (verified
# by _render_impact_for_fn returning no rows for it).
_LEAF_SIG = "function max(UD60x18 a, UD60x18 b) internal pure returns (UD60x18)"


class InscopeFallbackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_tool()
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (self.ws / "SCOPE.md").write_text(_SCOPE_MD, encoding="utf-8")

        self.inv_path = self.ws / "invariants.jsonl"
        inv_rec = {
            "function": "deposit",
            "file": "src/Vault.sol",
            "language": "solidity",
            "signature": _INVAR_SIG,
            "invariant_candidates": ["amount-nonzero", "reentrancy-check"],
        }
        self.inv_path.write_text(json.dumps(inv_rec) + "\n", encoding="utf-8")

        units = [
            {"file": "src/Vault.sol", "function": "deposit",
             "lang": "solidity", "signature": _INVAR_SIG},
            # in-scope leaf math helper: _render_impact_for_fn -> [].
            {"file": "src/UD60x18Ext.sol", "function": "max",
             "lang": "solidity", "signature": _LEAF_SIG},
            # mutation-artifact: must be EXCLUDED even though it is a leaf helper.
            {"file": "src/UD60x18ExtMutantA.sol", "function": "max",
             "lang": "solidity", "signature": _LEAF_SIG},
        ]
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "\n".join(json.dumps(u) for u in units) + "\n", encoding="utf-8")

        self.out_path = self.ws / "questions.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self) -> list[dict]:
        rc = self.mod.main([
            "--invariants", str(self.inv_path),
            "--output", str(self.out_path),
            "--workspace", str(self.ws),
        ])
        self.assertEqual(rc, 0, "main() should succeed")
        recs = []
        with self.out_path.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
        return recs

    # --------------------------------------------------------------- precondition
    def test_renderer_returns_empty_for_leaf_helper(self) -> None:
        # Confirms the bug precondition: the renderer attaches nothing for the
        # internal-pure leaf helper, so without the fallback it would reach the
        # hunt with zero questions.
        rec = {"function": "max", "file": "src/UD60x18Ext.sol",
               "language": "solidity", "signature": _LEAF_SIG}
        imp = self.mod._render_impact_for_fn(rec, _SCOPE_MD, 8)
        self.assertEqual(
            imp, [],
            "precondition: leaf helper must render no impact rows for this test "
            "to exercise the fallback")

    # -------------------------------------------------------------- assertions
    def test_leaf_helper_gets_fallback_question(self) -> None:
        recs = self._run()
        leaf = [r for r in recs
                if r.get("function") == "max"
                and r.get("file") == "src/UD60x18Ext.sol"]
        self.assertGreater(
            len(leaf), 0,
            "in-scope leaf helper with empty render must still get >=1 question")
        fallback = [r for r in leaf
                    if r.get("question_source") == "impact-methodology-fallback"]
        self.assertGreater(
            len(fallback), 0,
            "the leaf helper's question must be a fallback row")
        for r in fallback:
            self.assertEqual(r.get("impact_id"), "")
            self.assertEqual(r.get("kill_condition"), "")
            self.assertTrue(str(r.get("question") or "").strip())

    def test_oos_mutation_artifact_gets_no_fallback(self) -> None:
        recs = self._run()
        oos = [r for r in recs
               if r.get("file") == "src/UD60x18ExtMutantA.sol"]
        self.assertEqual(
            oos, [],
            "a mutation-artifact / OOS unit must NOT get a fallback question")

    def test_invariant_covered_unit_unaffected(self) -> None:
        recs = self._run()
        # No fallback row for the invariant-covered deposit unit.
        deposit_fallback = [
            r for r in recs
            if r.get("function") == "deposit"
            and r.get("question_source") == "impact-methodology-fallback"]
        self.assertEqual(
            deposit_fallback, [],
            "invariant-covered unit must not receive a fallback row")
        # Invariant-driven rows still emit (backward-compatible).
        deposit_inv = [r for r in recs
                       if r.get("function") == "deposit"
                       and r.get("question_source") != "impact-methodology-fallback"]
        self.assertGreater(len(deposit_inv), 0)

    def test_no_sidecar_is_noop(self) -> None:
        (self.ws / ".auditooor" / "inscope_units.jsonl").unlink()
        recs = self._run()
        fallback = [r for r in recs
                    if r.get("question_source") == "impact-methodology-fallback"]
        self.assertEqual(
            fallback, [],
            "absent the sidecar, no fallback questions are emitted")


if __name__ == "__main__":
    unittest.main()
