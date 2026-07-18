"""
tools/tests/test_invariant_auto_synth_scalar_and_math.py

Guard tests for tools/invariant-auto-synth.py - synth_invariants_sol.

Bug covered (re-verified L2, MED): synth_invariants_sol only emitted invariants
when the mapping-write regex (var[key] = ...) matched. So:

  1. A public/external setter that writes a SCALAR or STRUCT field
     (pendingExitFeeChange = T({...}); acm = x; valuationKeeper = x) produced
     ZERO candidates - no invariant seed at all.
  2. An internal/pure/view value-math helper (AccountingLib.splitValuatedNavOut,
     RoundingGuard.preferOriginalWithin1Wei, UD60x18Ext.max) produced ZERO
     candidates - exactly the NAV-split + 1-wei-rounding surface where ERC-4626
     inflation / insolvency bugs live (Strata 2026-06-30: 8/17 in-scope files
     got no seed, 4 never recovered downstream).

Fix (additive, backward-compatible): add a scalar/struct state-write detector
(emits INV-<fn>-state-write-consistency for public/external fns regardless of
param shape, excluding local `type name =` declarations) and a precision/
rounding candidate for internal/pure/view value-math helpers.

The pre-existing mapping-write / param / modifier / reentrancy candidates are
unchanged.

Lane: bugfix-inventory-claude-20260630
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TOOL = _REPO_ROOT / "tools" / "invariant-auto-synth.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("invariant_auto_synth", str(_TOOL))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["invariant_auto_synth"] = mod
    spec.loader.exec_module(mod)
    return mod


_M = _load_module()


class ScalarStructWriteTest(unittest.TestCase):
    def test_external_scalar_setter_yields_candidate(self):
        """A public/external setter that writes a scalar/struct field (no
        amount/address param shape) must yield >=1 candidate (was zero)."""
        body = "pendingExitFeeChange = Change({v: fee}); acm = msg.sender;"
        cands = _M.synth_invariants_sol(
            "proposeExitFee", "uint256 fee", "external",
            fn_has_modifier=True, body=body, returns="", mutability="")
        self.assertTrue(
            any("state-write-consistency" in c for c in cands),
            f"expected a scalar/struct state-write candidate, got {cands}")

    def test_internal_scalar_write_does_not_emit_external_setter_axis(self):
        """The state-write-consistency axis is for public/external only; an
        internal fn with a scalar write must NOT emit it."""
        body = "valuationKeeper = newKeeper;"
        cands = _M.synth_invariants_sol(
            "_setKeeper", "address newKeeper", "internal",
            fn_has_modifier=False, body=body, returns="", mutability="")
        self.assertFalse(
            any("state-write-consistency" in c for c in cands),
            f"internal fn should not get the external-setter axis, got {cands}")


class ValueMathHelperTest(unittest.TestCase):
    def test_internal_pure_nav_split_yields_precision_candidate(self):
        """An internal pure NAV-split helper (named-return assignments, no real
        state write) must yield a precision/rounding candidate (was zero)."""
        body = (
            "uint256 jrtAvailableNav = a - b;\n"
            "jrtAssetsOut = jrtAssetsOutEffective + jrtLossCoverage;\n"
            "srtAssetsOut = srtAssetsOutEffective - jrtLossCoverage;\n"
            "return (jrtAssetsOut, srtAssetsOut);"
        )
        cands = _M.synth_invariants_sol(
            "splitValuatedNavOut",
            "uint256 jrtBaseNav, uint128 valuationPrice", "internal",
            fn_has_modifier=False, body=body,
            returns="uint256 jrtAssetsOut, uint256 srtAssetsOut",
            mutability="pure")
        self.assertTrue(
            any("precision-rounding" in c for c in cands),
            f"expected a precision/rounding candidate, got {cands}")

    def test_internal_pure_one_wei_rounding_yields_precision_candidate(self):
        body = (
            "uint256 diff = original > candidate ? original - candidate "
            ": candidate - original;\nreturn diff <= 1 ? original : candidate;"
        )
        cands = _M.synth_invariants_sol(
            "preferOriginalWithin1Wei",
            "uint256 original, uint256 candidate", "internal",
            fn_has_modifier=False, body=body, returns="uint256",
            mutability="pure")
        self.assertTrue(
            any("precision-rounding" in c for c in cands),
            f"expected a precision/rounding candidate, got {cands}")

    def test_pure_local_only_helper_does_not_spuriously_fire(self):
        """A pure helper whose name/returns are NOT value-math (only local
        variable arithmetic) must not fire the precision OR scalar-write axes."""
        body = (
            "uint256 sum = a + b;\n"
            "uint256 prod = a * b;\n"
            "return sum;"
        )
        cands = _M.synth_invariants_sol(
            "_combine", "uint256 a, uint256 b", "internal",
            fn_has_modifier=False, body=body, returns="uint256",
            mutability="pure")
        self.assertFalse(
            any("precision-rounding" in c for c in cands),
            f"non-value-math helper should not fire precision axis, got {cands}")
        self.assertFalse(
            any("state-write-consistency" in c for c in cands),
            f"local-var assignments are not state writes, got {cands}")


class BackwardCompatTest(unittest.TestCase):
    def test_mapping_write_candidates_unchanged(self):
        """Pre-existing mapping-write / reentrancy candidates still emit and the
        new axes do not clobber them."""
        body = "balances[from_] -= amount; balances[to] += amount;"
        cands = _M.synth_invariants_sol(
            "transfer", "address to, uint256 amount", "external",
            fn_has_modifier=False, body=body, returns="", mutability="")
        self.assertTrue(any("sum-balances" in c for c in cands),
                        f"mapping-write candidate missing, got {cands}")
        self.assertTrue(any("amount-nonzero" in c for c in cands),
                        f"param candidate missing, got {cands}")

    def test_returns_and_mutability_args_optional(self):
        """The two new parameters are optional (backward-compatible signature)."""
        body = "balances[to] += amount;"
        cands = _M.synth_invariants_sol(
            "transfer", "address to, uint256 amount", "external",
            False, body)
        self.assertTrue(any("sum-balances" in c for c in cands),
                        f"call without new args must still work, got {cands}")


if __name__ == "__main__":
    unittest.main()
