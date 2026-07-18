#!/usr/bin/env python3
"""Inter-procedural (transitive-ext) same-fn-CEI recognition - Glider gap W4.

Conservative enhancement of ``intra_fn_cei`` (tools/slither_predicates.py): an
INTERNAL-call node whose callee-closure contains a GENUINE external call is treated
as ext-bearing, so the cross-fn "ext-via-internal-helper THEN write-in-caller"
reentrancy slice (which the direct ``_node_is_external_call`` walk misses) is caught.

ADDITIVE-ONLY: a DIRECT external-call lead is byte-identical to the legacy dict; only
a TRANSITIVE marker adds ``via`` + ``transitive`` provenance. This file PINS:

  - W4-1 ``interproc_cei_via_helper_suspect``     -> FLAGGED, transitive=True, via=_doCall.
  - W4-2 ``interproc_cei_helper_before_write_clean`` -> NOT flagged (write before the
                                                       transitive ext; never-FP).
  - W4-3 ``interproc_cei_guarded_clean``          -> NOT flagged (nonReentrant guard).
  - W4-4 ``interproc_cei_internal_no_ext_clean``  -> NOT flagged (internal call is not
                                                       ext-bearing).
  - MUTATION non-vacuity: removing the external call from the helper flips W4-1
    FLAGGED -> clean.
  - ADDITIVE proof: the 3 gap#5 fixtures produce byte-identical ``intra_fn_cei``
    output (direct-ext leads gain NO ``via``/``transitive`` key).

W4 FP-fix (CEI-scoped external-call recognition): the CEI oracle counts an external
call ONLY when it is STATE-MUTATING (could reenter-and-write). A ``view``/``pure``
call compiles to a STATICCALL and CANNOT reenter, so a state-write after it is
CEI-SAFE. This file additionally PINS:

  - FP-fix #1 ``cei_view_call_then_write_clean``         -> NOT flagged (direct view).
  - FP-fix #2 ``interproc_cei_view_via_helper_clean``    -> NOT flagged (view via helper).
  - FP-fix #3 ``interproc_cei_pure_lib_via_helper_clean``-> NOT flagged (pure lib via helper).
  - FP-fix #4 ``interproc_cei_unknown_mutability_via_helper_suspect`` -> STILL FLAGGED
    (CONSERVATIVE never-MISS: only a POSITIVELY view/pure target is excluded; an
    UNKNOWN / non-view target is treated as state-mutating).

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass).
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "callgraph_closure"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_sp():
    spec = importlib.util.spec_from_file_location(
        "slither_predicates", TOOLS / "slither_predicates.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sp = _load_sp()


def _slither_available() -> bool:
    try:
        import slither  # noqa: F401

        return True
    except Exception:
        return False


SKIP_NO_SLITHER = unittest.skipUnless(
    _slither_available(),
    "slither-analyzer not importable; transitive-CEI tests need a real compile",
)


def _compile(path: pathlib.Path):
    from slither import Slither

    return Slither(str(path))


def _get_fn(sl, cname, fname):
    for c in sl.contracts:
        if c.name == cname:
            for f in c.functions:
                if f.name == fname:
                    return c, f
    return None, None


# --- Degrade path (no Slither needed) ----------------------------------------


class TransitiveExtDegradeTest(unittest.TestCase):
    """R80: a non-navigable input never crashes and is treated as non-ext."""

    class _Dummy:
        pass

    def test_closure_reaches_external_false_on_dummy(self):
        self.assertFalse(sp._closure_reaches_external(self._Dummy()))

    def test_call_node_reaches_external_none_on_bare_object(self):
        # A bare object is neither a direct ext-call node nor has internal_calls.
        self.assertIsNone(sp._call_node_reaches_external(object()))


# --- Semantic path: transitive-ext recognition --------------------------------


@SKIP_NO_SLITHER
class TransitiveCeiOracleTest(unittest.TestCase):
    def test_w4_1_via_helper_is_suspect_with_provenance(self):
        sl = _compile(FX / "interproc_cei_via_helper_suspect.sol")
        _, fn = _get_fn(sl, "InterprocCeiViaHelperSuspect", "withdraw")
        res = sp.intra_fn_cei(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1, "transitive ext-via-helper-then-write not flagged")
        lead = res[0]
        self.assertEqual(lead["var"], "balances")
        self.assertTrue(lead.get("transitive") is True, "missing transitive provenance")
        self.assertEqual(lead.get("via"), "_doCall")
        self.assertIsNotNone(lead["ext_call_line"])
        self.assertIsNotNone(lead["state_write_line"])
        self.assertGreater(lead["state_write_line"], lead["ext_call_line"])

    def test_w4_2_helper_before_write_never_fp(self):
        sl = _compile(FX / "interproc_cei_helper_before_write_clean.sol")
        _, fn = _get_fn(sl, "InterprocCeiHelperBeforeWriteClean", "withdraw")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_w4_3_guarded_never_fp(self):
        sl = _compile(FX / "interproc_cei_guarded_clean.sol")
        _, fn = _get_fn(sl, "InterprocCeiGuardedClean", "withdraw")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_w4_4_internal_no_ext_never_fp(self):
        sl = _compile(FX / "interproc_cei_internal_no_ext_clean.sol")
        _, fn = _get_fn(sl, "InterprocCeiInternalNoExtClean", "withdraw")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_w4_1_closure_intra_cei_surfaces_at_caller(self):
        # The transitive lead is found in withdraw()'s OWN body walk, so the closure
        # variant anchors at_fn = withdraw (own-body-first).
        sl = _compile(FX / "interproc_cei_via_helper_suspect.sol")
        _, fn = _get_fn(sl, "InterprocCeiViaHelperSuspect", "withdraw")
        res = sp.closure_intra_fn_cei(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["at_fn"], "withdraw")
        self.assertEqual(res[0].get("via"), "_doCall")


# --- ADDITIVE-ONLY proof: gap#5 fixtures byte-identical ------------------------


@SKIP_NO_SLITHER
class Gap5AdditiveByteIdenticalTest(unittest.TestCase):
    """The 3 gap#5 fixtures must produce IDENTICAL intra_fn_cei output - a DIRECT-ext
    lead gains NO via/transitive key (the enhancement only ADDS new transitive flags,
    never changes/removes a direct flag)."""

    def test_gap5_a_direct_ext_unchanged_no_provenance(self):
        sl = _compile(FX / "cei_ext_then_write_suspect.sol")
        _, fn = _get_fn(sl, "CeiExtThenWriteSuspect", "withdraw")
        res = sp.intra_fn_cei(fn)
        self.assertEqual(res, [{
            "ext_call_line": 14,
            "state_write_line": 16,
            "var": "balances",
            "fn": "withdraw",
        }])
        # No transitive provenance leaked onto a direct-ext lead.
        self.assertNotIn("via", res[0])
        self.assertNotIn("transitive", res[0])

    def test_gap5_b_write_before_call_still_clean(self):
        sl = _compile(FX / "cei_write_before_call_clean.sol")
        _, fn = _get_fn(sl, "CeiWriteBeforeCallClean", "withdraw")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_gap5_c_guarded_still_clean(self):
        sl = _compile(FX / "cei_nonreentrant_guarded_clean.sol")
        _, fn = _get_fn(sl, "CeiNonReentrantGuardedClean", "withdraw")
        self.assertEqual(sp.intra_fn_cei(fn), [])


# --- W4 FP-fix: CEI-scoped (view/pure/staticcall excluded) --------------------


@SKIP_NO_SLITHER
class CeiViewPureExclusionTest(unittest.TestCase):
    """A ``view``/``pure`` external call (STATICCALL) cannot reenter-and-write, so a
    state-write AFTER it is CEI-SAFE and must NOT be flagged - directly or
    transitively through an internal helper. CONSERVATIVE never-MISS: an UNKNOWN /
    non-view external target is still treated as state-mutating (STILL flagged)."""

    def test_fp1_direct_view_call_then_write_clean(self):
        # FP-fix #1: a DIRECT external VIEW call then a state-write -> NOT flagged.
        sl = _compile(FX / "cei_view_call_then_write_clean.sol")
        _, fn = _get_fn(sl, "CeiViewCallThenWriteClean", "update")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_fp2_view_via_helper_clean(self):
        # FP-fix #2 (panel FP): helper does an external VIEW call, caller writes
        # after -> NOT flagged (transitive marker excludes the view-only helper).
        sl = _compile(FX / "interproc_cei_view_via_helper_clean.sol")
        _, fn = _get_fn(sl, "InterprocCeiViewViaHelperClean", "update")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_fp3_pure_lib_via_helper_clean(self):
        # FP-fix #3 (panel FP): helper calls an external PURE library fn, caller
        # writes after -> NOT flagged.
        sl = _compile(FX / "interproc_cei_pure_lib_via_helper_clean.sol")
        _, fn = _get_fn(sl, "InterprocCeiPureLibViaHelperClean", "bump")
        self.assertEqual(sp.intra_fn_cei(fn), [])

    def test_fp4_unknown_mutability_via_helper_still_suspect(self):
        # FP-fix #4 (never-MISS): helper reaches an external call of UNKNOWN / non-view
        # mutability before the caller writes -> STILL FLAGGED (conservative).
        sl = _compile(FX / "interproc_cei_unknown_mutability_via_helper_suspect.sol")
        _, fn = _get_fn(
            sl, "InterprocCeiUnknownMutabilityViaHelperSuspect", "withdraw"
        )
        res = sp.intra_fn_cei(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1,
                         "unknown-mutability external call must NOT be excluded "
                         "(conservative never-MISS): real CEI silenced!")
        lead = res[0]
        self.assertEqual(lead["var"], "balances")
        self.assertTrue(lead.get("transitive") is True)
        self.assertEqual(lead.get("via"), "_doThing")

    def test_predicate_unit_neverMiss_on_unresolvable_and_staticcall(self):
        # Unit-level proof of the CONSERVATIVE never-MISS edges that the real-compile
        # fixtures cannot easily synthesize: an UNRESOLVABLE high-level target must NOT
        # be treated as view/pure (so the call counts as state-mutating), and the
        # low-level .staticcall exclusion vs .call/.delegatecall inclusion.
        # UNRESOLVABLE high-level target -> NOT view/pure -> counted as state-mutating.
        self.assertFalse(sp._hlc_is_view_or_pure((None, None)))  # unresolvable tuple
        self.assertFalse(sp._hlc_is_view_or_pure(object()))      # junk (never-MISS)

        # Low-level: .staticcall excluded; .call / .delegatecall / .transfer included.
        class _LL:
            def __init__(self, s):
                self._s = s

            def __str__(self):
                return self._s

        self.assertTrue(sp._llc_is_staticcall(
            _LL("tuple = low_level_call, dest:a, function:staticcall, arguments:[]")))
        self.assertFalse(sp._llc_is_staticcall(
            _LL("tuple = low_level_call, dest:a, function:call, arguments:[]")))
        self.assertFalse(sp._llc_is_staticcall(
            _LL("tuple = low_level_call, dest:a, function:delegatecall, arguments:[]")))
        # An unreadable / oddly-shaped low-level call -> NOT staticcall (never-MISS).

        class _BadStr:
            def __str__(self):
                raise RuntimeError("unreadable")

        self.assertFalse(sp._llc_is_staticcall(_BadStr()))


# --- Mutation evidence (non-vacuity) ------------------------------------------


@SKIP_NO_SLITHER
class TransitiveCeiMutationTest(unittest.TestCase):
    """Non-vacuity: removing the external call from the helper (so it no longer
    reaches out) flips W4-1 FLAGGED -> clean."""

    def test_mutation_remove_ext_from_helper_flips_to_clean(self):
        src = (FX / "interproc_cei_via_helper_suspect.sol").read_text(encoding="utf-8")
        sl = _compile(FX / "interproc_cei_via_helper_suspect.sol")
        _, fn = _get_fn(sl, "InterprocCeiViaHelperSuspect", "withdraw")
        # Base: transitive ext-then-write -> FLAGGED.
        base = sp.intra_fn_cei(fn)
        self.assertEqual(len(base), 1)
        self.assertTrue(base[0].get("transitive") is True)

        # Mutate: replace the helper's external call with pure local work, so the
        # helper no longer reaches out -> the caller's internal call is non-ext.
        mutated = src.replace(
            '''        (bool ok, ) = msg.sender.call{value: amt}("");  // the genuine external call
        require(ok, "send failed");''',
            '''        uint256 noop = amt + 1;  // mutation: external call removed
        require(noop > amt, "overflow");''',
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "interproc_cei_via_helper_suspect.sol"
            mp.write_text(mutated, encoding="utf-8")
            # The cross-compile cache keys on object id, which is unique per fresh
            # compile, so the mutated helper is re-evaluated honestly.
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "InterprocCeiViaHelperSuspect", "withdraw")
            res = sp.intra_fn_cei(mfn)
            self.assertEqual(res, [],
                             "annotation did not flip FLAGGED->clean when the helper's "
                             "external call was removed (vacuous transitive recognition!)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
