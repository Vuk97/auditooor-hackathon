#!/usr/bin/env python3
"""EnumerableSet at()-in-remove iteration-skip oracle - Glider gap W5. Regression +
mutation pinning of the predicates added to ``tools/slither_predicates.py``:

  - ``enumerable_remove_in_loop``         - FORWARD loop that reads `<coll>.at(i)`
                                            AND `<coll>.remove(...)` on the SAME
                                            collection while the counter advances
                                            monotonically (iteration-skip).
  - ``closure_enumerable_remove_in_loop`` - own-body + forward closure variant.

OpenZeppelin `EnumerableSet.remove` swaps the LAST element into the removed slot, so
a forward `for (i=0; i<set.length(); i++)` loop that reads `set.at(i)` and
`set.remove(...)` SKIPS the swapped-in element. The CORRECT pattern iterates
BACKWARD (`i--`).

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
is tested without Slither. Mutation evidence:
``test_mutation_forward_to_backward_flips_annotation`` flips the suspect loop from
forward (`i++`) to backward (`i--`) and asserts the annotation flips True->[] (non-
vacuity). Never-false-positive: a backward loop, an at()-only loop, and a fixed-key
removal all yield no annotation.

This COMPLEMENTS gap #5 ``unbounded_loops`` (gas-exhaustion via an attacker-growable
`.length` bound); this is a FUNCTIONAL iteration-skip (silently-skipped elements). It
does NOT duplicate it.
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
    "slither-analyzer not importable; enumset-remove tests need a real compile",
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


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class EnumsetRemoveDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_enumerable_remove_in_loop_degrades(self):
        self.assertTrue(sp.is_degraded(sp.enumerable_remove_in_loop(self._Dummy())))

    def test_closure_variant_degrades(self):
        self.assertTrue(
            sp.is_degraded(sp.closure_enumerable_remove_in_loop(self._Dummy()))
        )

    def test_exported_in_all(self):
        self.assertIn("enumerable_remove_in_loop", sp.__all__)
        self.assertIn("closure_enumerable_remove_in_loop", sp.__all__)


# ─── Semantic path: the oracle ───────────────────────────────────────────────


@SKIP_NO_SLITHER
class EnumsetRemoveInLoopOracleTest(unittest.TestCase):
    def test_a_forward_at_and_remove_is_suspect(self):
        # (a) forward loop reads set.at(i) + set.remove() on the SAME collection
        #     -> iteration-skip suspect.
        sl = _compile(FX / "enumset_remove_in_loop_suspect.sol")
        _, fn = _get_fn(sl, "EnumsetRemoveInLoopSuspect", "purgeAll")
        res = sp.enumerable_remove_in_loop(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        r = res[0]
        self.assertEqual(r["collection"], "members")
        self.assertEqual(r["function"], "purgeAll")
        self.assertEqual(r["contract"], "EnumsetRemoveInLoopSuspect")
        self.assertEqual(r["severity_hint"], "iteration-skip")
        self.assertIsNotNone(r["loop_line"])
        self.assertIsNotNone(r["at_line"])
        self.assertIsNotNone(r["remove_line"])
        # The at() read precedes the remove() in source order.
        self.assertLess(r["at_line"], r["remove_line"])

    def test_b_backward_loop_never_fp(self):
        # (b) BACKWARD loop (`i--`) is the SAFE pattern -> NOT flagged.
        sl = _compile(FX / "enumset_remove_backward_clean.sol")
        _, fn = _get_fn(sl, "EnumsetRemoveBackwardClean", "purgeAll")
        self.assertEqual(sp.enumerable_remove_in_loop(fn), [])

    def test_c_at_only_no_remove_never_fp(self):
        # (c) forward loop reads at(i) but never remove() -> NOT flagged.
        sl = _compile(FX / "enumset_at_only_clean.sol")
        _, fn = _get_fn(sl, "EnumsetAtOnlyClean", "listAll")
        self.assertEqual(sp.enumerable_remove_in_loop(fn), [])

    def test_d_fixed_key_remove_never_fp(self):
        # (d) forward loop removes a fixed key (no at(i)-by-counter on the removed
        #     collection) -> NOT flagged.
        sl = _compile(FX / "enumset_remove_fixed_key_clean.sol")
        _, fn = _get_fn(sl, "EnumsetRemoveFixedKeyClean", "purgeList")
        self.assertEqual(sp.enumerable_remove_in_loop(fn), [])

    def test_e_remove_then_break_never_fp(self):
        # (e) W5 FP fix: forward at(i)+remove on the SAME collection, but an
        #     UNCONDITIONAL `break` right after the single removal. The loop
        #     terminates after the one remove, so the swap-and-pop can never affect
        #     a later at(counter) iteration -> the skip hazard is vacuous -> NOT
        #     flagged. (find-and-remove-ONE idiom; the canonical FP.)
        sl = _compile(FX / "enumset_remove_then_break_clean.sol")
        _, fn = _get_fn(sl, "EnumsetRemoveThenBreakClean", "removeOne")
        self.assertEqual(sp.enumerable_remove_in_loop(fn), [])

    def test_f_remove_then_return_never_fp(self):
        # (f) W5 FP fix: forward at(i)+remove then an UNCONDITIONAL `return` after
        #     the single removal -> loop terminates -> NOT flagged.
        sl = _compile(FX / "enumset_remove_then_return_clean.sol")
        _, fn = _get_fn(sl, "EnumsetRemoveThenReturnClean", "removeOne")
        self.assertEqual(sp.enumerable_remove_in_loop(fn), [])

    def test_g_conditional_break_still_suspect(self):
        # (g) W5: the `break` fires only on a CONDITIONAL branch; a post-remove path
        #     still reaches the loop back-edge WITHOUT break/return after the
        #     swap-and-pop, so the iteration-skip hazard is REAL -> still FLAGGED.
        sl = _compile(FX / "enumset_remove_conditional_break_suspect.sol")
        _, fn = _get_fn(sl, "EnumsetRemoveConditionalBreakSuspect", "purgeMaybe")
        res = sp.enumerable_remove_in_loop(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["collection"], "members")
        self.assertEqual(res[0]["function"], "purgeMaybe")
        self.assertEqual(res[0]["severity_hint"], "iteration-skip")

    def test_closure_own_body_first(self):
        sl = _compile(FX / "enumset_remove_in_loop_suspect.sol")
        _, fn = _get_fn(sl, "EnumsetRemoveInLoopSuspect", "purgeAll")
        res = sp.closure_enumerable_remove_in_loop(fn)
        self.assertFalse(sp.is_degraded(res))
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["at_fn"], "purgeAll")


# ─── Mutation evidence (non-vacuity) ─────────────────────────────────────────


@SKIP_NO_SLITHER
class EnumsetRemoveMutationTest(unittest.TestCase):
    """Non-vacuity: flipping the suspect loop from forward (`i++`) to backward
    (`i--`) must flip the annotation True->[] (the direction is load-bearing)."""

    def test_mutation_forward_to_backward_flips_annotation(self):
        src = (FX / "enumset_remove_in_loop_suspect.sol").read_text(encoding="utf-8")
        sl = _compile(FX / "enumset_remove_in_loop_suspect.sol")
        _, fn = _get_fn(sl, "EnumsetRemoveInLoopSuspect", "purgeAll")
        # Base: forward loop -> flagged.
        base = sp.enumerable_remove_in_loop(fn)
        self.assertEqual(len(base), 1, "base forward loop must be flagged")

        # Flip the loop header + advance from forward to backward. The `.at(i)` read
        # stays referencing the counter; only the DIRECTION changes.
        mutated = src.replace(
            "        for (uint256 i = 0; i < members.length(); i++) {\n"
            "            address m = members.at(i);\n"
            "            members.remove(m);\n"
            "        }",
            "        for (uint256 i = members.length(); i > 0; i--) {\n"
            "            address m = members.at(i - 1);\n"
            "            members.remove(m);\n"
            "        }",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "enumset_remove_in_loop_suspect.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "EnumsetRemoveInLoopSuspect", "purgeAll")
            res = sp.enumerable_remove_in_loop(mfn)
            self.assertEqual(
                res, [],
                "annotation did not flip True->[] under forward->backward "
                "mutation (vacuous! direction is not load-bearing)",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
