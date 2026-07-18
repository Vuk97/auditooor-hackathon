#!/usr/bin/env python3
"""Divide-before-multiply precision-loss oracle - regression + mutation (Glider gap W3).

Pins the divide-before-multiply precision detector added to
``tools/slither_predicates.py``:

  - ``divide_before_multiply``          - conservative `(a / b) * c` oracle over the
                                          slither Binary IR (DIVISION lvalue feeding a
                                          later MULTIPLICATION; never auto-finding).
  - ``closure_divide_before_multiply``  - own-body + callee-closure entry.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
runs WITHOUT Slither. Mutation evidence:
``test_mutation_reorder_to_mul_before_div_flips_annotation`` rewrites
`(amount / rate) * shares` to the correct `(amount * shares) / rate` and asserts the
annotation flips True->False (non-vacuity). Never-false-positive: mul-before-div,
div-only, and a pure constant fold all yield [].
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
        "slither_predicates_dbm", TOOLS / "slither_predicates.py"
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
    "slither-analyzer not importable; divide-before-multiply IR tests need a real compile",
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


# ─── Enum-name + degrade path (no Slither needed) ────────────────────────────


class DivBeforeMulDegradeTest(unittest.TestCase):
    class _Dummy:
        pass

    def test_divide_before_multiply_degrades_on_nonnavigable(self):
        self.assertTrue(sp.is_degraded(sp.divide_before_multiply(self._Dummy())))

    def test_closure_divide_before_multiply_degrades(self):
        self.assertTrue(
            sp.is_degraded(sp.closure_divide_before_multiply(self._Dummy()))
        )

    @SKIP_NO_SLITHER
    def test_binarytype_enum_names_exist(self):
        # The detector relies on BinaryType.DIVISION / .MULTIPLICATION existing
        # verbatim. Confirm they do in the installed slither (else the detector
        # degrades by design rather than guessing - R80).
        from slither.slithir.operations.binary import BinaryType

        self.assertTrue(hasattr(BinaryType, "DIVISION"))
        self.assertTrue(hasattr(BinaryType, "MULTIPLICATION"))


# ─── Semantic path (real Slither compile of fixtures) ────────────────────────


@SKIP_NO_SLITHER
class DivBeforeMulOracleTest(unittest.TestCase):
    def test_a_inline_div_before_mul_is_suspect(self):
        # (a) `(amount / rate) * shares` -> suspect on value-moving operands.
        sl = _compile(FX / "div_before_mul_suspect.sol")
        _, fn = _get_fn(sl, "DivBeforeMulSuspect", "payout")
        self.assertIsNotNone(fn)
        leads = sp.divide_before_multiply(fn)
        self.assertFalse(sp.is_degraded(leads))
        self.assertEqual(len(leads), 1, leads)
        d = leads[0]
        self.assertEqual(d["contract"], "DivBeforeMulSuspect")
        self.assertEqual(d["function"], "payout")
        self.assertEqual(d["severity_hint"], "precision-loss")
        self.assertIs(d["value_moving"], True)
        self.assertIsNotNone(d["div_line"])
        self.assertIsNotNone(d["mul_line"])
        self.assertEqual(d["at_line"], d["div_line"])
        self.assertTrue(str(d["at_file"]).endswith("div_before_mul_suspect.sol"))

    def test_b_indirect_div_result_through_assignment_is_suspect(self):
        # (b) `uint q = balance / rate; q * shares;` -> the div result is copied to a
        # named local before the multiply; the assignment-fold must still catch it.
        sl = _compile(FX / "div_before_mul_suspect.sol")
        _, fn = _get_fn(sl, "DivBeforeMulSuspect", "payoutIndirect")
        leads = sp.divide_before_multiply(fn)
        self.assertEqual(len(leads), 1, leads)
        # div on one line, mul on the next (indirect form).
        self.assertIsNotNone(leads[0]["div_line"])
        self.assertIsNotNone(leads[0]["mul_line"])

    def test_c_mul_before_div_not_flagged(self):
        # (c) `(amount * shares) / rate` is the CORRECT scale-then-divide order.
        sl = _compile(FX / "mul_before_div_clean.sol")
        _, fn = _get_fn(sl, "MulBeforeDivClean", "payout")
        self.assertEqual(sp.divide_before_multiply(fn), [])

    def test_d_div_only_not_flagged(self):
        # (d) a division whose result is never multiplied -> NOT flagged.
        sl = _compile(FX / "div_only_clean.sol")
        _, fn = _get_fn(sl, "DivOnlyClean", "share")
        self.assertEqual(sp.divide_before_multiply(fn), [])

    def test_e_const_fold_not_flagged(self):
        # (e) `(100 / 10) * 3` - every source operand is a compile-time literal, so
        # it is a constant fold, not a runtime precision bug -> NOT flagged.
        sl = _compile(FX / "const_fold_clean.sol")
        _, fn = _get_fn(sl, "ConstFoldClean", "f")
        self.assertEqual(sp.divide_before_multiply(fn), [])

    def test_f_div_then_reassign_not_flagged(self):
        # (f) FP regression: `x = a / b; x = fresh; return x * shares;` - the div-result
        # stamp on `x` is reassigned to a non-div value before the multiply, so the
        # multiply consumes `fresh`, NOT the quotient. The forward tracker must KILL the
        # stale stamp on reassignment -> NOT flagged.
        sl = _compile(FX / "div_then_reassign_clean.sol")
        _, fn = _get_fn(sl, "DivThenReassignClean", "reassignThenMul")
        self.assertIsNotNone(fn)
        self.assertEqual(sp.divide_before_multiply(fn), [])

    def test_g_div_then_branch_reassign_not_flagged(self):
        # (g) branch-reassign variant: the stamp is overwritten on a conditional path
        # (a Phi merges a div-result and a non-div value). Conservative kill on any
        # lvalue-rewriting op that does not propagate div-ness -> NOT flagged.
        sl = _compile(FX / "div_then_reassign_clean.sol")
        _, fn = _get_fn(sl, "DivThenReassignClean", "branchReassignThenMul")
        self.assertIsNotNone(fn)
        self.assertEqual(sp.divide_before_multiply(fn), [])

    def test_closure_entry_finds_own_body(self):
        sl = _compile(FX / "div_before_mul_suspect.sol")
        _, fn = _get_fn(sl, "DivBeforeMulSuspect", "payout")
        leads = sp.closure_divide_before_multiply(fn)
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["at_fn"], "payout")

    def test_closure_entry_clean_on_mul_before_div(self):
        sl = _compile(FX / "mul_before_div_clean.sol")
        _, fn = _get_fn(sl, "MulBeforeDivClean", "payout")
        self.assertEqual(sp.closure_divide_before_multiply(fn), [])


@SKIP_NO_SLITHER
class DivBeforeMulMutationTest(unittest.TestCase):
    """Non-vacuity: reordering `(a / b) * c` -> `(a * c) / b` must flip the
    annotation True->False."""

    def test_mutation_reorder_to_mul_before_div_flips_annotation(self):
        src = (FX / "div_before_mul_suspect.sol").read_text(encoding="utf-8")
        sl = _compile(FX / "div_before_mul_suspect.sol")
        _, fn = _get_fn(sl, "DivBeforeMulSuspect", "payout")
        # baseline: divide-before-multiply -> FLAGGED.
        self.assertEqual(len(sp.divide_before_multiply(fn)), 1)

        mutated = src.replace(
            "(amount / rate) * shares",
            "(amount * shares) / rate",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "div_before_mul_suspect.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "DivBeforeMulSuspect", "payout")
            leads = sp.divide_before_multiply(mfn)
            self.assertEqual(
                leads, [],
                "annotation did not flip True->False when reordered to "
                "mul-before-div (vacuous!)",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
