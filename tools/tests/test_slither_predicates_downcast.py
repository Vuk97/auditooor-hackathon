#!/usr/bin/env python3
"""Type-convertibility lattice + UNSAFE-DOWNCAST oracle - regression + mutation.

Pins the Glider `can_convert` / type-convertibility analog added to
``tools/slither_predicates.py``:

  - ``parse_int_type``               - (u)intN -> {signed, bits} | None.
  - ``cast_is_lossy`` / ``can_convert`` - the widening/narrowing/sign-flip lattice.
  - ``unsafe_value_downcasts``       - conservative LOSSY-cast-on-value oracle over
                                       the slither TypeConversion IR (never auto-finding).
  - ``closure_unsafe_value_downcasts`` - own-body + callee-closure entry.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
+ the pure type-lattice cases run WITHOUT Slither. Mutation evidence:
``test_mutation_remove_safecast_flips_annotation`` replaces SafeCast.toUint64(amount)
with a raw uint64(amount) and asserts the downcast annotation flips False->True
(non-vacuity). Never-false-positive: widening + non-value + SafeCast all yield [].
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
        "slither_predicates_dc", TOOLS / "slither_predicates.py"
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
    "slither-analyzer not importable; downcast IR tests need a real compile",
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


# ─── Pure type lattice (no Slither needed) ───────────────────────────────────


class TypeLatticeTest(unittest.TestCase):
    def test_parse_int_type_basic(self):
        self.assertEqual(sp.parse_int_type("uint256"), {"signed": False, "bits": 256})
        self.assertEqual(sp.parse_int_type("uint64"), {"signed": False, "bits": 64})
        self.assertEqual(sp.parse_int_type("int256"), {"signed": True, "bits": 256})
        self.assertEqual(sp.parse_int_type("int8"), {"signed": True, "bits": 8})

    def test_parse_int_type_default_width(self):
        # bare `uint`/`int` default to 256 bits.
        self.assertEqual(sp.parse_int_type("uint"), {"signed": False, "bits": 256})
        self.assertEqual(sp.parse_int_type("int"), {"signed": True, "bits": 256})

    def test_parse_int_type_non_numeric_is_none(self):
        for t in ("address", "bool", "string", "bytes32", "uint64[]",
                  "mapping(address => uint256)", "", None, "uint12"):
            self.assertIsNone(sp.parse_int_type(t), t)

    def test_cast_is_lossy_narrowing(self):
        self.assertEqual(sp.cast_is_lossy("uint256", "uint64"), "narrowing")
        self.assertEqual(sp.cast_is_lossy("uint128", "uint96"), "narrowing")

    def test_cast_is_lossy_lossless_widening(self):
        self.assertEqual(sp.cast_is_lossy("uint64", "uint256"), "lossless")
        self.assertEqual(sp.cast_is_lossy("int8", "int256"), "lossless")
        self.assertEqual(sp.cast_is_lossy("uint64", "uint64"), "lossless")

    def test_cast_is_lossy_sign_flip(self):
        self.assertEqual(sp.cast_is_lossy("int256", "uint256"), "sign-flip")
        self.assertEqual(sp.cast_is_lossy("uint256", "int256"), "sign-flip")
        # a sign change DOMINATES even when also a widen/narrow.
        self.assertEqual(sp.cast_is_lossy("int64", "uint256"), "sign-flip")
        self.assertEqual(sp.cast_is_lossy("uint256", "int64"), "sign-flip")

    def test_cast_is_lossy_unknown(self):
        self.assertEqual(sp.cast_is_lossy("address", "uint256"), "unknown")
        self.assertEqual(sp.cast_is_lossy("uint256", "bytes32"), "unknown")

    def test_can_convert_lossless_true(self):
        self.assertIs(sp.can_convert("uint64", "uint256"), True)

    def test_can_convert_lossy_false(self):
        self.assertIs(sp.can_convert("uint256", "uint64"), False)
        self.assertIs(sp.can_convert("int256", "uint256"), False)

    def test_can_convert_unknown_degrades(self):
        # R80: cannot honestly rule on a non-numeric conversion -> DEGRADED, never
        # silently 'lossless'.
        self.assertTrue(sp.is_degraded(sp.can_convert("address", "uint256")))


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class DowncastDegradeTest(unittest.TestCase):
    class _Dummy:
        pass

    def test_unsafe_value_downcasts_degrades_on_nonnavigable(self):
        self.assertTrue(sp.is_degraded(sp.unsafe_value_downcasts(self._Dummy())))

    def test_closure_unsafe_value_downcasts_degrades(self):
        self.assertTrue(
            sp.is_degraded(sp.closure_unsafe_value_downcasts(self._Dummy()))
        )


# ─── Semantic path (real Slither compile of fixtures) ────────────────────────


@SKIP_NO_SLITHER
class UnsafeDowncastOracleTest(unittest.TestCase):
    def test_a_uint256_to_uint64_amount_is_suspect(self):
        # (a) uint64(amount) narrowing on a value operand -> suspect, kind=narrowing.
        sl = _compile(FX / "downcast_suspect_uint64.sol")
        _, fn = _get_fn(sl, "DowncastSuspectUint64", "pay")
        self.assertIsNotNone(fn)
        leads = sp.unsafe_value_downcasts(fn)
        self.assertFalse(sp.is_degraded(leads))
        self.assertEqual(len(leads), 1, leads)
        d = leads[0]
        self.assertEqual(d["var"], "amount")
        self.assertEqual(d["from"], "uint256")
        self.assertEqual(d["to"], "uint64")
        self.assertEqual(d["kind"], "narrowing")
        self.assertIsNotNone(d["line"])

    def test_b_int_to_uint_signflip_is_suspect(self):
        # (b) int256 -> uint256 on a value operand -> suspect, kind=sign-flip.
        sl = _compile(FX / "downcast_signflip.sol")
        _, fn = _get_fn(sl, "DowncastSignFlip", "credit")
        leads = sp.unsafe_value_downcasts(fn)
        self.assertEqual(len(leads), 1, leads)
        self.assertEqual(leads[0]["kind"], "sign-flip")
        self.assertEqual(leads[0]["var"], "balance")

    def test_c_safecast_not_flagged(self):
        # (c) SafeCast.toUint64(amount) is a LibraryCall, not a TypeConversion at
        # the call site -> the calling fn yields NO lead. The library's own wrapper
        # body is suppressed (SafeCast wrapper).
        sl = _compile(FX / "downcast_safecast.sol")
        _, payfn = _get_fn(sl, "DowncastSafeCast", "pay")
        self.assertEqual(sp.unsafe_value_downcasts(payfn), [])
        _, wrapfn = _get_fn(sl, "SafeCast", "toUint64")
        # the wrapper body's internal uint64(value) cast is suppressed.
        self.assertEqual(sp.unsafe_value_downcasts(wrapfn), [])

    def test_d_widening_not_flagged(self):
        # (d) widening uint64 -> uint256 is lossless -> NOT flagged.
        sl = _compile(FX / "downcast_widening.sol")
        _, fn = _get_fn(sl, "DowncastWidening", "pay")
        self.assertEqual(sp.unsafe_value_downcasts(fn), [])

    def test_e_nonvalue_not_flagged(self):
        # (e) uint256 -> uint8 of a non-value `flagId` -> NOT flagged (not economic).
        sl = _compile(FX / "downcast_nonvalue.sol")
        _, fn = _get_fn(sl, "DowncastNonValue", "setFlag")
        self.assertEqual(sp.unsafe_value_downcasts(fn), [])

    def test_value_name_filter_excludes_unrelated(self):
        sl = _compile(FX / "downcast_suspect_uint64.sol")
        _, fn = _get_fn(sl, "DowncastSuspectUint64", "pay")
        self.assertEqual(
            sp.unsafe_value_downcasts(fn, value_names={"somethingElse"}), []
        )

    def test_value_name_filter_includes_named(self):
        sl = _compile(FX / "downcast_suspect_uint64.sol")
        _, fn = _get_fn(sl, "DowncastSuspectUint64", "pay")
        leads = sp.unsafe_value_downcasts(fn, value_names={"amount"})
        self.assertEqual(len(leads), 1)

    def test_closure_entry_finds_own_body(self):
        sl = _compile(FX / "downcast_suspect_uint64.sol")
        _, fn = _get_fn(sl, "DowncastSuspectUint64", "pay")
        leads = sp.closure_unsafe_value_downcasts(fn)
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["at_fn"], "pay")


@SKIP_NO_SLITHER
class DowncastMutationTest(unittest.TestCase):
    """Non-vacuity: removing the SafeCast wrapper (-> a raw narrowing cast) must
    flip the annotation False->True."""

    def test_mutation_remove_safecast_flips_annotation(self):
        src = (FX / "downcast_safecast.sol").read_text(encoding="utf-8")
        sl = _compile(FX / "downcast_safecast.sol")
        _, payfn = _get_fn(sl, "DowncastSafeCast", "pay")
        # baseline: SafeCast-wrapped -> NOT flagged.
        self.assertEqual(sp.unsafe_value_downcasts(payfn), [])

        mutated = src.replace(
            "credited[msg.sender] = SafeCast.toUint64(amount);",
            "credited[msg.sender] = uint64(amount);",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "downcast_safecast.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "DowncastSafeCast", "pay")
            leads = sp.unsafe_value_downcasts(mfn)
            self.assertEqual(
                len(leads), 1,
                "annotation did not flip False->True when SafeCast removed (vacuous!)",
            )
            self.assertEqual(leads[0]["kind"], "narrowing")
            self.assertEqual(leads[0]["var"], "amount")


if __name__ == "__main__":
    unittest.main(verbosity=2)
