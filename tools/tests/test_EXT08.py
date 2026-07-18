#!/usr/bin/env python3
"""EXT08 unsound-hand-rolled-guard-predicate screen - non-vacuous regression.

Pins tools/guard-predicate-soundness-screen.py: the Cetus (~$223M) class. A
hand-rolled checked-math / checked-cast guard IS PRESENT but its predicate does not
match the width-sensitive operation it wraps - the bound/mask/type-max is WIDER than
the cast/shift it protects, so an input passes the check yet overflows/truncates the
op. This is NOT the missing-SafeMath detector (which assumes the check is absent).

Non-vacuity (all three legs REQUIRED by the build spec):
  (1) PLANTED POSITIVE fires  - a downcast guarded by a WIDER type-max, and a
      Cetus-shaped left-shift guarded by a mask whose top bit exceeds the result
      width, both flag (guard_bound_width > op_width, dominance=dominates).
  (2) COVERED/benign NEGATIVE silent - the SAME cast guarded by the EXACT-width
      type-max, and a business-cap guard (no bit-width boundary), do not flag.
  (3) NEUTRALIZE the core predicate - monkeypatch `_is_permissive_mismatch` to a
      constant False; the planted positive must then STOP firing. Proves the
      width-mismatch predicate is load-bearing, not decoration.
Plus: a stricter guard (bound narrower than op) never fires; a guard that does NOT
dominate the op emits a dominance-gap advisory (fires=False); the advisory contract
(verdict/advisory/auto_credit) holds on every row; a REAL fleet file (morpho
toUint128, sound) stays silent - no FP-spray.
"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
_TOOL = TOOLS / "guard-predicate-soundness-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("ext08_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MOD = _load()


def _rows(src: str, rel: str = "Lib.sol"):
    return MOD.scan_file(pathlib.Path(rel), rel, file_text=src)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# --- fixtures ---------------------------------------------------------------
# POSITIVE (cast): guard bound = uint256 (256 bits) but the downcast is uint128 -
# an x in (2^128, 2^256) passes the check yet is silently truncated.
POS_CAST = """
library MathLib {
    function toUint128(uint256 x) internal pure returns (uint128) {
        require(x <= type(uint256).max, "CastOverflow");
        return uint128(x);
    }
}
"""

# NEGATIVE (cast): the sound original - guard width == cast width (128 == 128).
NEG_CAST = """
library MathLib {
    function toUint128(uint256 x) internal pure returns (uint128) {
        require(x <= type(uint128).max, "CastOverflow");
        return uint128(x);
    }
}
"""

# POSITIVE (shift, Cetus-shaped): result is uint256, shift by 64, so the operand
# must fit in 256-64 = 192 bits. The mask admits a 200-bit operand (50 hex f's) -
# a value in (2^192, 2^200) passes `n <= mask` yet `n << 64` overflows u256.
POS_SHIFT = """
library FullMath {
    function checked_shlw(uint256 n) internal pure returns (uint256) {
        uint256 mask = 0xffffffffffffffffffffffffffffffffffffffffffffffffff; // 50 f = 200 bits
        require(n <= mask, "overflow");
        return n << 64;
    }
}
"""

# NEGATIVE (shift, sound): mask admits exactly 192 bits (48 f's) = 256-64. A value
# passing `n <= mask` fits in 192 bits, so `n << 64` never overflows u256.
NEG_SHIFT = """
library FullMath {
    function checked_shlw(uint256 n) internal pure returns (uint256) {
        uint256 mask = 0xffffffffffffffffffffffffffffffffffffffffffffffff; // 48 f = 192 bits
        require(n <= mask, "overflow");
        return n << 64;
    }
}
"""

# NEGATIVE (business cap - no bit-width boundary): a legit config cap carries no
# type-max / pow2 / all-F boundary, so it is not even an enforcement point -> no row.
NEG_BUSINESS = """
contract Vault {
    function deposit(uint256 x) external {
        require(x <= 1000000e18, "cap");
        supply = uint128(x);
    }
}
"""

# NEGATIVE (stricter guard): bound narrower than the op (64 < 128) - over-strict,
# rejects valid inputs, but is SAFE and must never fire.
NEG_STRICTER = """
library MathLib {
    function toUint128(uint256 x) internal pure returns (uint128) {
        require(x <= type(uint64).max, "CastOverflow");
        return uint128(x);
    }
}
"""

# DOMINANCE-GAP: the guard for x sits AFTER the cast (does not dominate it on this
# path) - a path-incompleteness advisory (fires=False), the "guard does not
# dominate the op" arm.
GAP_CAST = """
library MathLib {
    function bad(uint256 x) internal pure returns (uint128 y) {
        y = uint128(x);
        require(x <= type(uint256).max, "late");
    }
}
"""

# RUST positive: `as u128` cast guarded by a wider u256::MAX bound.
POS_RUST = """
fn narrow(x: u256) -> u128 {
    assert!(x <= u256::MAX);
    x as u128
}
"""

# NEGATIVE (inner-narrowing, mask): the guard (uint256) is WIDER than the uint128
# downcast, but `x & type(uint128).max` inside the cast caps x to 128 bits, so the
# downcast is sound - the AND-mask is a value-narrowing op the bare-operand match must
# not ignore. Must stay silent even though guard_width(256) > op_width(128).
NEG_NARROW_MASK = """
library MathLib {
    function toUint128(uint256 x) internal pure returns (uint128) {
        require(x <= type(uint256).max, "CastOverflow");
        return uint128(x & type(uint128).max);
    }
}
"""

# NEGATIVE (inner-narrowing, right-shift): `x >> 128` zeroes the top 128 bits, so the
# value fits in 256-128 = 128 bits - the uint128 downcast is sound under a wider
# uint256 guard. Must stay silent.
NEG_NARROW_SHIFT = """
library MathLib {
    function hi(uint256 x) internal pure returns (uint128) {
        require(x <= type(uint256).max, "CastOverflow");
        return uint128(x >> 128);
    }
}
"""

# NEGATIVE (realistic sub-field extract, NON-tautological guard): a 64-bit mask makes
# `uint64(amount & 0xffff...ff)` a safe storage-packing extract even though the guard
# (uint128) is genuinely wider than the op (uint64). This is the common packing idiom
# the fix must not mislabel. Must stay silent.
NEG_SUBFIELD = """
library Packing {
    function lo64(uint128 amount) internal pure returns (uint64) {
        require(amount <= type(uint128).max, "range");
        return uint64(amount & 0xffffffffffffffff);
    }
}
"""


class Ext08Screen(unittest.TestCase):
    # ---- leg 1: planted positives fire ----
    def test_positive_cast_fires(self):
        rows = _rows(POS_CAST)
        fired = _fired(rows)
        self.assertEqual(len(fired), 1, rows)
        r = fired[0]
        self.assertEqual(r["op_kind"], "cast")
        self.assertEqual(r["op_width"], 128)
        self.assertEqual(r["guard_bound_width"], 256)
        self.assertEqual(r["operand"], "x")
        self.assertEqual(r["dominance"], "dominates")

    def test_positive_shift_fires(self):
        rows = _rows(POS_SHIFT)
        fired = _fired(rows)
        self.assertEqual(len(fired), 1, rows)
        r = fired[0]
        self.assertEqual(r["op_kind"], "shift")
        self.assertEqual(r["op_width"], 192)        # 256 - 64
        self.assertEqual(r["guard_bound_width"], 200)  # 50 hex f's

    def test_positive_rust_cast_fires(self):
        rows = _rows(POS_RUST, rel="math.rs")
        fired = _fired(rows)
        self.assertEqual(len(fired), 1, rows)
        self.assertEqual(fired[0]["op_kind"], "cast")
        self.assertEqual(fired[0]["op_width"], 128)

    # ---- leg 2: benign negatives silent ----
    def test_negative_cast_silent(self):
        self.assertEqual(_fired(_rows(NEG_CAST)), [])

    def test_negative_shift_silent(self):
        self.assertEqual(_fired(_rows(NEG_SHIFT)), [])

    def test_negative_business_cap_no_row(self):
        # no bit-width boundary -> not even an enforcement point.
        self.assertEqual(_rows(NEG_BUSINESS), [])

    def test_negative_stricter_guard_silent(self):
        rows = _rows(NEG_STRICTER)
        self.assertEqual(_fired(rows), [])
        # still an enumerated (sound) enforcement point.
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dominance"], "dominates")

    # ---- leg 3: neutralize the core predicate -> positive stops firing ----
    def test_neutralize_core_predicate_kills_positive(self):
        orig = MOD._is_permissive_mismatch
        try:
            MOD._is_permissive_mismatch = lambda gb, ow: False
            self.assertEqual(_fired(_rows(POS_CAST)), [],
                             "positive still fired after neutralizing the predicate")
            self.assertEqual(_fired(_rows(POS_SHIFT)), [])
        finally:
            MOD._is_permissive_mismatch = orig
        # sanity: restored predicate fires again
        self.assertEqual(len(_fired(_rows(POS_CAST))), 1)

    # ---- inner-narrowing suppression (precision fix) ----
    def test_narrowed_mask_cast_silent(self):
        # `uint128(x & type(uint128).max)` under a wider uint256 guard - mask caps to
        # 128 bits, so the downcast is sound and must NOT fire.
        rows = _rows(NEG_NARROW_MASK)
        self.assertEqual(_fired(rows), [], rows)
        r = next(r for r in rows if r["op_kind"] == "cast")
        self.assertEqual(r["dominance"], "dominates")
        self.assertTrue(r["narrowed_sound"])

    def test_narrowed_shift_cast_silent(self):
        # `uint128(x >> 128)` under a wider uint256 guard - right-shift narrows to 128
        # bits, so the downcast is sound and must NOT fire.
        rows = _rows(NEG_NARROW_SHIFT)
        self.assertEqual(_fired(rows), [], rows)
        self.assertTrue(any(r["narrowed_sound"] for r in rows if r["op_kind"] == "cast"))

    def test_subfield_extract_silent(self):
        # `uint64(amount & 0xffff...ff)` under a genuinely-wider uint128 guard - the
        # 64-bit mask makes the extract safe; a realistic non-tautological guard.
        rows = _rows(NEG_SUBFIELD)
        self.assertEqual(_fired(rows), [], rows)
        r = next(r for r in rows if r["op_kind"] == "cast")
        self.assertTrue(r["narrowed_sound"])

    def test_inner_narrowing_suppression_is_load_bearing(self):
        # Neutralize the inner-narrowing analysis -> the safe narrowed idioms wrongly
        # fire again, proving the suppression (not some unrelated path) silences them,
        # while the RAW-operand positive keeps firing regardless.
        orig = MOD._narrowed_effective_width
        try:
            MOD._narrowed_effective_width = lambda *a, **k: None
            self.assertEqual(len(_fired(_rows(NEG_NARROW_MASK))), 1)
            self.assertEqual(len(_fired(_rows(NEG_NARROW_SHIFT))), 1)
            self.assertEqual(len(_fired(_rows(NEG_SUBFIELD))), 1)
        finally:
            MOD._narrowed_effective_width = orig
        # restored -> silent again, and the raw positive still fires.
        self.assertEqual(_fired(_rows(NEG_NARROW_MASK)), [])
        self.assertEqual(len(_fired(_rows(POS_CAST))), 1)

    # ---- dominance-gap arm ----
    def test_dominance_gap_is_advisory_not_fire(self):
        rows = _rows(GAP_CAST)
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["dominance"], "gap")
        self.assertFalse(rows[0]["fires"])

    # ---- advisory contract on every row ----
    def test_advisory_contract(self):
        for src in (POS_CAST, POS_SHIFT, NEG_CAST, GAP_CAST):
            for r in _rows(src):
                self.assertEqual(r["capability"], "EXT08")
                self.assertTrue(r["advisory"])
                self.assertFalse(r["auto_credit"])
                self.assertEqual(r["verdict"], "needs-fuzz")
                self.assertIn("question", r)

    # ---- real fleet file (morpho toUint128) stays silent - no FP-spray ----
    def test_real_fleet_file_no_false_positive(self):
        f = pathlib.Path(
            "/Users/wolf/audits/morpho/src/morpho-blue/src/libraries/UtilsLib.sol")
        if not f.exists():
            self.skipTest("fleet file absent")
        rows = MOD.scan_file(f, f.name)
        self.assertEqual(_fired(rows), [], "FP on a sound real guard")
        # but it IS enumerated as a sound enforcement point.
        self.assertTrue(any(r["function"] == "toUint128" for r in rows))


if __name__ == "__main__":
    unittest.main()
