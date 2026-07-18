#!/usr/bin/env python3
"""Tests for GEN-4B division-rounds-against-beneficiary-screen.py.

Covers: the divide-before-multiply arm (infix + method-chain) across
Solidity/Rust/Go/Move, the wrong-rounding-direction arm, and the FP-controls
(multiply-before-divide silent, non-conserved silent, correct rounding silent).
"""
import importlib.util
import unittest
from pathlib import Path

_TOOL = (Path(__file__).resolve().parents[1]
         / "division-rounds-against-beneficiary-screen.py")
_spec = importlib.util.spec_from_file_location("gen4b", _TOOL)
gen4b = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen4b)


def _scan(src: str, name: str):
    return gen4b.scan_file(Path(name), name, file_text=src)


class TestDivideBeforeMultiply(unittest.TestCase):
    def test_solidity_infix_fires_high(self):
        rows = _scan(
            "contract V{function f(uint a,uint t)external{"
            "uint shares = a / t * PRICE;}}", "V.sol")
        dbm = [r for r in rows if r["arm"] == "divide-before-multiply"]
        self.assertEqual(len(dbm), 1)
        self.assertEqual(dbm[0]["lang"], "solidity")
        self.assertEqual(dbm[0]["severity"], "high")  # 'shares' in operands
        self.assertTrue(dbm[0]["advisory"])
        self.assertEqual(dbm[0]["verdict"], "needs-fuzz")

    def test_multiply_before_divide_silent(self):
        rows = _scan(
            "contract V{function f(uint a,uint t)external{"
            "uint shares = a * PRICE / t;}}", "V.sol")
        self.assertEqual(
            [r for r in rows if r["arm"] == "divide-before-multiply"], [])

    def test_non_conserved_silent(self):
        # a divide-before-multiply on a NON-value quantity (index/loop) -> silent
        rows = _scan(
            "contract V{function f()external{"
            "uint page = idx / rowsPerPage * columnWidth;}}", "V.sol")
        self.assertEqual(rows, [])

    def test_pure_division_silent(self):
        rows = _scan(
            "contract V{function f(uint amount)external{"
            "uint half = amount / 2;}}", "V.sol")
        self.assertEqual(rows, [])

    def test_go_quo_before_mul_fires(self):
        rows = _scan(
            "package v\nfunc Fee(aum,rate,yr Dec)Dec{"
            "feeDec := aum.Quo(yr).Mul(rate)\nreturn feeDec}", "fee.go")
        dbm = [r for r in rows if r["arm"] == "divide-before-multiply"]
        self.assertEqual(len(dbm), 1)
        self.assertEqual(dbm[0]["lang"], "go")

    def test_go_mul_before_quo_silent(self):
        rows = _scan(
            "package v\nfunc Fee(aum,rate,yr Dec)Dec{"
            "feeDec := aum.Mul(rate).Quo(yr)\nreturn feeDec}", "fee.go")
        self.assertEqual(rows, [])

    def test_rust_chain_with_unwrap_fires(self):
        rows = _scan(
            "fn f(reward:u128,total:u128,stake:u128)->u128{"
            "reward.checked_div(total).unwrap().checked_mul(stake).unwrap()}",
            "p.rs")
        dbm = [r for r in rows if r["arm"] == "divide-before-multiply"]
        self.assertEqual(len(dbm), 1)
        self.assertEqual(dbm[0]["lang"], "rust")

    def test_rust_correct_chain_silent(self):
        rows = _scan(
            "fn f(reward:u128,total:u128,stake:u128)->u128{"
            "reward.checked_mul(stake).unwrap().checked_div(total).unwrap()}",
            "p.rs")
        self.assertEqual(rows, [])

    def test_move_infix_fires(self):
        rows = _scan(
            "module a::b{public fun conv(assets:u64,total:u64):u64{"
            "let shares = assets / total * scale; shares}}", "m.move")
        dbm = [r for r in rows if r["arm"] == "divide-before-multiply"]
        self.assertEqual(len(dbm), 1)
        self.assertEqual(dbm[0]["lang"], "move")

    def test_weak_hint_is_medium(self):
        # conserved token only in fn name / statement, not the operands
        rows = _scan(
            "contract V{function computeReward()external{"
            "uint x = a / b * c;}}", "V.sol")
        dbm = [r for r in rows if r["arm"] == "divide-before-multiply"]
        self.assertEqual(len(dbm), 1)
        self.assertEqual(dbm[0]["severity"], "medium")


class TestWrongRoundingDirection(unittest.TestCase):
    def test_payout_rounds_up_fires_medium(self):
        rows = _scan(
            "contract V{function f()external{"
            "uint payout = amount.mulDivUp(x, y);}}", "V.sol")
        wrd = [r for r in rows if r["arm"] == "wrong-rounding-direction"]
        self.assertEqual(len(wrd), 1)
        self.assertEqual(wrd[0]["severity"], "medium")

    def test_payout_rounds_down_silent(self):
        rows = _scan(
            "contract V{function f()external{"
            "uint payout = redeemAmt.mulDivDown(x, y);}}", "V.sol")
        self.assertEqual(
            [r for r in rows if r["arm"] == "wrong-rounding-direction"], [])

    def test_debt_rounds_down_fires(self):
        rows = _scan(
            "contract V{function f()external{"
            "uint debt = borrowAmount.mulDivDown(x, y);}}", "V.sol")
        wrd = [r for r in rows if r["arm"] == "wrong-rounding-direction"]
        self.assertEqual(len(wrd), 1)

    def test_debt_rounds_up_silent(self):
        rows = _scan(
            "contract V{function f()external{"
            "uint debt = borrowAmount.mulDivUp(x, y);}}", "V.sol")
        self.assertEqual(
            [r for r in rows if r["arm"] == "wrong-rounding-direction"], [])


class TestHygiene(unittest.TestCase):
    def test_comment_masked(self):
        rows = _scan(
            "contract V{function f(uint amount,uint t)external{"
            "// uint s = amount / t * PRICE;\n uint ok=1;}}", "V.sol")
        self.assertEqual(rows, [])

    def test_unknown_ext_silent(self):
        self.assertEqual(_scan("amount / t * price", "x.py"), [])

    def test_schema_and_capability(self):
        rows = _scan(
            "contract V{function f(uint a,uint t)external{"
            "uint shares = a / t * PRICE;}}", "V.sol")
        self.assertEqual(rows[0]["schema"], gen4b.HYP_SCHEMA)
        self.assertEqual(rows[0]["capability"], "GEN_4B")
        self.assertIn("id", rows[0])


if __name__ == "__main__":
    unittest.main()
