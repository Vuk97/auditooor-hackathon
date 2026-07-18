#!/usr/bin/env python3
"""Z1: tests for halo2 pass-2 witness-underdetermination (residual freedom).

Distinct from pass-1 (dropped-col) and E4 (gate existence): pass-2 fires when a
gate DOES reference an advice column but leaves it under-determined (no boolean /
inverse uniqueness pin), so a false statement can obtain a valid proof via a
prover-chosen alternate assignment. Invariant: INV-ZK-WITNESS-UNIQUE.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent
TOOL_PATH = TOOLS / "zk-hacker-questions.py"


def _load():
    spec = importlib.util.spec_from_file_location("zk_hacker_questions", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


zkhq = _load()

# --- fixtures: real halo2 create_gate idioms ---------------------------------

# BENIGN: swap used as ternary condition AND boolean-pinned via bool_check(swap).
CLEAN_MUX = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.create_gate("cond swap", |meta| {
        let q_swap = meta.query_selector(q_swap);
        let a = meta.query_advice(config.a, Rotation::cur());
        let b = meta.query_advice(config.b, Rotation::cur());
        let a_swapped = meta.query_advice(config.a_swapped, Rotation::cur());
        let swap = meta.query_advice(config.swap, Rotation::cur());
        let a_check = a_swapped - ternary(swap.clone(), b.clone(), a.clone());
        let bool_check = bool_check(swap);
        Constraints::with_selector(q_swap, [("a check", a_check), ("swap bool", bool_check)])
    });
}
"""

# MUTANT: identical but the boolean pin on swap is DROPPED -> residual freedom.
MUT_MUX = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.create_gate("cond swap", |meta| {
        let q_swap = meta.query_selector(q_swap);
        let a = meta.query_advice(config.a, Rotation::cur());
        let b = meta.query_advice(config.b, Rotation::cur());
        let a_swapped = meta.query_advice(config.a_swapped, Rotation::cur());
        let swap = meta.query_advice(config.swap, Rotation::cur());
        let a_check = a_swapped - ternary(swap.clone(), b.clone(), a.clone());
        Constraints::with_selector(q_swap, [("a check", a_check)])
    });
}
"""

# PASS-1 locus (DEDUP): advice `dangling` queried but referenced in NO constraint.
DROPPED_COL = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.create_gate("drop", |meta| {
        let s = meta.query_selector(s);
        let x = meta.query_advice(config.x, Rotation::cur());
        let dangling = meta.query_advice(config.dangling, Rotation::cur());
        let chk = x.clone() * x;
        Constraints::with_selector(s, [("x", chk)])
    });
}
"""

# FP-GUARD: gate whose closure returns no Constraints (lookup/permutation) is skipped.
LOOKUP_GATE = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.lookup("range", |meta| {
        let v = meta.query_advice(config.v, Rotation::cur());
        vec![(v, table.range)]
    });
    meta.create_gate("perm", |meta| {
        let v = meta.query_advice(config.v, Rotation::cur());
        meta.enable_equality(config.v);
        let noop = v.clone();
        noop
    });
}
"""

# BENIGN inverse-hint: a_inv pinned by `a * a_inv - 1` (nonzero-inverse gadget).
CLEAN_HINT = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.create_gate("is_zero", |meta| {
        let s = meta.query_selector(s);
        let a = meta.query_advice(config.a, Rotation::cur());
        let a_inv = meta.query_advice(config.a_inv, Rotation::cur());
        let is_zero = meta.query_advice(config.is_zero, Rotation::cur());
        let pin = a.clone() * a_inv.clone() - Expression::Constant(F::one());
        Constraints::with_selector(s, [("inv", pin), ("z", is_zero.clone() * a)])
    });
}
"""

# MUTANT inverse-hint: the a_inv pin is dropped; a_inv is under-determined.
MUT_HINT = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.create_gate("is_zero", |meta| {
        let s = meta.query_selector(s);
        let a = meta.query_advice(config.a, Rotation::cur());
        let a_inv = meta.query_advice(config.a_inv, Rotation::cur());
        let is_zero = meta.query_advice(config.is_zero, Rotation::cur());
        Constraints::with_selector(s, [("use", a_inv.clone() * is_zero.clone() * a)])
    });
}
"""

REAL_CONDSWAP = Path(
    "/Users/wolf/audits/orchard-halo2/src/halo2/halo2_gadgets/"
    "src/utilities/cond_swap.rs")


def _p2(text):
    hs = zkhq.halo2_constraint_completeness(Path("x.rs"), text)
    return [h for h in hs if h["predicate"] == zkhq.HALO2_WU_PREDICATE]


def _p1(text):
    hs = zkhq.halo2_constraint_completeness(Path("x.rs"), text)
    return [h for h in hs if h["predicate"] == zkhq.HALO2_CC_PREDICATE]


class TestWitnessUnderdetermination(unittest.TestCase):
    def test_mutant_mux_fires(self):
        hs = _p2(MUT_MUX)
        self.assertEqual(len(hs), 1)
        h = hs[0]
        self.assertEqual(h["advice_col"], "swap")
        self.assertEqual(h["role"], "mux-condition")
        self.assertEqual(h["invariant"], "INV-ZK-WITNESS-UNIQUE")
        self.assertEqual(h["verdict"], "needs-fuzz")
        self.assertTrue(h["advisory"])
        self.assertIsNone(h["covered_by"])

    def test_clean_mux_benign(self):
        self.assertEqual(_p2(CLEAN_MUX), [])

    def test_dropped_col_is_pass1_not_pass2(self):
        # DEDUP: an advice with NO constraint is pass-1's locus; pass-2 silent.
        p2 = _p2(DROPPED_COL)
        p1 = _p1(DROPPED_COL)
        self.assertEqual(p2, [])
        self.assertTrue(any(h["dropped_col"] == "dangling" for h in p1))

    def test_lookup_gate_fp_guard(self):
        # no returned Constraints -> not judged by either pass.
        self.assertEqual(_p2(LOOKUP_GATE), [])
        self.assertEqual(_p1(LOOKUP_GATE), [])

    def test_clean_inverse_hint_benign(self):
        self.assertEqual(_p2(CLEAN_HINT), [])

    def test_mutant_inverse_hint_fires(self):
        hs = _p2(MUT_HINT)
        cols = {h["advice_col"]: h["role"] for h in hs}
        self.assertIn("a_inv", cols)
        self.assertEqual(cols["a_inv"], "inverse-hint")

    def test_real_condswap_clean_no_pass2(self):
        # read-only natural-instance confirm: the shipped (pinned) gadget is benign.
        if not REAL_CONDSWAP.exists():
            self.skipTest("orchard-halo2 ws not present")
        text = REAL_CONDSWAP.read_text(encoding="utf-8", errors="ignore")
        hs = zkhq.halo2_constraint_completeness(REAL_CONDSWAP, text)
        p2 = [h for h in hs if h["predicate"] == zkhq.HALO2_WU_PREDICATE]
        self.assertEqual(p2, [])


if __name__ == "__main__":
    unittest.main()
