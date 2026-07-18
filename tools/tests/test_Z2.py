#!/usr/bin/env python3
"""Z2 zk-lookup-membership-bound - non-vacuous regression suite.

Pins the three membership-binding sub-invariants of the standalone screen
tools/zk-lookup-membership-bound.py:

  (1) committed-table (CORE): a lookup whose TABLE side references an advice
      column is prover-controllable -> FIRES; a committed fixed table -> SILENT.
  (2) selector-gated-off: a lookup input gated only by an advice tag (no
      committed selector) -> FIRES; a committed query_selector gate -> SILENT.
  (3) multiplicity-unchecked: a `multiplicity` advice col with no range/bool pin
      anywhere -> FIRES; a pinned one -> SILENT.

NON-VACUITY (the load-bearing assertion): neutralizing the CORE predicate
(CORE_TABLE_BINDING_CHECK=False) makes the planted uncommitted-table POSITIVE
STOP firing. If the arm were a tautology the neutralization would not change it.

Every emission is asserted verdict="needs-fuzz" (advisory, NO-AUTO-CREDIT) and
covered_by is None (E4/Z1/A4 dedup by construction). The real-fleet idiom
(committed table with a Rust trailing comma) is pinned SILENT to guard the
trailing-comma parse fix against regression.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "zk-lookup-membership-bound.py"


def _load():
    spec = importlib.util.spec_from_file_location("z2_mod", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


z2 = _load()

# --- fixtures: real halo2 meta.lookup idioms ---------------------------------

# BENIGN: committed fixed table (config.table_idx) + committed selector.
# This is the real orchard lookup_range_check shape (trailing comma included).
CLEAN_COMMITTED = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.lookup(|meta| {
        let q_lookup = meta.query_selector(config.q_lookup);
        let q_running = meta.query_selector(config.q_running);
        let z_cur = meta.query_advice(config.running_sum, Rotation::cur());
        let z_next = meta.query_advice(config.running_sum, Rotation::next());
        let word = z_cur.clone() - z_next * F::from(1 << K);
        vec![(
            q_lookup * word,
            config.table_idx,
        )]
    });
}
"""

# POSITIVE (1): the TABLE side is an advice column (config.running_sum) - the
# prover controls the membership set, so any value "matches".
POS_UNCOMMITTED_TABLE = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.lookup(|meta| {
        let q_lookup = meta.query_selector(config.q_lookup);
        let z_cur = meta.query_advice(config.running_sum, Rotation::cur());
        vec![(
            q_lookup * z_cur,
            config.running_sum,
        )]
    });
}
"""

# POSITIVE (2): input gated ONLY by an advice tag q_lookup (no query_selector /
# query_fixed anywhere) - prover can zero the input on a malicious row.
POS_SELECTOR_ADVICE = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.lookup(|meta| {
        let q_lookup = meta.query_advice(config.q_lookup, Rotation::cur());
        let value = meta.query_advice(config.value, Rotation::cur());
        vec![(
            q_lookup * value,
            config.table_value,
        )]
    });
}
"""

# BENIGN (2): same shape but the gate is a committed selector -> SILENT.
NEG_SELECTOR_COMMITTED = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.lookup(|meta| {
        let q_lookup = meta.query_selector(config.q_lookup);
        let value = meta.query_advice(config.value, Rotation::cur());
        vec![(
            q_lookup * value,
            config.table_value,
        )]
    });
}
"""

# POSITIVE (3): a `multiplicity` advice col with no range/bool pin anywhere.
POS_MULT_UNPINNED = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.lookup(|meta| {
        let q_lookup = meta.query_selector(config.q_lookup);
        let value = meta.query_advice(config.value, Rotation::cur());
        let multiplicity = meta.query_advice(config.multiplicity, Rotation::cur());
        vec![(
            q_lookup * value,
            config.table_value,
        )]
    });
}
"""

# BENIGN (3): identical but the multiplicity is bool-pinned elsewhere -> SILENT.
NEG_MULT_PINNED = """
fn configure(meta: &mut ConstraintSystem<F>) {
    meta.create_gate("mult range", |meta| {
        let multiplicity = meta.query_advice(config.multiplicity, Rotation::cur());
        range_check(multiplicity, 64)
    });
    meta.lookup(|meta| {
        let q_lookup = meta.query_selector(config.q_lookup);
        let value = meta.query_advice(config.value, Rotation::cur());
        let multiplicity = meta.query_advice(config.multiplicity, Rotation::cur());
        vec![(
            q_lookup * value,
            config.table_value,
        )]
    });
}
"""


def _arms(hyps):
    return sorted(h["arm"] for h in hyps)


class Z2CommittedTableTest(unittest.TestCase):
    def test_positive_uncommitted_table_fires(self):
        hyps = z2.analyze_text(POS_UNCOMMITTED_TABLE, "pos.rs")
        arms = _arms(hyps)
        self.assertIn("uncommitted-table", arms)
        hit = next(h for h in hyps if h["arm"] == "uncommitted-table")
        self.assertEqual(hit["advice_token"], "running_sum")
        self.assertEqual(hit["invariant"], "INV-ZK-LOOKUP-MEMBERSHIP-BOUND")

    def test_negative_committed_table_silent(self):
        hyps = z2.analyze_text(CLEAN_COMMITTED, "clean.rs")
        self.assertNotIn("uncommitted-table", _arms(hyps))
        # fully benign: no arm fires at all
        self.assertEqual(hyps, [])

    def test_non_vacuity_neutralize_core_kills_positive(self):
        """Neutralize the CORE predicate -> the planted positive MUST stop firing."""
        original = z2.CORE_TABLE_BINDING_CHECK
        try:
            z2.CORE_TABLE_BINDING_CHECK = False
            hyps = z2.analyze_text(POS_UNCOMMITTED_TABLE, "pos.rs")
            self.assertNotIn("uncommitted-table", _arms(hyps),
                             "core predicate is a tautology - neutralization "
                             "did not silence the positive")
        finally:
            z2.CORE_TABLE_BINDING_CHECK = original
        # restored: positive fires again
        self.assertIn("uncommitted-table",
                      _arms(z2.analyze_text(POS_UNCOMMITTED_TABLE, "pos.rs")))


class Z2SelectorArmTest(unittest.TestCase):
    def test_positive_advice_gate_fires(self):
        hyps = z2.analyze_text(POS_SELECTOR_ADVICE, "s.rs")
        arms = _arms(hyps)
        self.assertIn("selector-gated-off", arms)
        hit = next(h for h in hyps if h["arm"] == "selector-gated-off")
        self.assertEqual(hit["gate_tag"], "q_lookup")

    def test_negative_committed_selector_silent(self):
        hyps = z2.analyze_text(NEG_SELECTOR_COMMITTED, "s.rs")
        self.assertNotIn("selector-gated-off", _arms(hyps))


class Z2MultiplicityArmTest(unittest.TestCase):
    def test_positive_unpinned_multiplicity_fires(self):
        hyps = z2.analyze_text(POS_MULT_UNPINNED, "m.rs")
        arms = _arms(hyps)
        self.assertIn("multiplicity-unchecked", arms)
        hit = next(h for h in hyps if h["arm"] == "multiplicity-unchecked")
        self.assertEqual(hit["mult_col"], "multiplicity")

    def test_negative_pinned_multiplicity_silent(self):
        hyps = z2.analyze_text(NEG_MULT_PINNED, "m.rs")
        self.assertNotIn("multiplicity-unchecked", _arms(hyps))


class Z2ContractTest(unittest.TestCase):
    def test_every_emission_is_advisory_needs_fuzz(self):
        for fx in (POS_UNCOMMITTED_TABLE, POS_SELECTOR_ADVICE, POS_MULT_UNPINNED):
            for h in z2.analyze_text(fx, "x.rs"):
                self.assertTrue(h["advisory"])
                self.assertEqual(h["verdict"], "needs-fuzz")   # NO-AUTO-CREDIT
                self.assertIsNone(h["covered_by"])             # E4/Z1/A4 dedup

    def test_trailing_comma_committed_stays_silent(self):
        """Regression: real Rust `(input, table_col,)` trailing comma must NOT
        blank the table side into a vacuous non-fire (that was the parse bug)."""
        hyps = z2.analyze_text(CLEAN_COMMITTED, "c.rs")
        self.assertEqual(hyps, [])
        # and the advice-table variant (also trailing comma) DOES fire
        self.assertIn("uncommitted-table",
                      _arms(z2.analyze_text(POS_UNCOMMITTED_TABLE, "p.rs")))

    def test_cli_never_fails_closed(self):
        import subprocess
        r = subprocess.run(
            ["python3", str(TOOL), str(TOOL)],  # scan a non-.rs path
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)  # advisory-first: exit 0 always


if __name__ == "__main__":
    unittest.main()
