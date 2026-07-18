#!/usr/bin/env python3
"""E4 halo2-constraint-completeness lane - non-vacuous regression.

Pins the ABSENCE/ordering predicate added to tools/zk-hacker-questions.py:
it parses each meta.create_gate closure and flags an advice/witness column
that is queried inside the gate but referenced in NO returned Constraints
expr (a dropped / unconstrained witness). Every hypothesis is
verdict="needs-fuzz" (NO-AUTO-CREDIT); advisory-first (OFF unless the env
flag is set).

Mutation-verify anchor: orchard-halo2 circuit.rs:317 "v_old = 0 or
enable_spends = 1". The CLEAN 4-tuple gate must NOT fire; the MUTANT (that
tuple dropped -> enable_spends queried but unconstrained) MUST fire.

Non-vacuity: mutating the predicate breaks a case.
  - referenced-check OFF (treat every col as unreferenced) -> the CLEAN
    fixture fires (asserted NOT to).
  - fire-on-absence OFF -> the MUTANT fixture stops firing (asserted to).
It is A1-safe: the class is a net-new column-level absence signal, distinct
from the keyword-PRESENCE QUESTION_LIBRARY (asserted).
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
FX = ROOT / "tests" / "fixtures" / "E4"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "zk_hacker_questions_e4", TOOLS / "zk-hacker-questions.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


E4 = _load_tool()


def _scan(fixture_name):
    f = FX / fixture_name
    return E4.halo2_constraint_completeness(f, f.read_text())


class TestHalo2ConstraintCompleteness(unittest.TestCase):
    def test_clean_does_not_fire(self):
        # Every queried col referenced by a returned constraint -> no drop.
        self.assertEqual(_scan("clean.rs"), [])

    def test_mutant_fires_on_dropped_col(self):
        hyps = _scan("mutant.rs")
        self.assertEqual(len(hyps), 1)
        h = hyps[0]
        self.assertEqual(h["dropped_col"], "enable_spends")
        self.assertEqual(h["predicate"], "halo2-constraint-completeness")

    def test_no_auto_credit(self):
        for h in _scan("mutant.rs"):
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertTrue(h["advisory"])

    def test_a1_dedup_net_new_class(self):
        # Absence class must NOT collide with the keyword-presence library.
        kw_classes = {p["bug_class"] for p in E4.QUESTION_LIBRARY}
        self.assertNotIn("halo2-constraint-completeness", kw_classes)
        for h in _scan("mutant.rs"):
            self.assertIsNone(h["covered_by"])  # column-locus never re-derived
            self.assertIn("dropped_col", h)

    def test_fp_guard_no_constraints_block_skipped(self):
        # A gate closure with no returned Constraints:: (lookup/permutation
        # style) must be skipped, not flagged.
        src = ('meta.create_gate("lk", |meta| {\n'
               '  let a = meta.query_advice(advices[0], Rotation::cur());\n'
               '  meta.lookup(|_| vec![(a, table)]);\n'
               '  vec![]\n'
               '});\n')
        p = pathlib.Path("/tmp/e4_fp_guard.rs")
        p.write_text(src)
        self.assertEqual(E4.halo2_constraint_completeness(p, src), [])

    def test_predicate_mutation_would_break(self):
        # Non-vacuity witness: if the referenced-check were disabled (every col
        # deemed unreferenced), clean.rs would emit >0. Prove it emits exactly
        # the referenced-suppressed set (0) so a broken predicate is caught.
        clean = _scan("clean.rs")
        mutant = _scan("mutant.rs")
        self.assertLess(len(clean), len(mutant))  # drop strictly detectable


if __name__ == "__main__":
    unittest.main()
