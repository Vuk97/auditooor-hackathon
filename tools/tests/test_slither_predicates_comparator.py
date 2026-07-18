#!/usr/bin/env python3
"""Comparator + branch-target GUARD-CORRECTNESS semantics - regression + mutation.

Pins the Glider `is_eq`/comparator + `son_true`/`son_false` branch-target analog
added to ``tools/slither_predicates.py``:

  - ``guard_comparators``       - comparator classifier over slither Binary IR.
  - ``branch_effect_target``    - son_true / son_false navigator.
  - ``boundary_suspect``        - conservative `<=`-where-`<` / `>=`-where-`>`
                                  off-by-one cap LEAD oracle (never an auto-finding).
  - ``path_boundary_suspect``   - function-level first-suspect entry.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE
path is tested without Slither. Mutation evidence:
``test_mutation_flip_le_to_lt_flips_annotation`` flips `<=`->`<` and asserts the
boundary_suspect annotation flips True->False (non-vacuity). Never-false-positive:
the correct strict guard and the caller-identity guard both yield False.
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
    _slither_available(), "slither-analyzer not importable; comparator tests need a real compile"
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


class ComparatorDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_guard_comparators_degrades(self):
        # A bare object with no `.irs` and no `.type` -> the helpers degrade.
        self.assertTrue(sp.is_degraded(sp.boundary_suspect(self._Dummy())))

    def test_branch_effect_target_degrades(self):
        self.assertTrue(sp.is_degraded(sp.branch_effect_target(self._Dummy())))

    def test_path_boundary_suspect_degrades(self):
        self.assertTrue(sp.is_degraded(sp.path_boundary_suspect(self._Dummy())))

    def test_node_with_no_ir_yields_empty_not_degraded(self):
        # A navigable node (has `.irs == []`) with no comparator -> [] (not degrade).
        from types import SimpleNamespace as NS
        node = NS(irs=[], type="EXPRESSION", expression="x = 1")
        comps = sp.guard_comparators(node)
        # If slither IR classes are importable, [] is returned; otherwise DEGRADED.
        if _slither_available():
            self.assertEqual(comps, [])
            bs = sp.boundary_suspect(node)
            self.assertFalse(sp.is_degraded(bs))
            self.assertFalse(bs["boundary_suspect"])


# ─── Semantic path (real Slither compile of fixtures) ────────────────────────


@SKIP_NO_SLITHER
class ComparatorClassifierTest(unittest.TestCase):
    def test_le_cap_comparator_extracted(self):
        sl = _compile(FX / "boundary_suspect_le_cap.sol")
        _, fn = _get_fn(sl, "BoundarySuspectLeCap", "pay")
        self.assertIsNotNone(fn)
        ops = set()
        for n in fn.nodes:
            gc = sp.guard_comparators(n)
            self.assertFalse(sp.is_degraded(gc))
            for c in gc:
                ops.add(c["op"])
        self.assertIn("<=", ops)

    def test_strict_comparator_extracted(self):
        sl = _compile(FX / "boundary_correct_strict.sol")
        _, fn = _get_fn(sl, "BoundaryCorrectStrict", "pay")
        ops = {c["op"] for n in fn.nodes for c in sp.guard_comparators(n)}
        self.assertIn("<", ops)
        self.assertNotIn("<=", ops)

    def test_caller_identity_comparator_is_equal(self):
        sl = _compile(FX / "boundary_caller_identity.sol")
        _, fn = _get_fn(sl, "BoundaryCallerIdentity", "pay")
        ops = {c["op"] for n in fn.nodes for c in sp.guard_comparators(n)}
        self.assertIn("==", ops)


@SKIP_NO_SLITHER
class BoundarySuspectOracleTest(unittest.TestCase):
    def test_a_le_cap_is_boundary_suspect(self):
        # (a) require(amt <= cap) where `<` intended -> boundary_suspect=True.
        sl = _compile(FX / "boundary_suspect_le_cap.sol")
        _, fn = _get_fn(sl, "BoundarySuspectLeCap", "pay")
        bs = sp.path_boundary_suspect(fn, value_names={"amt"})
        self.assertFalse(sp.is_degraded(bs))
        self.assertTrue(bs["boundary_suspect"])
        self.assertEqual(bs["op"], "<=")
        self.assertEqual(bs["suggested_op"], "<")
        self.assertIsNotNone(bs["line"])

    def test_b_ge_cap_is_boundary_suspect(self):
        # (b) the `>=` non-strict mirror -> boundary_suspect=True.
        sl = _compile(FX / "boundary_ge_cap.sol")
        _, fn = _get_fn(sl, "BoundaryGeCap", "pay")
        bs = sp.path_boundary_suspect(fn, value_names={"amt"})
        self.assertTrue(bs["boundary_suspect"])
        self.assertEqual(bs["op"], ">=")
        self.assertEqual(bs["suggested_op"], ">")

    def test_c_strict_guard_never_false_positive(self):
        # (c) the CORRECT strict guard -> boundary_suspect=False (never-FP).
        sl = _compile(FX / "boundary_correct_strict.sol")
        _, fn = _get_fn(sl, "BoundaryCorrectStrict", "pay")
        bs = sp.path_boundary_suspect(fn, value_names={"amt"})
        self.assertFalse(bs["boundary_suspect"])

    def test_d_caller_identity_not_boundary_suspect(self):
        # (d) a caller-identity (==) guard is NOT a comparator/boundary concern.
        sl = _compile(FX / "boundary_caller_identity.sol")
        _, fn = _get_fn(sl, "BoundaryCallerIdentity", "pay")
        bs = sp.path_boundary_suspect(fn, value_names={"amt"})
        self.assertFalse(bs["boundary_suspect"])

    def test_value_name_filter_excludes_unrelated(self):
        # When value_names is restricted to a name NOT in the guard, no suspect.
        sl = _compile(FX / "boundary_suspect_le_cap.sol")
        _, fn = _get_fn(sl, "BoundarySuspectLeCap", "pay")
        bs = sp.path_boundary_suspect(fn, value_names={"somethingElse"})
        self.assertFalse(bs["boundary_suspect"])

    def test_value_name_filter_none_matches_any(self):
        # value_names=None -> any non-const-vs-const value/cap pair flags.
        sl = _compile(FX / "boundary_suspect_le_cap.sol")
        _, fn = _get_fn(sl, "BoundarySuspectLeCap", "pay")
        bs = sp.path_boundary_suspect(fn, value_names=None)
        self.assertTrue(bs["boundary_suspect"])


@SKIP_NO_SLITHER
class BranchTargetNavigatorTest(unittest.TestCase):
    def test_if_node_exposes_son_true_false(self):
        # An explicit `if (amt <= cap) { transfer } else { revert }` is lowered to
        # a CFG IF node; the navigator must expose son_true / son_false (the
        # branch-target API) without raising, and the IF arm (not ENDIF) is the
        # one flagged is_if.
        sl = _compile(FX / "boundary_if_branch.sol")
        _, fn = _get_fn(sl, "BoundaryIfBranch", "pay")
        saw_if = False
        for n in fn.nodes:
            bt = sp.branch_effect_target(n)
            self.assertFalse(sp.is_degraded(bt))
            self.assertIn("is_if", bt)
            self.assertIn("son_true", bt)
            self.assertIn("son_false", bt)
            if bt["is_if"]:
                saw_if = True
                # A real IF node has at least one son branch.
                self.assertTrue(
                    bt["son_true"] is not None or bt["son_false"] is not None
                )
        self.assertTrue(saw_if, "expected at least one IF node (the if guard)")

    def test_endif_is_not_flagged_if(self):
        # The join ENDIF node ends textually in 'IF' but is NOT a branch node.
        sl = _compile(FX / "boundary_if_branch.sol")
        _, fn = _get_fn(sl, "BoundaryIfBranch", "pay")
        endif_nodes = [n for n in fn.nodes
                       if str(getattr(n, "type", "")).upper().endswith("ENDIF")]
        self.assertTrue(endif_nodes, "fixture should have an ENDIF join node")
        for n in endif_nodes:
            self.assertFalse(sp.branch_effect_target(n)["is_if"])

    def test_if_branch_is_boundary_suspect(self):
        # The `if (amt <= cap)` non-strict bound is boundary-suspect on the IF arm.
        sl = _compile(FX / "boundary_if_branch.sol")
        _, fn = _get_fn(sl, "BoundaryIfBranch", "pay")
        bs = sp.path_boundary_suspect(fn, value_names={"amt"})
        self.assertTrue(bs["boundary_suspect"])
        self.assertEqual(bs["op"], "<=")


@SKIP_NO_SLITHER
class BoundaryMutationTest(unittest.TestCase):
    """Non-vacuity: flipping `<=`->`<` must flip the annotation True->False."""

    def test_mutation_flip_le_to_lt_flips_annotation(self):
        src = (FX / "boundary_suspect_le_cap.sol").read_text(encoding="utf-8")
        sl = _compile(FX / "boundary_suspect_le_cap.sol")
        _, fn = _get_fn(sl, "BoundarySuspectLeCap", "pay")
        self.assertTrue(
            sp.path_boundary_suspect(fn, value_names={"amt"})["boundary_suspect"]
        )

        mutated = src.replace(
            'require(amt <= cap, "over cap");',
            'require(amt < cap, "over cap");',
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "boundary_suspect_le_cap.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "BoundarySuspectLeCap", "pay")
            self.assertFalse(
                sp.path_boundary_suspect(mfn, value_names={"amt"})["boundary_suspect"],
                "annotation did not flip True->False under <=->< mutation (vacuous!)",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
