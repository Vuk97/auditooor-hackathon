#!/usr/bin/env python3
"""Logic-tautology / dead-comparison guard-logic correctness oracle - regression
+ mutation pinning of the predicates added to ``tools/slither_predicates.py``
(Glider gap W6 P2):

  - ``logic_tautology_suspects``         - own-body scan, returns list of hits.
  - ``closure_logic_tautology_suspects`` - own body + forward callee closure.

Two sub-rules:
  (a) always-true-or: a Binary OROR whose both input temporaries were produced
      by NOT_EQUAL comparisons sharing the SAME caller-identity variable name
      (msg.sender / tx.origin). The OR of two disequalities on the same caller
      is logically always satisfied, nullifying the access check.
  (b) dead-comparison: a stand-alone EXPRESSION node whose ONLY Binary IR is an
      EQUAL or NOT_EQUAL whose lvalue is never read by any later IR in the same
      node. The result is discarded - a guard forgotten in require.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE
path is tested without Slither. Mutation evidence:
``test_mutation_or_to_and_flips_annotation`` flips `||`->`&&` and asserts the
always-true annotation flips FLAGGED->clean (non-vacuity). Never-false-positive:
the correct AND form, the different-callers OR, the guarded comparison, and the
assigned comparison all yield no annotation.

NOTE: no question is emitted when the slice record is absent (the function has no
DefUsePath) - this is the "no question when slice absent" contract, tested by
``test_no_question_when_slice_absent``.
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
    "slither-analyzer not importable; logic-tautology tests need a real compile",
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


# ---- Degrade path (no Slither needed) -----------------------------------------------


class LogicTautologyDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_logic_tautology_suspects_degrades(self):
        self.assertTrue(sp.is_degraded(sp.logic_tautology_suspects(self._Dummy())))

    def test_closure_logic_tautology_suspects_degrades(self):
        self.assertTrue(
            sp.is_degraded(sp.closure_logic_tautology_suspects(self._Dummy()))
        )

    def test_degrade_is_distinct_from_empty_list(self):
        # DEGRADED is not the same as [] - callers can distinguish "could not
        # analyse" from "navigable but no suspects".
        self.assertIsNot(sp.DEGRADED, [])
        self.assertFalse(sp.is_degraded([]))


# ---- Semantic path: always-true OR tautology (sub-rule a) ---------------------------


@SKIP_NO_SLITHER
class AlwaysTrueOrOracleTest(unittest.TestCase):
    def test_a_always_true_or_is_suspect(self):
        # (a) require(msg.sender != admin || msg.sender != owner) -> always-true-or.
        sl = _compile(FX / "tautology_always_true_or_suspect.sol")
        _, fn = _get_fn(sl, "TautologyAlwaysTrueOrSuspect", "withdraw")
        self.assertIsNotNone(fn, "fixture function not found")
        hits = sp.logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        self.assertEqual(len(hits), 1, f"expected 1 hit, got {hits}")
        h = hits[0]
        self.assertEqual(h["kind"], "always-true-or")
        self.assertEqual(h["severity_hint"], "broken-access-control")
        self.assertIn("msg.sender", h.get("caller_name", ""))
        self.assertIsNotNone(h.get("at_line"))

    def test_b_correct_and_never_fp(self):
        # (b) require(msg.sender != admin && msg.sender != owner) -> NOT flagged
        # (never-false-positive on the correct AND form).
        sl = _compile(FX / "tautology_correct_and_clean.sol")
        _, fn = _get_fn(sl, "TautologyCorrectAndClean", "withdraw")
        self.assertIsNotNone(fn)
        hits = sp.logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        always_true_hits = [h for h in hits if h.get("kind") == "always-true-or"]
        self.assertEqual(always_true_hits, [],
                         "correct AND form must NOT be flagged (never-FP)")

    def test_c_different_callers_never_fp(self):
        # (c) require(msg.sender != admin || other != owner) -> NOT flagged
        # (different identities on the two OR sides).
        sl = _compile(FX / "tautology_different_callers_clean.sol")
        _, fn = _get_fn(sl, "TautologyDifferentCallersClean", "check")
        self.assertIsNotNone(fn)
        hits = sp.logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        always_true_hits = [h for h in hits if h.get("kind") == "always-true-or"]
        self.assertEqual(always_true_hits, [],
                         "different-callers OR must NOT be flagged (never-FP)")

    def test_closure_always_true_or_own_body_first(self):
        # closure variant: own body is found first with at_fn populated.
        sl = _compile(FX / "tautology_always_true_or_suspect.sol")
        _, fn = _get_fn(sl, "TautologyAlwaysTrueOrSuspect", "withdraw")
        hits = sp.closure_logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        self.assertTrue(any(h.get("function") == "withdraw" for h in hits),
                        "closure must include own-body hits")


# ---- Semantic path: dead comparison (sub-rule b) ------------------------------------


@SKIP_NO_SLITHER
class DeadComparisonOracleTest(unittest.TestCase):
    def test_d_dead_comparison_is_suspect(self):
        # (d) `msg.sender == admin;` (result discarded) -> dead-comparison.
        sl = _compile(FX / "tautology_dead_comparison_suspect.sol")
        _, fn = _get_fn(sl, "TautologyDeadComparisonSuspect", "setBalance")
        self.assertIsNotNone(fn, "fixture function not found")
        hits = sp.logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        dead_hits = [h for h in hits if h.get("kind") == "dead-comparison"]
        self.assertEqual(len(dead_hits), 1, f"expected 1 dead-comparison hit, got {hits}")
        h = dead_hits[0]
        self.assertEqual(h["severity_hint"], "broken-access-control")
        self.assertIn(h.get("op"), ("==", "!="))
        self.assertIsNotNone(h.get("at_line"))

    def test_e_comparison_in_require_never_fp(self):
        # (e) `require(msg.sender == admin)` -> comparison IS consumed by require, NOT dead.
        sl = _compile(FX / "tautology_comparison_in_guard_clean.sol")
        _, fn = _get_fn(sl, "TautologyComparisonInGuardClean", "setBalanceRequire")
        self.assertIsNotNone(fn)
        hits = sp.logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        dead_hits = [h for h in hits if h.get("kind") == "dead-comparison"]
        self.assertEqual(dead_hits, [],
                         "comparison inside require() must NOT be flagged (never-FP)")

    def test_e2_comparison_in_if_never_fp(self):
        # (e2) `if (msg.sender == admin) { ... }` -> comparison drives branch, NOT dead.
        sl = _compile(FX / "tautology_comparison_in_guard_clean.sol")
        _, fn = _get_fn(sl, "TautologyComparisonInGuardClean", "setBalanceIf")
        self.assertIsNotNone(fn)
        hits = sp.logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        dead_hits = [h for h in hits if h.get("kind") == "dead-comparison"]
        self.assertEqual(dead_hits, [],
                         "comparison inside if() must NOT be flagged (never-FP)")

    def test_e3_assigned_comparison_never_fp(self):
        # (e3) `ok = (msg.sender == admin)` -> result IS assigned, NOT dead.
        sl = _compile(FX / "tautology_comparison_in_guard_clean.sol")
        _, fn = _get_fn(sl, "TautologyComparisonInGuardClean", "isAdmin")
        self.assertIsNotNone(fn)
        hits = sp.logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        dead_hits = [h for h in hits if h.get("kind") == "dead-comparison"]
        self.assertEqual(dead_hits, [],
                         "assigned comparison must NOT be flagged (never-FP)")

    def test_closure_dead_comparison_own_body_first(self):
        sl = _compile(FX / "tautology_dead_comparison_suspect.sol")
        _, fn = _get_fn(sl, "TautologyDeadComparisonSuspect", "setBalance")
        hits = sp.closure_logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(hits))
        dead_hits = [h for h in hits if h.get("kind") == "dead-comparison"]
        self.assertTrue(len(dead_hits) >= 1, "closure must include own-body dead-comparison hit")


# ---- Mutation evidence (non-vacuity) ------------------------------------------------


@SKIP_NO_SLITHER
class LogicTautologyMutationTest(unittest.TestCase):
    """Non-vacuity: flipping `||`->`&&` in the tautology fixture must flip the
    annotation FLAGGED->clean (mutation of the base -> no always-true-or hit)."""

    def test_mutation_or_to_and_flips_annotation(self):
        src = (FX / "tautology_mutation_base.sol").read_text(encoding="utf-8")
        sl = _compile(FX / "tautology_mutation_base.sol")
        _, fn = _get_fn(sl, "TautologyMutationBase", "access")
        self.assertIsNotNone(fn, "base fixture function not found")
        # Base: || -> FLAGGED.
        base_hits = sp.logic_tautology_suspects(fn)
        self.assertFalse(sp.is_degraded(base_hits))
        base_always_true = [h for h in base_hits if h.get("kind") == "always-true-or"]
        self.assertEqual(len(base_always_true), 1,
                         "base fixture must be flagged as always-true-or")

        # Mutation: replace || with && -> annotation must disappear (CLEAN).
        mutated = src.replace(
            "require(msg.sender != admin || msg.sender != owner",
            "require(msg.sender != admin && msg.sender != owner",
        )
        self.assertNotEqual(mutated, src, "mutation pattern did not match fixture")
        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "tautology_mutation_base.sol"
            mp.write_text(mutated, encoding="utf-8")
            msl = _compile(mp)
            _, mfn = _get_fn(msl, "TautologyMutationBase", "access")
            self.assertIsNotNone(mfn, "mutated fixture function not found")
            mut_hits = sp.logic_tautology_suspects(mfn)
            self.assertFalse(sp.is_degraded(mut_hits))
            mut_always_true = [h for h in mut_hits if h.get("kind") == "always-true-or"]
            self.assertEqual(
                mut_always_true, [],
                "annotation did not flip FLAGGED->clean under ||->&&  mutation (vacuous!)",
            )


# ---- Consume I1: no question when slice absent --------------------------------------


class NoQuestionWhenSliceAbsentTest(unittest.TestCase):
    """Spec: gen_logic_tautology_questions([]) -> []. The I1 consumer must not
    fabricate questions when there are no annotated slice records."""

    def _load_pfhq(self):
        spec = importlib.util.spec_from_file_location(
            "per_function_hacker_questions",
            TOOLS / "per-function-hacker-questions.py",
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        # Suppress import-time stderr noise from the module.
        import io
        sys.stderr = io.StringIO()
        try:
            spec.loader.exec_module(mod)
        except SystemExit:
            pass
        finally:
            sys.stderr = sys.__stderr__
        return mod

    def test_no_question_when_slice_absent(self):
        """gen_logic_tautology_questions([]) must return []."""
        try:
            mod = self._load_pfhq()
        except Exception as exc:
            self.skipTest(f"could not import per-function-hacker-questions: {exc}")
        result = mod.gen_logic_tautology_questions([])
        self.assertEqual(result, [],
                         "no questions must be emitted when there are no suspect paths")

    def test_filter_rejects_non_annotated_paths(self):
        """_flow_path_is_logic_tautology_suspect must return False for a path
        without the logic_tautology_suspect annotation."""
        try:
            mod = self._load_pfhq()
        except Exception as exc:
            self.skipTest(f"could not import per-function-hacker-questions: {exc}")
        # A valid-looking path without the annotation.
        path = {
            "path_id": "dfp-test-0",
            "source": {"fn": "foo", "file": "foo.sol"},
            "sink": {"fn": "bar", "file": "foo.sol", "kind": "transfer"},
            "unguarded": True,
            "confidence": "semantic-ssa",
        }
        self.assertFalse(
            mod._flow_path_is_logic_tautology_suspect(path),
            "path without logic_tautology_suspect must not be seeded",
        )

    def test_filter_accepts_annotated_path(self):
        """_flow_path_is_logic_tautology_suspect must return True for a path
        with logic_tautology_suspect=True (non-degraded, non-heuristic)."""
        try:
            mod = self._load_pfhq()
        except Exception as exc:
            self.skipTest(f"could not import per-function-hacker-questions: {exc}")
        path = {
            "path_id": "dfp-test-1",
            "source": {"fn": "foo", "file": "foo.sol"},
            "sink": {"fn": "bar", "file": "foo.sol", "kind": "transfer"},
            "unguarded": True,
            "confidence": "semantic-ssa",
            "logic_tautology_suspect": True,
            "logic_tautology": {
                "contract": "Foo",
                "function": "foo",
                "kind": "always-true-or",
                "at_line": 10,
                "expr": "msg.sender != admin || msg.sender != owner",
                "severity_hint": "broken-access-control",
            },
        }
        self.assertTrue(
            mod._flow_path_is_logic_tautology_suspect(path),
            "annotated path must be seeded",
        )

    def test_question_content_always_true_or(self):
        """gen_logic_tautology_questions emits a question with question_class
        'broken-access-control-logic' for an always-true-or annotated path."""
        try:
            mod = self._load_pfhq()
        except Exception as exc:
            self.skipTest(f"could not import per-function-hacker-questions: {exc}")
        path = {
            "path_id": "dfp-test-2",
            "source": {"fn": "foo", "file": "Vault.sol"},
            "sink": {"fn": "bar", "file": "Vault.sol", "kind": "transfer"},
            "unguarded": True,
            "confidence": "semantic-ssa",
            "language": "solidity",
            "logic_tautology_suspect": True,
            "logic_tautology": {
                "contract": "Vault",
                "function": "foo",
                "kind": "always-true-or",
                "at_line": 42,
                "expr": "msg.sender != admin || msg.sender != owner",
                "caller_name": "msg.sender",
                "severity_hint": "broken-access-control",
            },
        }
        qs = mod.gen_logic_tautology_questions([path])
        self.assertEqual(len(qs), 1, "expected exactly one question emitted")
        q = qs[0]
        self.assertEqual(q["question_class"], "broken-access-control-logic")
        self.assertEqual(q["logic_tautology_kind"], "always-true-or")
        self.assertTrue(q.get("logic_tautology_suspect"))
        self.assertIn("always", q["question"].lower())
        self.assertIn("msg.sender", q["question"])

    def test_question_content_dead_comparison(self):
        """gen_logic_tautology_questions emits the dead-comparison variant
        with question_class 'broken-access-control-logic'."""
        try:
            mod = self._load_pfhq()
        except Exception as exc:
            self.skipTest(f"could not import per-function-hacker-questions: {exc}")
        path = {
            "path_id": "dfp-test-3",
            "source": {"fn": "setBalance", "file": "Vault.sol"},
            "sink": {"fn": "setBalance", "file": "Vault.sol", "kind": "storage-value"},
            "unguarded": True,
            "confidence": "semantic-ssa",
            "language": "solidity",
            "logic_tautology_suspect": True,
            "logic_tautology": {
                "contract": "Vault",
                "function": "setBalance",
                "kind": "dead-comparison",
                "at_line": 15,
                "expr": "msg.sender == admin",
                "op": "==",
                "severity_hint": "broken-access-control",
            },
        }
        qs = mod.gen_logic_tautology_questions([path])
        self.assertEqual(len(qs), 1)
        q = qs[0]
        self.assertEqual(q["question_class"], "broken-access-control-logic")
        self.assertEqual(q["logic_tautology_kind"], "dead-comparison")
        self.assertIn("dead", q["question"].lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
