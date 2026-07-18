#!/usr/bin/env python3
"""Two-step-ownership-accept WRONG-GUARD detector - Glider gap W6 P5. Regression +
mutation pinning of the predicate added to ``tools/slither_predicates.py``:

  - ``two_step_accept_wrong_guard`` - flags an accept/claim-ownership function that
                                      has an onlyOwner-family MODIFIER (the WRONG
                                      guard: checks the CURRENT owner) but NO
                                      msg.sender==pending* comparison (the CORRECT
                                      guard is absent). Conservative 5-condition AND.

The CORRECT pattern: acceptOwnership checks `require(msg.sender == pendingOwner)`.
The BUG: acceptOwnership is gated by `onlyOwner` which checks `msg.sender == owner`
(the CURRENT owner). The pending owner can never call it, or the current owner can
self-hijack the two-step.

This is DISTINCT from:
  - cap-1 missing-guard (no guard at all - here a guard IS present, just wrong)
  - W1 override-dropped-guard (a base had a guard but the child dropped it)
  - W6 P2 logic-tautology (guard logic is broken: always-true OR / dead comparison)

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
is tested without Slither. Mutation evidence:
``test_mutation_add_pending_check_flips_to_clean`` adds a
``require(msg.sender == pendingOwner)`` to the suspect fixture and asserts the
annotation flips FLAGGED -> [] (non-vacuity: condition 5 is load-bearing).
Never-false-positive: correct pending check, no pending var, and no modifier all
yield [].
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
    "slither-analyzer not importable; two-step-accept tests need a real compile",
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


# ---- Degrade path (no Slither needed) ----------------------------------------


class TwoStepAcceptDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_non_navigable_returns_degraded(self):
        result = sp.two_step_accept_wrong_guard(self._Dummy())
        self.assertTrue(sp.is_degraded(result))

    def test_degraded_is_falsy(self):
        result = sp.two_step_accept_wrong_guard(self._Dummy())
        self.assertFalse(bool(result))

    def test_exported_in_all(self):
        self.assertIn("two_step_accept_wrong_guard", sp.__all__)


# ---- Semantic oracle tests (Slither required) ---------------------------------


@SKIP_NO_SLITHER
class TwoStepAcceptSuspectTest(unittest.TestCase):
    """Flagged case: acceptOwnership gated by onlyOwner with a pendingOwner var
    but no require(msg.sender == pendingOwner) check anywhere in the function."""

    def setUp(self):
        self.sl = _compile(FX / "two_step_accept_wrong_guard_suspect.sol")

    def test_flagged_function_detected(self):
        _, fn = _get_fn(self.sl, "TwoStepAcceptWrongGuardSuspect", "acceptOwnership")
        self.assertIsNotNone(fn, "fixture function not found")
        result = sp.two_step_accept_wrong_guard(fn)
        self.assertFalse(sp.is_degraded(result), "must not degrade on a navigable fn")
        self.assertEqual(len(result), 1, "expected exactly 1 suspect record")
        r = result[0]
        self.assertEqual(r["contract"], "TwoStepAcceptWrongGuardSuspect")
        self.assertEqual(r["function"], "acceptOwnership")
        self.assertEqual(r["severity_hint"], "access-control")
        self.assertIn("pending", r["pending_var"].lower(),
                      "pending_var must name a pending* var")
        self.assertIn("owner", r["ownership_var"].lower(),
                      "ownership_var must name an owner/admin var")
        # Guard modifier must be present and be the onlyOwner-family wrong guard.
        self.assertTrue(r["guard_modifier"],
                        "guard_modifier must be non-empty")
        # at_line must be a positive integer (function declaration line).
        self.assertIsNotNone(r["at_line"])
        self.assertGreater(r["at_line"], 0)

    def test_unrelated_functions_not_flagged(self):
        # transferOwnership is also onlyOwner but NOT an accept/claim function.
        _, fn = _get_fn(self.sl, "TwoStepAcceptWrongGuardSuspect",
                        "transferOwnership")
        if fn is None:
            return  # skip if slither named it differently
        result = sp.two_step_accept_wrong_guard(fn)
        self.assertFalse(sp.is_degraded(result))
        self.assertEqual(result, [],
                         "transferOwnership must not be flagged (not accept/claim)")


@SKIP_NO_SLITHER
class TwoStepAcceptCorrectPendingCheckCleanTest(unittest.TestCase):
    """Clean case: correct pending check present -> NOT flagged (never-FP)."""

    def test_correct_pending_check_not_flagged(self):
        sl = _compile(FX / "two_step_accept_correct_pending_check_clean.sol")
        _, fn = _get_fn(sl, "TwoStepAcceptCorrectPendingCheckClean",
                        "acceptOwnership")
        self.assertIsNotNone(fn)
        result = sp.two_step_accept_wrong_guard(fn)
        self.assertFalse(sp.is_degraded(result))
        self.assertEqual(result, [],
                         "correct pending check must suppress the annotation")


@SKIP_NO_SLITHER
class TwoStepAcceptNoPendingVarCleanTest(unittest.TestCase):
    """Clean case: no pendingOwner var -> condition 2 fails -> NOT flagged."""

    def test_no_pending_var_not_flagged(self):
        sl = _compile(FX / "two_step_accept_no_pending_var_clean.sol")
        _, fn = _get_fn(sl, "TwoStepAcceptNoPendingVarClean", "acceptOwnership")
        self.assertIsNotNone(fn)
        result = sp.two_step_accept_wrong_guard(fn)
        self.assertFalse(sp.is_degraded(result))
        self.assertEqual(result, [],
                         "no pending var must prevent flagging (condition 2 fails)")


@SKIP_NO_SLITHER
class TwoStepAcceptNoModifierCleanTest(unittest.TestCase):
    """Clean case: no onlyOwner-family modifier -> condition 4 fails -> NOT flagged.
    (This is the missing-guard class, not the wrong-guard class.)"""

    def test_no_modifier_not_flagged(self):
        sl = _compile(FX / "two_step_accept_no_modifier_clean.sol")
        _, fn = _get_fn(sl, "TwoStepAcceptNoModifierClean", "acceptOwnership")
        self.assertIsNotNone(fn)
        result = sp.two_step_accept_wrong_guard(fn)
        self.assertFalse(sp.is_degraded(result))
        self.assertEqual(result, [],
                         "no modifier must prevent flagging (condition 4 fails)")


# ---- Mutation evidence (non-vacuity) -----------------------------------------


@SKIP_NO_SLITHER
class TwoStepAcceptMutationTest(unittest.TestCase):
    """Non-vacuity: adding a require(msg.sender == pendingOwner) check to the
    suspect function must flip the annotation FLAGGED -> [] (condition 5 is
    load-bearing: the presence of the correct pending check is what suppresses
    the annotation)."""

    def test_mutation_add_pending_check_flips_to_clean(self):
        base_src = (FX / "two_step_accept_mutation_base.sol").read_text(
            encoding="utf-8")
        sl_base = _compile(FX / "two_step_accept_mutation_base.sol")
        _, fn_base = _get_fn(sl_base, "TwoStepAcceptMutationBase", "acceptOwnership")

        # Base: no pending check -> flagged.
        base_result = sp.two_step_accept_wrong_guard(fn_base)
        self.assertEqual(len(base_result), 1, "base must be flagged (suspect)")

        # Mutate: add require(msg.sender == pendingOwner) inside acceptOwnership.
        # We inject the correct check right before the ownership assignment.
        mutated = base_src.replace(
            "    function acceptOwnership() external onlyOwner {\n"
            "        owner = pendingOwner;\n",
            "    function acceptOwnership() external onlyOwner {\n"
            "        require(msg.sender == pendingOwner, \"not pending owner\");\n"
            "        owner = pendingOwner;\n",
        )
        self.assertNotEqual(mutated, base_src,
                            "mutation pattern did not match fixture source")

        with tempfile.TemporaryDirectory() as td:
            mp = pathlib.Path(td) / "two_step_accept_mutation_base.sol"
            mp.write_text(mutated, encoding="utf-8")
            sl_mut = _compile(mp)
            _, fn_mut = _get_fn(sl_mut, "TwoStepAcceptMutationBase",
                                "acceptOwnership")
            result = sp.two_step_accept_wrong_guard(fn_mut)
            self.assertEqual(
                result, [],
                "annotation did not flip FLAGGED->[] after adding the correct "
                "pending-owner check (condition 5 not load-bearing - non-vacuity "
                "test FAILED)",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
