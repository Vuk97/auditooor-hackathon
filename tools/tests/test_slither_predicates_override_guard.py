#!/usr/bin/env python3
"""Override-dropped-guard dispatch detector - Glider gap W1. Regression +
mutation pinning of the predicates added to ``tools/slither_predicates.py``:

  - ``override_dropped_guards``         - flags a function whose concrete override
                                          DROPPED a caller-identity access-control
                                          guard its base version enforced
                                          (conservative: base-guarded +
                                          override-unguarded ONLY; never-false-positive).
  - ``closure_override_dropped_guards`` - thin FP-neutral wrapper (same result;
                                          the base/override verdicts are already
                                          closure-aware via has_guard_in_closure).

The detector REUSES the existing guard recognition (``has_guard_in_closure`` ->
``_node_default_guard`` -> the OZ / legacy / AccessManaged sets) end-to-end; it
does NOT rebuild guard recognition.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
is tested without Slither. Mutation evidence:
``test_mutation_readd_guard_to_override_flips_to_clean`` and
``test_mutation_remove_base_guard_flips_to_clean`` mutate the fixture so it is no
longer a DROP and assert the verdict flips FLAGGED -> clean (non-vacuity).
Never-false-positive: override-keeps-guard, override-guard-in-callee, and
no-base-guard all yield no flag.

This COMPLEMENTS ``has_guard_in_closure`` (which sees only the post-drop state) and
the gap #4 call-site selector (which enumerates call SITES, not guard deltas across
the override DAG); it does NOT duplicate either.
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
    "slither-analyzer not importable; override-guard tests need a real compile",
)


def _compile(path: pathlib.Path):
    from slither import Slither

    return Slither(str(path))


def _get_contract(sl, cname):
    for c in sl.contracts:
        if c.name == cname:
            return c
    return None


def _flag_names(recs):
    """Set of flagged function names from an override_dropped_guards result."""
    if sp.is_degraded(recs) or not recs:
        return set()
    return {r["function"] for r in recs}


# ─── __all__ export ──────────────────────────────────────────────────────────


class ExportTest(unittest.TestCase):
    def test_predicates_exported(self):
        self.assertIn("override_dropped_guards", sp.__all__)
        self.assertIn("closure_override_dropped_guards", sp.__all__)
        self.assertTrue(callable(sp.override_dropped_guards))
        self.assertTrue(callable(sp.closure_override_dropped_guards))


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class OverrideGuardDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_override_dropped_guards_degrades(self):
        self.assertTrue(sp.is_degraded(sp.override_dropped_guards(self._Dummy())))

    def test_closure_variant_degrades(self):
        self.assertTrue(
            sp.is_degraded(sp.closure_override_dropped_guards(self._Dummy()))
        )


# ─── Semantic path: FLAGGED cases ────────────────────────────────────────────


@SKIP_NO_SLITHER
class OverrideDropFlaggedTest(unittest.TestCase):
    def test_legacy_onlyowner_drop_is_flagged(self):
        sl = _compile(FX / "override_drops_onlyowner_suspect.sol")
        c = _get_contract(sl, "Derived")
        recs = sp.override_dropped_guards(c)
        self.assertFalse(sp.is_degraded(recs))
        self.assertIn("setConfig", _flag_names(recs))
        r = next(x for x in recs if x["function"] == "setConfig")
        self.assertEqual(r["base_contract"], "BaseGuardedOnlyOwner")
        self.assertEqual(r["selector"], "setConfig(uint256)")
        self.assertEqual(r["severity_hint"], "access-control")
        self.assertIsNotNone(r["at_line"])
        self.assertTrue(r["at_file"].endswith("override_drops_onlyowner_suspect.sol"))
        self.assertIn("onlyOwner", r["dropped_guard"])

    def test_oz_checkowner_drop_is_flagged(self):
        sl = _compile(FX / "override_drops_oz_checkowner_suspect.sol")
        c = _get_contract(sl, "Derived")
        recs = sp.override_dropped_guards(c)
        self.assertFalse(sp.is_degraded(recs))
        self.assertIn("transferTreasury", _flag_names(recs))
        r = next(x for x in recs if x["function"] == "transferTreasury")
        self.assertEqual(r["base_contract"], "OzOwnableBase")
        self.assertEqual(r["severity_hint"], "access-control")

    def test_closure_variant_same_result(self):
        sl = _compile(FX / "override_drops_onlyowner_suspect.sol")
        c = _get_contract(sl, "Derived")
        a = sp.override_dropped_guards(c)
        b = sp.closure_override_dropped_guards(c)
        self.assertEqual(_flag_names(a), _flag_names(b))


# ─── Semantic path: CLEAN cases (never-false-positive) ───────────────────────


@SKIP_NO_SLITHER
class OverrideDropCleanTest(unittest.TestCase):
    def test_override_keeps_equivalent_guard_not_flagged(self):
        sl = _compile(FX / "override_keeps_guard_clean.sol")
        c = _get_contract(sl, "Derived")
        recs = sp.override_dropped_guards(c)
        self.assertFalse(sp.is_degraded(recs))
        self.assertNotIn("setConfig", _flag_names(recs))

    def test_override_guard_in_forward_callee_not_flagged(self):
        sl = _compile(FX / "override_guard_in_callee_clean.sol")
        c = _get_contract(sl, "Derived")
        recs = sp.override_dropped_guards(c)
        self.assertFalse(sp.is_degraded(recs))
        self.assertNotIn("setConfig", _flag_names(recs))

    def test_no_base_guard_is_not_a_drop(self):
        # Conservative direction: a base that itself has no guard cannot be a
        # "drop" - nothing to drop. Must NOT flag.
        sl = _compile(FX / "no_base_guard_clean.sol")
        c = _get_contract(sl, "Derived")
        recs = sp.override_dropped_guards(c)
        self.assertFalse(sp.is_degraded(recs))
        self.assertNotIn("setConfig", _flag_names(recs))

    def test_owner_zero_address_sanity_check_drop_is_not_flagged(self):
        # FP REGRESSION (W1 stricter base-guard predicate): the base `update()`
        # is permissionless; its only require is a zero-address SANITY check
        # `require(owner() != address(0))` that names the owner accessor but never
        # reads the caller. Dropping that sanity require is NOT an access-control
        # drop. Before the fix this FALSELY flagged via the accessor-name-only
        # signal. Must NOT flag, and the whole-contract result must be [].
        sl = _compile(FX / "override_drops_owner_sanity_clean.sol")
        c = _get_contract(sl, "Derived")
        recs = sp.override_dropped_guards(c)
        self.assertFalse(sp.is_degraded(recs))
        self.assertNotIn("update", _flag_names(recs))
        # No drop anywhere on this contract.
        self.assertEqual(recs, [])

    def test_owner_sanity_base_guard_is_strict_negative(self):
        # The stricter W1 base-guard predicate must reject the accessor-only
        # sanity check directly: has_guard_in_closure(base, _w1_strict_base_guard)
        # is False for the sanity-only base, while the permissive default counts
        # it as a guard (signal 3). This pins the FP root cause at the predicate.
        sl = _compile(FX / "override_drops_owner_sanity_clean.sol")
        base = _get_contract(sl, "BaseSanityOnly")
        bf = next(f for f in base.functions if f.name == "update"
                  and f.contract_declarer.name == "BaseSanityOnly")
        strict = sp.has_guard_in_closure(bf, guard_pred=sp._w1_strict_base_guard)
        self.assertFalse(sp.is_degraded(strict))
        self.assertFalse(bool(strict),
                         "sanity-only owner() check must NOT be a strict guard")
        # Default permissive path still recognizes it (gaps #1-5 unchanged).
        default = sp.has_guard_in_closure(bf)
        self.assertFalse(sp.is_degraded(default))
        self.assertTrue(bool(default),
                        "permissive default must stay byte-identical (signal 3)")


# ─── Mutation non-vacuity (FLAGGED -> clean flips) ───────────────────────────


@SKIP_NO_SLITHER
class OverrideDropMutationTest(unittest.TestCase):
    """Prove the detector is non-vacuous: making the fixture no longer a DROP
    flips the verdict FLAGGED -> clean. Two mutations, each the inverse of one
    drop precondition."""

    _BASE = (FX / "override_drops_onlyowner_suspect.sol").read_text()

    def _flag_for_source(self, src: str) -> bool:
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "mut.sol"
            p.write_text(src)
            sl = _compile(p)
            c = _get_contract(sl, "Derived")
            recs = sp.override_dropped_guards(c)
            return "setConfig" in _flag_names(recs)

    def test_baseline_is_flagged(self):
        self.assertTrue(self._flag_for_source(self._BASE))

    def test_mutation_readd_guard_to_override_flips_to_clean(self):
        # MUTATION 1: re-add the guard to the override (it is no longer dropped).
        mutated = self._BASE.replace(
            "    function setConfig(uint256 v) external override {\n"
            "        config = v;\n"
            "    }",
            "    function setConfig(uint256 v) external override {\n"
            "        require(msg.sender == owner, \"not owner\");\n"
            "        config = v;\n"
            "    }",
        )
        self.assertNotEqual(mutated, self._BASE, "mutation 1 did not apply")
        self.assertFalse(
            self._flag_for_source(mutated),
            "re-adding the guard to the override must flip FLAGGED -> clean",
        )

    def test_mutation_remove_base_guard_flips_to_clean(self):
        # MUTATION 2: drop the guard from the BASE too (no base guard -> nothing
        # was dropped -> not a drop).
        mutated = self._BASE.replace(
            "    function setConfig(uint256 v) external virtual onlyOwner {",
            "    function setConfig(uint256 v) external virtual {",
        )
        self.assertNotEqual(mutated, self._BASE, "mutation 2 did not apply")
        self.assertFalse(
            self._flag_for_source(mutated),
            "removing the base guard must flip FLAGGED -> clean (no drop)",
        )


if __name__ == "__main__":
    unittest.main()
