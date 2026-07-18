#!/usr/bin/env python3
"""Oracle try/catch-swallow detector - Glider gap W2. Regression + mutation
pinning of the predicates added to ``tools/slither_predicates.py``:

  - ``oracle_swallow_suspects``         - flags a TRY/CATCH wrapping an ORACLE /
                                          price read whose catch SWALLOWS the
                                          failure (no revert / no re-throw / no
                                          subsequent validating require), so
                                          execution proceeds on a stale/zero/
                                          default value
                                          (conservative / never-false-positive).
  - ``closure_oracle_swallow_suspects`` - own-body + forward-closure variant
                                          (folds modifier bodies + callees);
                                          FP-neutral (each member list is the same
                                          conservative predicate).

The detector REUSES the existing IR/CFG primitives (``_node_irs``,
``_node_callee_names``, the TRY/CATCH NodeType modeling) end-to-end; it does NOT
rebuild call/guard recognition. It complements the access-control / boundary /
downcast / asm / intra-CEI / unbounded-loop oracles (a distinct failure-handling
bug class) - it does NOT duplicate any of them.

Honesty (R80): the semantic cases require a real Slither compile of the in-tree
fixtures; if Slither is not importable they SKIP (no faked pass). The DEGRADE path
(non-navigable input) is tested without Slither. The detector also DEGRADES (no
guess) when the installed slither lacks TRY/CATCH node modeling. Mutation evidence:
``test_mutation_catch_revert_flips_to_clean`` (+ require(false) variant) mutates the
swallowing catch into a propagating one and asserts the verdict flips
FLAGGED -> clean (non-vacuity). Never-false-positive: catch-reverts,
catch-validated-by-subsequent-require, and no-try-at-all all yield no flag.
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
    "slither-analyzer not importable; oracle-swallow tests need a real compile",
)


def _compile(path: pathlib.Path):
    from slither import Slither

    return Slither(str(path))


def _get_fn(sl, cname, fname):
    for c in sl.contracts:
        if c.name != cname:
            continue
        for f in c.functions:
            if f.name == fname:
                return f
    return None


def _flagged(recs) -> bool:
    return (not sp.is_degraded(recs)) and bool(recs)


# ─── __all__ export ──────────────────────────────────────────────────────────


class ExportTest(unittest.TestCase):
    def test_predicates_exported(self):
        self.assertIn("oracle_swallow_suspects", sp.__all__)
        self.assertIn("closure_oracle_swallow_suspects", sp.__all__)
        self.assertTrue(callable(sp.oracle_swallow_suspects))
        self.assertTrue(callable(sp.closure_oracle_swallow_suspects))

    def test_oracle_name_set_present(self):
        # The curated oracle-read name set is a module-level frozenset next to the
        # authz sets; it must contain the canonical Chainlink reads.
        self.assertIn("latestrounddata", sp._ORACLE_READ_NAMES)
        self.assertIn("latestanswer", sp._ORACLE_READ_NAMES)
        self.assertIsInstance(sp._ORACLE_READ_NAMES, frozenset)


# ─── Degrade path (no Slither needed) ────────────────────────────────────────


class OracleSwallowDegradeTest(unittest.TestCase):
    """R80: a non-navigable input degrades (distinct sentinel), never a guess."""

    class _Dummy:
        pass

    def test_oracle_swallow_degrades(self):
        self.assertTrue(sp.is_degraded(sp.oracle_swallow_suspects(self._Dummy())))

    def test_closure_variant_degrades(self):
        self.assertTrue(
            sp.is_degraded(sp.closure_oracle_swallow_suspects(self._Dummy()))
        )

    def test_try_catch_modeled_probe(self):
        # The capability probe must return a bool (True on this slither, which
        # models TRY/CATCH; if a future slither drops it, the predicate DEGRADES).
        self.assertIsInstance(sp._slither_try_catch_modeled(), bool)


# ─── Semantic path: FLAGGED case ─────────────────────────────────────────────


@SKIP_NO_SLITHER
class OracleSwallowFlaggedTest(unittest.TestCase):
    def test_swallowing_catch_is_flagged(self):
        sl = _compile(FX / "oracle_swallow_suspect.sol")
        f = _get_fn(sl, "OracleSwallow", "refresh")
        self.assertIsNotNone(f)
        recs = sp.oracle_swallow_suspects(f)
        self.assertFalse(sp.is_degraded(recs))
        self.assertEqual(len(recs), 1, "expected exactly one swallow suspect")
        r = recs[0]
        self.assertEqual(r["contract"], "OracleSwallow")
        self.assertEqual(r["function"], "refresh")
        self.assertEqual(r["oracle_callee"], "latestrounddata")
        self.assertEqual(r["severity_hint"], "oracle")
        self.assertIsNotNone(r["catch_line"])
        self.assertIsNotNone(r["try_line"])
        self.assertTrue(r["at_file"].endswith("oracle_swallow_suspect.sol"))

    def test_closure_variant_same_result(self):
        sl = _compile(FX / "oracle_swallow_suspect.sol")
        f = _get_fn(sl, "OracleSwallow", "refresh")
        a = sp.oracle_swallow_suspects(f)
        b = sp.closure_oracle_swallow_suspects(f)
        self.assertFalse(sp.is_degraded(a))
        self.assertFalse(sp.is_degraded(b))
        # own-body suspect must be present in the closure result too.
        names_a = {(x["contract"], x["function"], x["catch_line"]) for x in a}
        names_b = {(x["contract"], x["function"], x["catch_line"]) for x in b}
        self.assertTrue(names_a.issubset(names_b))


# ─── Semantic path: CLEAN cases (never-false-positive) ───────────────────────


@SKIP_NO_SLITHER
class OracleSwallowCleanTest(unittest.TestCase):
    def test_catch_reverts_not_flagged(self):
        # The catch REVERTS (custom error) -> propagated, not swallowed.
        sl = _compile(FX / "oracle_catch_reverts_clean.sol")
        f = _get_fn(sl, "OracleCatchReverts", "refresh")
        recs = sp.oracle_swallow_suspects(f)
        self.assertFalse(sp.is_degraded(recs))
        self.assertEqual(recs, [])

    def test_catch_validated_by_subsequent_require_not_flagged(self):
        # The catch sets a fallback flag a later require validates -> handled.
        sl = _compile(FX / "oracle_catch_validated_clean.sol")
        f = _get_fn(sl, "OracleCatchValidated", "refresh")
        recs = sp.oracle_swallow_suspects(f)
        self.assertFalse(sp.is_degraded(recs))
        self.assertEqual(recs, [])

    def test_no_try_not_flagged(self):
        # A direct oracle read with NO try/catch -> no swallow shape to flag.
        sl = _compile(FX / "oracle_no_try_clean.sol")
        f = _get_fn(sl, "OracleNoTry", "refresh")
        recs = sp.oracle_swallow_suspects(f)
        self.assertFalse(sp.is_degraded(recs))
        self.assertEqual(recs, [])

    def test_catch_helper_reverts_not_flagged(self):
        # W2 FP fix (transitive propagate): the catch does NOT revert inline - it
        # calls a one-hop INTERNAL helper `_fail()` whose body unconditionally
        # reverts. The whole tx reverts, so this is NOT a swallow. -> NOT flagged.
        sl = _compile(FX / "oracle_catch_helper_reverts_clean.sol")
        f = _get_fn(sl, "OracleCatchHelperReverts", "refresh")
        recs = sp.oracle_swallow_suspects(f)
        self.assertFalse(sp.is_degraded(recs))
        self.assertEqual(recs, [])

    def test_catch_library_helper_reverts_not_flagged(self):
        # W2 FP fix (transitive propagate, LIBRARY hop): the catch propagates via
        # a library function `Errors.revertOnStale()` whose body unconditionally
        # reverts. -> NOT flagged.
        sl = _compile(FX / "oracle_catch_helper_reverts_clean.sol")
        f = _get_fn(sl, "OracleCatchLibraryReverts", "refresh")
        recs = sp.oracle_swallow_suspects(f)
        self.assertFalse(sp.is_degraded(recs))
        self.assertEqual(recs, [])

    def test_nonoracle_generic_name_calls_not_flagged(self):
        # W2 FP fix (tightened name set): try/catch wrapping NON-oracle external
        # calls under the dropped bare-generic names (read / quote / current).
        # Even though the catch swallows, these are not oracle reads. -> NOT flagged.
        sl = _compile(FX / "oracle_nonoracle_call_clean.sol")
        for fn in ("refresh", "refreshQuote", "refreshCurrent"):
            f = _get_fn(sl, "NonOracleSwallow", fn)
            self.assertIsNotNone(f, fn)
            recs = sp.oracle_swallow_suspects(f)
            self.assertFalse(sp.is_degraded(recs))
            self.assertEqual(recs, [], "non-oracle generic-name call must NOT flag: " + fn)


# ─── Mutation non-vacuity (FLAGGED -> clean flips) ───────────────────────────


@SKIP_NO_SLITHER
class OracleSwallowMutationTest(unittest.TestCase):
    """Prove the detector is non-vacuous: turning the swallowing catch into a
    PROPAGATING one (revert / require(false)) flips the verdict FLAGGED -> clean."""

    _BASE = (FX / "oracle_swallow_suspect.sol").read_text()
    _SWALLOW_BODY = (
        "        } catch {\n"
        "            // swallow: keep the stale price, no revert / no propagate\n"
        "        }"
    )

    def _flag_for_source(self, src: str) -> bool:
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "mut.sol"
            p.write_text(src)
            sl = _compile(p)
            f = _get_fn(sl, "OracleSwallow", "refresh")
            recs = sp.oracle_swallow_suspects(f)
            return _flagged(recs)

    def test_baseline_is_flagged(self):
        self.assertTrue(self._flag_for_source(self._BASE))

    def test_mutation_catch_revert_flips_to_clean(self):
        mutated = self._BASE.replace(
            self._SWALLOW_BODY,
            "        } catch {\n"
            "            revert(\"oracle read failed\");\n"
            "        }",
        )
        self.assertNotEqual(mutated, self._BASE, "revert mutation did not apply")
        self.assertFalse(
            self._flag_for_source(mutated),
            "reverting catch must NOT be flagged (vacuous detector!)",
        )

    def test_mutation_catch_require_false_flips_to_clean(self):
        mutated = self._BASE.replace(
            self._SWALLOW_BODY,
            "        } catch {\n"
            "            require(false, \"oracle read failed\");\n"
            "        }",
        )
        self.assertNotEqual(mutated, self._BASE, "require(false) mutation did not apply")
        self.assertFalse(
            self._flag_for_source(mutated),
            "require(false) catch must NOT be flagged (vacuous detector!)",
        )


# ─── W2 FP-fix non-vacuity (transitive-propagate suppression flips) ──────────


@SKIP_NO_SLITHER
class OracleTransitivePropagateMutationTest(unittest.TestCase):
    """Prove the transitive-propagate SUPPRESSION is non-vacuous: gutting the
    one-hop helper `_fail()` from `revert OracleDown()` to a NO-OP turns the catch
    into a genuine swallow, so the verdict must flip clean -> FLAGGED. (If the
    detector ignored the helper body entirely it would stay clean either way -
    vacuous; this proves it actually proved the always-revert.)"""

    _BASE = (FX / "oracle_catch_helper_reverts_clean.sol").read_text()

    def _flag_for_source(self, src: str) -> bool:
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "mut.sol"
            p.write_text(src)
            sl = _compile(p)
            f = _get_fn(sl, "OracleCatchHelperReverts", "refresh")
            recs = sp.oracle_swallow_suspects(f)
            return _flagged(recs)

    def test_baseline_helper_reverts_is_clean(self):
        # helper unconditionally reverts -> suppressed (clean).
        self.assertFalse(self._flag_for_source(self._BASE))

    def test_mutation_helper_noop_flips_to_flagged(self):
        # gut `_fail`'s body: `revert OracleDown();` -> `;` (a no-op). Now the
        # catch genuinely swallows -> must be FLAGGED.
        mutated = self._BASE.replace(
            "    function _fail() internal pure {\n"
            "        revert OracleDown();\n"
            "    }",
            "    function _fail() internal pure {\n"
            "        // no-op: helper no longer reverts (mutation)\n"
            "    }",
        )
        self.assertNotEqual(mutated, self._BASE, "no-op mutation did not apply")
        self.assertTrue(
            self._flag_for_source(mutated),
            "no-op helper must flip the catch to a FLAGGED swallow (non-vacuous!)",
        )

    def test_mutation_helper_conditional_revert_flips_to_flagged(self):
        # weaken `_fail` to a CONDITIONAL revert taking a param: the helper no
        # longer ALWAYS reverts (it can fall through), so we cannot prove the path
        # aborts -> conservative never-MISS -> FLAGGED.
        mutated = self._BASE.replace(
            "    function _fail() internal pure {\n"
            "        revert OracleDown();\n"
            "    }",
            "    function _fail() internal pure {\n"
            "        if (block.timestamp == 0) revert OracleDown();\n"
            "    }",
        ).replace("internal pure", "internal view")
        self.assertNotEqual(mutated, self._BASE, "conditional mutation did not apply")
        self.assertTrue(
            self._flag_for_source(mutated),
            "conditionally-reverting helper must NOT suppress (never-MISS): FLAGGED",
        )


# ─── W2 FP-fix tightened name set ────────────────────────────────────────────


class OracleNameSetTighteningTest(unittest.TestCase):
    """The bare-generic tokens that produced non-oracle FPs were dropped; the
    specific oracle method names were kept."""

    def test_bare_generic_names_dropped(self):
        for n in ("read", "quote", "current"):
            self.assertNotIn(
                n, sp._ORACLE_READ_NAMES, "bare-generic name must be dropped: " + n
            )

    def test_specific_oracle_names_kept(self):
        for n in (
            "latestrounddata",
            "latestanswer",
            "getanswer",
            "getrounddata",
            "getprice",
            "peek",
            "consult",
            "price0cumulativelast",
            "price1cumulativelast",
            "getreserves",
        ):
            self.assertIn(n, sp._ORACLE_READ_NAMES, "specific oracle name dropped: " + n)


if __name__ == "__main__":
    unittest.main(verbosity=2)
