#!/usr/bin/env python3
"""test_A8.py - migration re-establishment advisory axis (A8).

Extends tools/cross-function-invariant-coverage.py with an advisory-first,
NO-AUTO-CREDIT (verdict=needs-fuzz) detector that enumerates MIGRATION sequences:
an entry function reaching BOTH a ``_migrate*`` / reinitializer step AND a same-
tx VALUE-MOVE via internal call edges, whose steady-state invariant must be
re-established at each intermediate step AND be atomic-on-revert.

Non-vacuity: the predicate is load-bearing - mutating the migrate matcher makes
the MUTANT fixture stop firing (test_predicate_is_load_bearing), and the CLEAN
fixture (migrate step present, value-move absent) is silent (mutation-kill).
The FP-guard drops an idempotent atomic one-shot init with no observable
intermediate.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "cross-function-invariant-coverage.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "A8"


def _load():
    spec = importlib.util.spec_from_file_location("xfi_a8", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["xfi_a8"] = m
    spec.loader.exec_module(m)
    return m


class TestMigrationReestablish(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws_from_fixture(self, name):
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "src" / name).write_text((_FIX / name).read_text(), encoding="utf-8")
        return d

    def _hits(self, name):
        return self.m._migration_reestablish_hypotheses(self._ws_from_fixture(name), [])

    # ---- mutation-kill ---------------------------------------------------
    def test_mutant_fires(self):
        hits = self._hits("mutant.sol")
        self.assertEqual(len(hits), 1, "mutant (migrate+move) must fire exactly once")
        h = hits[0]
        self.assertEqual(h["function"], "migrateFromV0ToV1")
        self.assertEqual(h["verdict"], "needs-fuzz")
        self.assertIn("_migrateFromV0ToV1", h["migrate_step"])
        self.assertIn("claim", h["value_move"])
        self.assertTrue(h["observables"], "an intermediate observable must be recorded")

    def test_clean_silent(self):
        # CLEAN = migrate step present but NO same-tx value move -> predicate unmet.
        self.assertEqual(self._hits("clean.sol"), [], "clean must not fire")

    # ---- non-vacuity: the migrate predicate is load-bearing --------------
    def test_predicate_is_load_bearing(self):
        # Neutralise the migrate-step matcher; the mutant must STOP firing,
        # proving the migrate half of the predicate is what makes it fire.
        saved = self.m._MR_MIGRATE_RE
        try:
            self.m._MR_MIGRATE_RE = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(self._hits("mutant.sol"), [],
                             "neutralising the migrate predicate must silence the mutant")
        finally:
            self.m._MR_MIGRATE_RE = saved
        # restored predicate fires again
        self.assertEqual(len(self._hits("mutant.sol")), 1)

    def test_move_predicate_is_load_bearing(self):
        saved = self.m._MR_MOVE_RE
        try:
            self.m._MR_MOVE_RE = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(self._hits("mutant.sol"), [],
                             "neutralising the value-move predicate must silence the mutant")
        finally:
            self.m._MR_MOVE_RE = saved

    # ---- FP-guard --------------------------------------------------------
    def test_fp_guard_drops_atomic_oneshot(self):
        # reinit + value-move but NO observable intermediate -> dropped.
        self.assertEqual(self._hits("fp_atomic_oneshot.sol"), [],
                         "idempotent atomic one-shot init is not a re-establishment obligation")

    def test_fp_guard_keeps_when_observable_added(self):
        # add an external call to the reinit step -> now an observable exists.
        src = (_FIX / "fp_atomic_oneshot.sol").read_text().replace(
            "function _reinit() internal { inited = true; }",
            "function _reinit() internal { inited = true; oracle.poke(); }")
        src = src.replace("contract InitOnce {",
                          "interface IO { function poke() external; }\ncontract InitOnce {\n    IO oracle;")
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "src" / "x.sol").write_text(src, encoding="utf-8")
        hits = self.m._migration_reestablish_hypotheses(d, [])
        self.assertEqual(len(hits), 1)
        self.assertIn("external-call", hits[0]["observables"])

    def test_emit_event_name_not_a_migrate_callee(self):
        # `emit FundsMigrated(...)` must NOT be captured as a migrate STEP callee.
        src = ("pragma solidity ^0.8.0;\ncontract E {\n"
               "  event FundsMigrated(uint256);\n"
               "  function f(uint256 a) public { emit FundsMigrated(a); transfer(a); }\n"
               "  function transfer(uint256 a) internal {}\n}\n")
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "src" / "e.sol").write_text(src, encoding="utf-8")
        self.assertEqual(self.m._migration_reestablish_hypotheses(d, []), [],
                         "an emitted event name is not a migrate callee")

    # ---- dedup vs the existing detector ----------------------------------
    def test_dedup_tags_covered_by_xfi_requirement(self):
        from dataclasses import dataclass, field

        # A requirement whose function_names include the entry -> hit is tagged covered.
        req = self.m.Requirement(kind="sibling-pair", label="x", invariant_hint="y",
                                 functions=[{"name": "migrateFromV0ToV1", "file": "src/mutant.sol", "line": 1}],
                                 function_names={"migrateFromV0ToV1"})
        ws = self._ws_from_fixture("mutant.sol")
        hits = self.m._migration_reestablish_hypotheses(ws, [req])
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]["covered_by_xfi_requirement"],
                        "overlap with an enumerated requirement must be tagged")
        # with no requirement it is distinct (net-new).
        hits2 = self.m._migration_reestablish_hypotheses(ws, [])
        self.assertFalse(hits2[0]["covered_by_xfi_requirement"])

    # ---- advisory-first gating + NO-AUTO-CREDIT --------------------------
    def test_advisory_off_by_default(self):
        os.environ.pop("AUDITOOOR_XFI_MIGRATION_REESTABLISH", None)
        ws = self._ws_from_fixture("mutant.sol")
        res = self.m.evaluate(ws)
        self.assertIsNone(res.get("migration_reestablish"),
                          "advisory must be OFF (None) by default")
        self.assertFalse((ws / ".auditooor" / "migration_reestablish_hypotheses.jsonl").exists(),
                         "no jsonl emitted when disabled")

    def test_enabled_emits_needs_fuzz_jsonl(self):
        os.environ["AUDITOOOR_XFI_MIGRATION_REESTABLISH"] = "1"
        try:
            ws = self._ws_from_fixture("mutant.sol")
            res = self.m.evaluate(ws)
            summ = res.get("migration_reestablish")
            self.assertIsNotNone(summ)
            self.assertTrue(summ["enabled"])
            self.assertEqual(summ["verdict"], "needs-fuzz")
            self.assertGreaterEqual(summ["count"], 1)
            jl = ws / ".auditooor" / "migration_reestablish_hypotheses.jsonl"
            self.assertTrue(jl.exists())
            rows = [json.loads(x) for x in jl.read_text().splitlines() if x.strip()]
            self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in rows),
                            "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        finally:
            os.environ.pop("AUDITOOOR_XFI_MIGRATION_REESTABLISH", None)


if __name__ == "__main__":
    unittest.main()
