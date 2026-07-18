#!/usr/bin/env python3
"""M2 - Move discarded-check-result axis (exploit-class-coverage.py).

A Move auth/membership PREDICATE (vector::contains / option::is_some /
table::contains ...) returns a bool/Option the caller SILENTLY DISCARDS (bare
statement expr or `let _ =`) instead of gating control flow with assert!/if -
so the enforcement never runs and any caller passes the gate. Advisory-first,
env-gated OFF (AUDITOOOR_DISCARDED_CHECK_SCAN=1); rows carry
hypothesis_verdict='needs-fuzz' with an EMPTY probe_verdict (NO auto-credit).
SYNTHETIC Move fixture - there is no Move ws in the fleet; the clean+vulnerable
pair uses the real Move membership-gate idiom. Corpus anchor: Typus (Sui Move)
CRITICAL ~$3.44M Oct-2025.

Load-bearing predicates (mutating any ONE breaks a case below):
  1. VULNERABLE fixture (bare `vector::contains(...);`) -> fires.
  2. CLEAN fixture (`assert!(vector::contains(...), E)`) -> does NOT fire.
  3. MUTATION-KILL: mutate the clean copy in a tmpdir (drop the assert! gate)
     -> mutant fires; the un-mutated clean copy stays silent.
  4. if/while/let-binding/return consumers -> do NOT fire (FP-guard).
  5. `let _ = pred(...)` explicit discard -> fires.
  6. DEDUP boundary: a discarded NON-predicate CALL return (coin::withdraw,
     W6-P1 unchecked-return-value) does NOT fire - this axis is a PREDICATE at
     a trust gate, not a call-return.
  7. verdict='needs-fuzz' + probe_verdict='' (no auto-credit) + advisory=True.
  8. env-gate OFF by default; .move-only.
"""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent
_s = importlib.util.spec_from_file_location("ecc", _T / "exploit-class-coverage.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)

_FIX = _T.parent / "detectors" / "move_wave2" / "test_fixtures"
_VULN = _FIX / "oracle_update_ignores_contains_vulnerable.move"
_CLEAN = _FIX / "oracle_update_ignores_contains_clean.move"


class TDiscardedCheck(unittest.TestCase):
    def test_vulnerable_fixture_fires(self):
        rows = m.discarded_check_rows(_VULN.read_text(), "x.move")
        self.assertEqual(len(rows), 1, f"only the discarded contains must fire: {rows}")
        r = rows[0]
        self.assertEqual(r["axis"], "discarded-check-result")
        self.assertEqual(r["predicate"], "vector::contains")
        self.assertEqual(r["class"], "access-control-composition")

    def test_clean_fixture_silent(self):
        # the assert!-gated predicate is USED - benign, no hypothesis.
        self.assertEqual(m.discarded_check_rows(_CLEAN.read_text(), "x.move"), [])

    def test_mutation_kill_clean_to_vulnerable(self):
        # cp clean -> tmpdir, inject a BEHAVIOR-CHANGING mutation (drop the
        # assert! gate, discard the predicate) -> mutant fires; clean silent.
        clean_src = _CLEAN.read_text()
        self.assertEqual(m.discarded_check_rows(clean_src, "c.move"), [],
                         "clean copy must NOT fire (benign)")
        d = Path(tempfile.mkdtemp())
        tgt = d / "oracle_update_ignores_contains.move"
        mutant = clean_src.replace(
            "assert!(vector::contains(&config.updaters, &who), E_NOT_UPDATER);",
            "vector::contains(&config.updaters, &who);")
        self.assertIn("        vector::contains(&config.updaters, &who);", mutant,
                      "mutation must land (behavior-changing)")
        tgt.write_text(mutant)
        rows = m.scan_discarded_paths([tgt])
        self.assertEqual(len(rows), 1, f"mutant must fire: {rows}")
        self.assertEqual(rows[0]["predicate"], "vector::contains")

    def test_consuming_contexts_are_clean(self):
        # every gate-consuming form must be silent (FP-guard).
        base = ("module a::b {{ use std::vector;\n"
                "public fun f(v: &vector<address>, a: address) {{\n"
                "  {}\n  do_it();\n}} fun do_it() {{}} }}")
        for used in (
            "assert!(vector::contains(v, &a), 1);",
            "if (vector::contains(v, &a)) {{ abort 1 }};",
            "while (vector::contains(v, &a)) {{ do_it() }};",
            "let ok = vector::contains(v, &a); assert!(ok, 1);",
            "if (!vector::contains(v, &a)) {{ abort 1 }};",
        ):
            src = base.format(used)
            self.assertEqual(m.discarded_check_rows(src, "x.move"), [],
                             f"consuming form must be clean: {used!r}")

    def test_underscore_bind_discard_fires(self):
        src = ("module a::b { use std::option;\n"
               "public fun f(o: &option::Option<u64>) {\n"
               "  let _ = option::is_some(o);\n  go();\n} fun go() {} }")
        rows = m.discarded_check_rows(src, "x.move")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["predicate"], "option::is_some")

    def test_dedup_vs_unchecked_return_value(self):
        # W6-P1 boundary: a discarded NON-predicate CALL return is NOT this axis.
        src = ("module a::b { use aptos_framework::coin;\n"
               "public fun f(s: &signer) {\n"
               "  let _ = coin::withdraw<u64>(s, 1);\n  go();\n} fun go() {} }")
        self.assertEqual(m.discarded_check_rows(src, "x.move"), [],
                         "coin::withdraw is a call-return (W6-P1), not a trust-gate predicate")

    def test_no_auto_credit_schema(self):
        r = m.discarded_check_rows(_VULN.read_text(), "x.move")[0]
        self.assertEqual(r["hypothesis_verdict"], "needs-fuzz")
        self.assertEqual(r["probe_verdict"], "")  # NO auto-credit
        self.assertTrue(r["advisory"])

    def test_env_gate_off_by_default(self):
        os.environ.pop(m.DISCARDED_CHECK_ENV, None)
        self.assertEqual(m.gated_discarded_rows(_VULN.read_text(), "x.move"), [],
                         "axis must be OFF by default")
        os.environ[m.DISCARDED_CHECK_ENV] = "1"
        try:
            on = m.gated_discarded_rows(_VULN.read_text(), "x.move")
        finally:
            os.environ.pop(m.DISCARDED_CHECK_ENV, None)
        self.assertEqual(len(on), 1, "axis must fire when env-enabled")

    def test_non_move_file_never_fires(self):
        os.environ[m.DISCARDED_CHECK_ENV] = "1"
        try:
            self.assertEqual(m.gated_discarded_rows(_VULN.read_text(), "x.sol"), [],
                             "non-.move file must skip the Move axis")
        finally:
            os.environ.pop(m.DISCARDED_CHECK_ENV, None)

    def test_ledger_gate_unchanged_by_axis(self):
        # DEDUP A1: the axis must NOT touch the exploit-class ledger verdict.
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / "m.move").write_text(_VULN.read_text())
        r = m.evaluate(ws)
        # no ledger authored -> gate still fails on undispositioned classes,
        # unaffected by any Move discarded-check hypotheses.
        self.assertTrue(r["verdict"].startswith("fail"))
        self.assertEqual(len(r["classes"]), len(m.CANONICAL_CLASSES))


if __name__ == "__main__":
    unittest.main()
