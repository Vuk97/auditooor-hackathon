#!/usr/bin/env python3
"""M1 - Move Coin<T>/Balance<T> value-conservation lane (coupled-state-
completeness.py, set_kind='move-coin-conservation').

NON-VACUOUS regression for the Move resource-linearity law sum(parts) == whole:
a `split`-shaped fn that packs a value-bearing part off a `&mut Coin` whole but
OMITS the paired whole-decrement mints value. Advisory-first, env-gated OFF
(AUDITOOOR_MOVE_CONSERVATION=1); rows carry hypothesis_verdict='needs-fuzz' with
an EMPTY probe_verdict (NO auto-credit). SYNTHETIC Move fixture - there is no
Move ws in the fleet; the clean+vulnerable pair uses the real Coin `value` idiom.

Load-bearing predicates (mutating any ONE breaks a case below):
  1. VULNERABLE split_bad (part packed, whole not decremented) -> fires.
  2. CLEAN split (whole.value -= amount present) -> does NOT fire (paired join).
  3. mint (no &mut whole) -> does NOT fire (authorized value creation FP-guard).
  4. env-gate OFF -> zero move rows even on the vulnerable fixture.
  5. verdict='needs-fuzz' + probe_verdict='' (no auto-credit).
  6. distinct set_kind from A9 interruption (dedup boundary).
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent
_s = importlib.util.spec_from_file_location("csc", _T / "coupled-state-completeness.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)

_FIXTURE = (_T.parent / "detectors" / "move_wave2" / "test_fixtures"
            / "coin_split_join_desync.move")


def _move_rows(src, rel="x.move"):
    return [r for r in m._move_coin_conservation_rows(src, rel)]


class TMove(unittest.TestCase):
    def test_vulnerable_split_fires(self):
        rows = _move_rows(_FIXTURE.read_text())
        self.assertEqual(len(rows), 1, f"only split_bad must fire, got {rows}")
        r = rows[0]
        self.assertEqual(r["set_kind"], "move-coin-conservation")
        self.assertEqual(r["omits"], ["whole.value"])
        self.assertIn("split_bad", r["question"])

    def test_clean_split_and_mint_do_not_fire(self):
        # the fixture's CLEAN `split` (has the decrement) and `mint` (no source
        # whole) must be silent; only split_bad survives.
        fired = {r["question"].split("`")[1] for r in _move_rows(_FIXTURE.read_text())}
        self.assertEqual(fired, {"split_bad"})

    def test_injected_join_makes_it_clean(self):
        # inject the paired decrement at the L14 anchor -> conserves -> no fire
        # (mutation-kill: the clean copy is silent).
        lines = _FIXTURE.read_text().splitlines()
        self.assertIn("join MISSING (L14 below)", lines[13])
        lines[13] = "        whole.value = whole.value - amount;"
        self.assertEqual(_move_rows("\n".join(lines)), [])

    def test_paired_decrement_variants_are_clean(self):
        # `-=` and delegated coin::split(&mut whole,..) both count as the join.
        for join in ("whole.value = whole.value - amount;",
                     "whole.value -= amount;",
                     "let part = coin::split(&mut whole, amount);"):
            src = ("module a::b { struct Coin<phantom T> has store { value: u64 }\n"
                   "public fun split<T>(whole: &mut Coin<T>, amount: u64): Coin<T> {\n"
                   f"  {join}\n  Coin<T> {{ value: amount }}\n}} }}")
            self.assertEqual(_move_rows(src), [], f"join `{join}` must be clean")

    def test_zero_value_ctor_not_flagged(self):
        # an empty-coin ctor packs value 0 - creates no value, must NOT fire even
        # with a &mut whole in scope.
        src = ("module a::b { struct Coin<phantom T> has store { value: u64 }\n"
               "public fun drain<T>(whole: &mut Coin<T>): Coin<T> {\n"
               "  Coin<T> { value: 0 }\n} }")
        self.assertEqual(_move_rows(src), [])

    def test_balance_type_also_fires(self):
        src = ("module a::b { struct Balance<phantom T> has store { value: u64 }\n"
               "public fun cut<T>(whole: &mut Balance<T>, amount: u64): Balance<T> {\n"
               "  Balance<T> { value: amount }\n} }")
        rows = _move_rows(src)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["omits"], ["whole.value"])

    def test_mint_without_source_whole_never_fires(self):
        # authorized creation (no &mut Coin param) is NOT a broken split.
        src = ("module a::b { struct Coin<phantom T> has store { value: u64 }\n"
               "public fun mint<T>(amount: u64): Coin<T> { Coin<T> { value: amount } }\n}")
        self.assertEqual(_move_rows(src), [])

    def test_needs_fuzz_no_auto_credit(self):
        r = _move_rows(_FIXTURE.read_text())[0]
        self.assertEqual(r["hypothesis_verdict"], "needs-fuzz")
        self.assertEqual(r["probe_verdict"], "")  # NO auto-credit
        self.assertTrue(r["advisory"])

    def test_env_gate_off_by_default(self):
        # via the public _rows_for_source: OFF by default, ON only when env=1.
        os.environ.pop(m.MOVE_CONSERVATION_ENV, None)
        off = [r for r in m._rows_for_source(_FIXTURE.read_text(), "x.move")
               if r["set_kind"] == "move-coin-conservation"]
        self.assertEqual(off, [], "move lane must be OFF by default")
        os.environ[m.MOVE_CONSERVATION_ENV] = "1"
        try:
            on = [r for r in m._rows_for_source(_FIXTURE.read_text(), "x.move")
                  if r["set_kind"] == "move-coin-conservation"]
        finally:
            os.environ.pop(m.MOVE_CONSERVATION_ENV, None)
        self.assertEqual(len(on), 1, "move lane must fire when env-enabled")

    def test_non_move_file_never_fires(self):
        # a .sol/.rs file must not enter the Move lane even with env on.
        os.environ[m.MOVE_CONSERVATION_ENV] = "1"
        try:
            rows = [r for r in m._rows_for_source(_FIXTURE.read_text(), "x.sol")
                    if r["set_kind"] == "move-coin-conservation"]
        finally:
            os.environ.pop(m.MOVE_CONSERVATION_ENV, None)
        self.assertEqual(rows, [], "non-.move file must skip the Move lane")

    def test_distinct_from_a9_interruption_kind(self):
        # dedup boundary: M1 is the in-body arithmetic conservation law; A9 is the
        # cross-fn interruption/partial-write SET. Distinct set_kind, distinct row.
        r = _move_rows(_FIXTURE.read_text())[0]
        self.assertNotEqual(r["set_kind"], "interruption")
        self.assertEqual(r["set_kind"], "move-coin-conservation")

    def test_emit_worklist_end_to_end(self):
        # full CLI path: --file with env on emits exactly the one Move row.
        os.environ[m.MOVE_CONSERVATION_ENV] = "1"
        try:
            ws = Path(tempfile.mkdtemp())
            (ws / ".auditooor").mkdir()
            (ws / "purse.move").write_text(_FIXTURE.read_text())
            (ws / ".auditooor" / "inscope_units.jsonl").write_text(
                '{"file": "purse.move", "function": "split_bad"}\n')
            self.assertEqual(
                m.main(["--workspace", str(ws), "--emit-worklist"]), 0)
            import json
            wl = ws / ".auditooor" / "coupled_state_worklist.jsonl"
            rows = [json.loads(l) for l in wl.read_text().splitlines() if l.strip()]
            move = [r for r in rows if r["set_kind"] == "move-coin-conservation"]
            self.assertEqual(len(move), 1)
        finally:
            os.environ.pop(m.MOVE_CONSERVATION_ENV, None)


if __name__ == "__main__":
    unittest.main()
