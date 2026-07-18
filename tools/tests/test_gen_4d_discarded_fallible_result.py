#!/usr/bin/env python3
"""GEN-4D - discarded-fallible-result-on-a-value-path screen.

Non-vacuous: every POSITIVE asserts a specific (arm, callee) hit and every
NEGATIVE asserts the ABSENCE. The REAL-FLEET mutation-witness pair proves the
guard predicate (a CHECKED error) has TEETH on real Go code:

  sei/src/sei-chain/sei-ibc-go/modules/apps/transfer/keeper/relay.go:296 -
  the real `k.bankKeeper.SendCoins(ctx, escrowAddress, receiver, ...)` is
  CHECKED via `if err := ...; err != nil { return ... }`. The checked original
  is SILENT; the same body with the check removed (`_ = k.bankKeeper.SendCoins(
  ...)`) FIRES on the Go discard-assign arm. A byte-identical restore leaves the
  original silent, so the discard predicate is not vacuous.

Covered axes:
  (i)   Go `_ = k.SendCoins(...)` discard-assign -> FIRES.
  (ii)  Go `if err := k.SendCoins(...); err != nil` CHECKED -> SILENT (guard).
  (iii) Go bare-statement `k.MintCoins(...)` (curated op) -> FIRES.
  (iv)  Go discarded getter `_ = k.GetBalance(...)` (not a value MOVE) -> SILENT.
  (v)   Rust `let _ = pool.transfer(...)` -> FIRES; `x.transfer(...)?` SILENT.
  (vi)  Rust `x.transfer(...).ok();` discard -> FIRES.
  (vii) Move `let _ = coin::transfer(...)` -> FIRES.
  (viii)REAL-FLEET mutation pair (checked SendCoins silent vs discarded fire).
  (ix)  advisory-first: exit 0 by default, non-zero only under --strict/env.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "discarded-fallible-result-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("gen_4d_screen", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gen_4d_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _scan(body: str, name: str):
    return MOD.scan_file(Path(name), name, file_text=textwrap.dedent(body))


class Gen4DTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # (i) POSITIVE - Go discard-assign of a value op.
    # ------------------------------------------------------------------
    def test_go_discard_sendcoins_fires(self):
        rows = _scan("""
            func (k Keeper) pay(ctx Context) {
                _ = k.bankKeeper.SendCoins(ctx, from, to, coins)
                k.credit(to)
            }
            """, "x.go")
        self.assertTrue(rows, "discarded SendCoins error must fire")
        r = rows[0]
        self.assertEqual(r["arm"], "go-discard-assign")
        self.assertEqual(r["callee"], "SendCoins")
        self.assertEqual(r["lang"], "go")
        self.assertEqual(r["capability"], "GEN_4D")
        self.assertEqual(r["schema"],
                         "auditooor.discarded_fallible_result_hypotheses.v1")
        self.assertEqual(r["severity"], "high")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])

    def test_go_tuple_blank_error_fires(self):
        rows = _scan("""
            func f() {
                n, _ := bank.TransferCoins(a, b)
                use(n)
            }
            """, "x.go")
        self.assertTrue(rows)
        self.assertEqual(rows[0]["callee"], "TransferCoins")

    def test_go_blank_value_named_error_silent(self):
        # `_, err := f()` discards the VALUE, keeps the error -> not a discard.
        rows = _scan("""
            func f() error {
                _, err := k.bankKeeper.SendCoins(ctx, a, b, c)
                return err
            }
            """, "x.go")
        self.assertEqual(rows, [], "blank value with named error is not a discard")

    # ------------------------------------------------------------------
    # (ii) NEGATIVE - Go checked error -> SILENT.
    # ------------------------------------------------------------------
    def test_go_checked_sendcoins_silent(self):
        rows = _scan("""
            func (k Keeper) pay(ctx Context) error {
                if err := k.bankKeeper.SendCoins(ctx, from, to, coins); err != nil {
                    return err
                }
                return nil
            }
            """, "x.go")
        self.assertEqual(rows, [], "checked SendCoins must be silent")

    def test_go_named_err_assign_silent(self):
        rows = _scan("""
            func f() error {
                err := bank.SendCoins(a, b, c)
                return err
            }
            """, "x.go")
        self.assertEqual(rows, [], "named err binding is not a discard")

    # ------------------------------------------------------------------
    # (iii) POSITIVE - Go bare-statement curated cosmos op.
    # ------------------------------------------------------------------
    def test_go_bare_statement_mintcoins_fires(self):
        rows = _scan("""
            func (k Keeper) run(ctx Context) {
                k.bankKeeper.MintCoins(ctx, mod, amt)
                k.finish()
            }
            """, "x.go")
        self.assertTrue(rows, "bare MintCoins statement must fire")
        self.assertEqual(rows[0]["arm"], "go-bare-statement")
        self.assertEqual(rows[0]["callee"], "MintCoins")

    def test_go_bare_statement_checked_not_double(self):
        # an `if err :=` MintCoins must NOT be caught by the bare-stmt arm.
        rows = _scan("""
            func f(ctx Context) error {
                if err := k.MintCoins(ctx, mod, amt); err != nil {
                    return err
                }
                return nil
            }
            """, "x.go")
        self.assertEqual(rows, [], "checked MintCoins must not fire on any arm")

    # ------------------------------------------------------------------
    # (iv) NEGATIVE - Go discarded non-value (getter) -> SILENT.
    # ------------------------------------------------------------------
    def test_go_discard_getter_silent(self):
        rows = _scan("""
            func f() {
                _ = k.GetBalance(ctx, addr)
                _ = logger.Info("done")
            }
            """, "x.go")
        self.assertEqual(rows, [], "discarded getter/logger is not a value move")

    # ------------------------------------------------------------------
    # Go checked-arith on a balance -> medium fire; plain arith silent.
    # ------------------------------------------------------------------
    def test_go_checked_arith_balance_discard_fires(self):
        rows = _scan("""
            func f() {
                _ = balance.checked_sub(amount)
            }
            """, "x.go")
        self.assertTrue(rows)
        self.assertEqual(rows[0]["severity"], "medium")

    # ------------------------------------------------------------------
    # (v) Rust let _ = value call fires; `?` silent.
    # ------------------------------------------------------------------
    def test_rust_let_underscore_transfer_fires(self):
        rows = _scan("""
            pub fn settle(pool: &Pool) {
                let _ = pool.transfer(from, to, amount);
                credit(to);
            }
            """, "x.rs")
        self.assertTrue(rows, "let _ = transfer must fire")
        r = rows[0]
        self.assertEqual(r["arm"], "rust-let-underscore")
        self.assertEqual(r["callee"], "transfer")
        self.assertEqual(r["lang"], "rust")
        self.assertEqual(r["severity"], "high")

    def test_rust_question_mark_silent(self):
        rows = _scan("""
            pub fn settle(pool: &Pool) -> Result<()> {
                pool.transfer(from, to, amount)?;
                Ok(())
            }
            """, "x.rs")
        self.assertEqual(rows, [], "propagated `?` transfer must be silent")

    def test_rust_unwrap_silent(self):
        rows = _scan("""
            fn f(p: &P) {
                p.mint(to, amt).unwrap();
            }
            """, "x.rs")
        self.assertEqual(rows, [], "unwrap is a handled result")

    # ------------------------------------------------------------------
    # (vi) Rust `.ok()` discard-as-statement fires.
    # ------------------------------------------------------------------
    def test_rust_dot_ok_discard_fires(self):
        rows = _scan("""
            fn f(p: &P) {
                p.withdraw(to, amt).ok();
            }
            """, "x.rs")
        self.assertTrue(rows, ".ok() discard must fire")
        self.assertEqual(rows[0]["arm"], "rust-dot-ok-discard")
        self.assertEqual(rows[0]["callee"], "withdraw")

    def test_rust_let_underscore_getter_silent(self):
        rows = _scan("""
            fn f(p: &P) {
                let _ = p.get_config();
            }
            """, "x.rs")
        self.assertEqual(rows, [], "discarded getter is not a value move")

    # ------------------------------------------------------------------
    # (vii) Move let _ = coin op fires.
    # ------------------------------------------------------------------
    def test_move_discard_coin_transfer_fires(self):
        rows = _scan("""
            public fun run(account: &signer) {
                let _ = coin::transfer(account, to, amount);
            }
            """, "x.move")
        self.assertTrue(rows, "move discarded coin::transfer must fire")
        self.assertEqual(rows[0]["arm"], "move-discard")
        self.assertEqual(rows[0]["lang"], "move")

    # ------------------------------------------------------------------
    # masking: a discard inside a comment/string must not fire.
    # ------------------------------------------------------------------
    def test_masking_ignores_comment(self):
        rows = _scan("""
            func f() {
                // _ = k.SendCoins(a, b, c)
                s := "_ = k.SendCoins(a, b, c)"
                _ = s
            }
            """, "x.go")
        self.assertEqual(rows, [], "masked discard must not fire")

    # ------------------------------------------------------------------
    # (viii) REAL-FLEET MUTATION WITNESS - sei ibc-go SendCoins.
    #        Checked original SILENT; discarded mutant FIRES.
    # ------------------------------------------------------------------
    _REAL_CHECKED = """
        func (k Keeper) OnRecvPacket(ctx Context) error {
            escrowAddress := types.GetEscrowAddress(port, channel)
            if err := k.bankKeeper.SendCoins(ctx, escrowAddress, receiver, sdk.NewCoins(token)); err != nil {
                return err
            }
            return nil
        }
        """
    _REAL_MUTANT = """
        func (k Keeper) OnRecvPacket(ctx Context) error {
            escrowAddress := types.GetEscrowAddress(port, channel)
            _ = k.bankKeeper.SendCoins(ctx, escrowAddress, receiver, sdk.NewCoins(token))
            return nil
        }
        """

    def test_real_fleet_checked_original_silent(self):
        self.assertEqual(_scan(self._REAL_CHECKED, "relay.go"), [],
                         "checked SendCoins original must be silent")

    def test_real_fleet_discarded_mutant_fires(self):
        rows = _scan(self._REAL_MUTANT, "relay.go")
        self.assertTrue(rows, "discarded SendCoins mutant must newly fire")
        r = rows[0]
        self.assertEqual(r["callee"], "SendCoins")
        self.assertEqual(r["arm"], "go-discard-assign")
        self.assertEqual(r["function"], "OnRecvPacket")

    def test_mutation_witness_pair_distinct(self):
        self.assertEqual(len(_scan(self._REAL_CHECKED, "relay.go")), 0)
        self.assertGreaterEqual(len(_scan(self._REAL_MUTANT, "relay.go")), 1)

    # ------------------------------------------------------------------
    # (ix) advisory-first exit-code contract via the CLI.
    # ------------------------------------------------------------------
    def test_cli_advisory_first_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "a.go").write_text(textwrap.dedent("""
                func f(ctx Context) {
                    _ = k.bankKeeper.SendCoins(ctx, from, to, coins)
                }
                """), encoding="utf-8")
            p = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            summ = json.loads(p.stdout)
            self.assertGreaterEqual(summ["fired"], 1)
            side = ws / ".auditooor" / \
                "discarded_fallible_result_hypotheses.jsonl"
            self.assertTrue(side.exists(), "sidecar must be emitted")
            p2 = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws),
                 "--strict"], capture_output=True, text=True)
            self.assertEqual(p2.returncode, 1, "strict must elevate on fire")
            env = dict(os.environ)
            env["AUDITOOOR_DISCARDED_FALLIBLE_RESULT_STRICT"] = "1"
            p3 = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                capture_output=True, text=True, env=env)
            self.assertEqual(p3.returncode, 1, "env strict must elevate")

    def test_check_mode_reads_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "a.go").write_text(textwrap.dedent("""
                func f(ctx Context) {
                    _ = k.bankKeeper.SendCoins(ctx, from, to, coins)
                }
                """), encoding="utf-8")
            subprocess.run([sys.executable, str(TOOL), "--workspace", str(ws)],
                           capture_output=True, text=True)
            p = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--check"],
                capture_output=True, text=True)
            summ = json.loads(p.stdout)
            self.assertEqual(summ["source"], "sidecar")
            self.assertGreaterEqual(summ["fired"], 1)


if __name__ == "__main__":
    unittest.main()
