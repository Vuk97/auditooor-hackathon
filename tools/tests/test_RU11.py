#!/usr/bin/env python3
"""RU11 - Drop-delegated safety post-condition unsoundness advisory axis.

Non-vacuous: each positive asserts a specific hit + arm, each negative asserts
absence; mutating the predicate (dropping the safety-op stage-1 gate, the
suppression arm, the drop-scoped panic arm, the drop-scoped early-move arm, or
the benign-control silence) breaks a case. Pins the mutation-verified
monero-oxide ClsagMultisigMaskReceiver fixture pair (clean=0, mutant=1 arm A).
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-detector-runner.py"
FIX = Path(__file__).resolve().parent / "fixtures" / "RU11"


def _load():
    spec = importlib.util.spec_from_file_location("rust_detector_runner_ru11", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner_ru11"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _write(ws: Path, rel: str, body: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _ds_hits(ws: Path):
    os.environ["AUDITOOR_RUST_DROPSAFETY_AXIS"] = "1"
    summary = MOD.scan_workspace(ws)
    axis = summary.get("rust_dropsafety_axis", {})
    return axis.get("hypotheses", [])


class RU11Tests(unittest.TestCase):
    def test_benign_safety_drop_silent(self):
        # THE control: a safety-Drop (zeroize) with no suppression, no panic op,
        # no early move -> RAII invariant intact -> silent.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/a.rs", """
                impl Drop for MaskReceiver {
                    fn drop(&mut self) {
                        (*self.buf.lock()).zeroize();
                    }
                }
                """)
            self.assertEqual(len(_ds_hits(ws)), 0)

    def test_arm_a_forget_suppression_fires(self):
        # arm A: a mem::forget of the safety-Drop type in the module defeats
        # runs-once -> fires.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/b.rs", """
                impl Drop for MaskReceiver {
                    fn drop(&mut self) {
                        (*self.buf.lock()).zeroize();
                    }
                }
                fn leak(r: MaskReceiver) {
                    core::mem::forget(r);
                }
                """)
            hits = _ds_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["drop_type"], "MaskReceiver")
            self.assertIn(
                "drop_suppression_forget_manuallydrop", hits[0]["extra"]["arms"]
            )

    def test_arm_a_manuallydrop_fires(self):
        # arm A variant: ManuallyDrop wrap also suppresses the post-condition.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "core/src/c.rs", """
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.mutex.unlock();
                    }
                }
                fn hold(g: Guard) -> ManuallyDrop<Guard> {
                    ManuallyDrop::new(g)
                }
                """)
            hits = _ds_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertIn(
                "drop_suppression_forget_manuallydrop", hits[0]["extra"]["arms"]
            )

    def test_arm_b_panic_in_drop_fires(self):
        # arm B: a panic-capable op inside the drop body aborts the settle
        # half-done (in-order/runs-once broken) -> fires.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "core/src/d.rs", """
                impl Drop for Settler {
                    fn drop(&mut self) {
                        let bal = self.balances.get(&self.id).expect("missing");
                        self.settle(bal);
                    }
                }
                """)
            hits = _ds_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertIn("panic_in_drop", hits[0]["extra"]["arms"])

    def test_arm_c_early_move_in_drop_fires(self):
        # arm C: a move-out (.take()) inside the drop can leave the post-cond
        # running on emptied state / an early return skips it -> fires.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "core/src/e.rs", """
                impl Drop for MaskReceiver {
                    fn drop(&mut self) {
                        let inner = self.buf.take();
                        drop(inner);
                        (*self.buf.lock()).zeroize();
                    }
                }
                """)
            hits = _ds_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertIn("early_return_or_move_in_drop", hits[0]["extra"]["arms"])

    def test_no_safety_op_suppressed(self):
        # stage-1 gate: a Drop that only logs (no zeroize/unlock/settle/clear)
        # is out of class even WITH a mem::forget in the module -> silent.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "core/src/f.rs", """
                impl Drop for Logger {
                    fn drop(&mut self) {
                        println!("dropping {}", self.name);
                    }
                }
                fn leak(l: Logger) {
                    core::mem::forget(l);
                }
                """)
            self.assertEqual(len(_ds_hits(ws)), 0)

    def test_take_outside_drop_not_flagged(self):
        # FP-guard: .take()/.expect() in a NON-drop method (legit consumption)
        # must not trip the drop-scoped arms. Benign safety-Drop -> silent.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/g.rs", """
                impl MaskReceiver {
                    fn recv(self) -> Option<Scalar> {
                        let mut lock = self.buf.lock();
                        let res = lock.take();
                        (*lock).zeroize();
                        res.expect("set")
                    }
                }
                impl Drop for MaskReceiver {
                    fn drop(&mut self) {
                        (*self.buf.lock()).zeroize();
                    }
                }
                """)
            self.assertEqual(len(_ds_hits(ws)), 0)

    def test_derived_drop_not_flagged(self):
        # only EXPLICIT `impl Drop for T` is considered; a derived ZeroizeOnDrop
        # with no explicit drop body is out of scope even with a forget present.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "ringct/clsag/src/h.rs", """
                #[derive(Zeroize, ZeroizeOnDrop)]
                pub struct Secret {
                    scalar: Scalar,
                }
                fn leak(s: Secret) {
                    core::mem::forget(s);
                }
                """)
            self.assertEqual(len(_ds_hits(ws)), 0)

    def test_axis_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "core/src/b.rs", """
                impl Drop for MaskReceiver {
                    fn drop(&mut self) { (*self.buf.lock()).zeroize(); }
                }
                fn leak(r: MaskReceiver) { core::mem::forget(r); }
                """)
            os.environ.pop("AUDITOOR_RUST_DROPSAFETY_AXIS", None)
            summary = MOD.scan_workspace(ws)
            self.assertNotIn("rust_dropsafety_axis", summary)

    def test_needs_fuzz_no_auto_credit(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "core/src/b.rs", """
                impl Drop for MaskReceiver {
                    fn drop(&mut self) { (*self.buf.lock()).zeroize(); }
                }
                fn leak(r: MaskReceiver) { core::mem::forget(r); }
                """)
            os.environ["AUDITOOR_RUST_DROPSAFETY_AXIS"] = "1"
            summary = MOD.scan_workspace(ws)
            axis = summary["rust_dropsafety_axis"]
            self.assertEqual(axis["verdict"], "needs-fuzz")
            self.assertFalse(axis["auto_credit"])
            self.assertEqual(
                axis["sibling_detector"],
                "rust.lockpoison.panic_while_holding_guard",
            )
            h = axis["hypotheses"][0]
            self.assertEqual(h["extra"]["verdict"], "needs-fuzz")
            self.assertIsNone(h["extra"]["covered_by"])  # dedup: net-new vs RU1
            self.assertEqual(
                h["extra"]["impact_contract"]["status"], "advisory_needs_fuzz"
            )

    def test_committed_fixtures(self):
        # Mutation-kill: monero-oxide ClsagMultisigMaskReceiver pair
        # (clean safety-Drop=0, mutant with core::mem::forget=1 arm A).
        clean = _ds_hits(FIX / "clean")
        mut = _ds_hits(FIX / "mutant")
        self.assertEqual(len(clean), 0)
        self.assertEqual(len(mut), 1)
        self.assertEqual(mut[0]["extra"]["drop_type"], "ClsagMultisigMaskReceiver")
        self.assertIn(
            "drop_suppression_forget_manuallydrop", mut[0]["extra"]["arms"]
        )
        self.assertIsNone(mut[0]["extra"]["covered_by"])


if __name__ == "__main__":
    unittest.main()
