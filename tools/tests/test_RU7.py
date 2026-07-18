#!/usr/bin/env python3
"""RU7 - lock-poison panic-while-holding advisory axis.

Non-vacuous: each positive asserts a specific hit, each negative asserts the
absence; mutating the predicate (dropping the std-poison gate, the guarded
write, the panic op, or the drop-suppression) breaks a case. Pins the
mutation-verified base-azul send_state.rs fixture pair (clean=0, mutant=1).
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
FIX = Path(__file__).resolve().parent / "fixtures" / "RU7"


def _load():
    spec = importlib.util.spec_from_file_location("rust_detector_runner_ru7", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner_ru7"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _write(ws: Path, rel: str, body: str) -> None:
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _lp_hits(ws: Path):
    os.environ["AUDITOOR_RUST_LOCKPOISON_AXIS"] = "1"
    summary = MOD.scan_workspace(ws)
    axis = summary.get("rust_lockpoison_axis", {})
    return axis.get("hypotheses", [])


class RU7Tests(unittest.TestCase):
    def test_index_after_guarded_write_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                use std::sync::Mutex;
                fn f(&self, i: usize) {
                    let mut inner = self.inner.lock().expect("poisoned");
                    inner.count += 1;
                    let _ = inner.recent[i];
                }
                """)
            hits = _lp_hits(ws)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["extra"]["lock_method"], "lock")

    def test_unwrap_after_guarded_write_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/b.rs", """
                use std::sync::RwLock;
                fn f(&self) {
                    let mut g = self.state.write().unwrap();
                    g.dirty = true;
                    g.pending.last().unwrap();
                }
                """)
            self.assertEqual(len(_lp_hits(ws)), 1)

    def test_no_panic_op_silent(self):
        # Guarded writes only, no panic op while held -> poison-safe, no fire.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/c.rs", """
                use std::sync::Mutex;
                fn f(&self) {
                    let mut inner = self.inner.lock().expect("poisoned");
                    inner.a = true;
                    inner.b += 1;
                }
                """)
            self.assertEqual(len(_lp_hits(ws)), 0)

    def test_parking_lot_no_result_silent(self):
        # parking_lot .lock() returns the guard directly (no Result unwrap) and
        # does NOT poison -> out of class, must not fire even with a panic op.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/d.rs", """
                use parking_lot::Mutex;
                fn f(&self, i: usize) {
                    let mut inner = self.inner.lock();
                    inner.count += 1;
                    let _ = inner.recent[i];
                }
                """)
            self.assertEqual(len(_lp_hits(ws)), 0)

    def test_panic_before_write_silent(self):
        # Panic op appears BEFORE any guarded write -> no partial-write poison
        # window modeled, must not fire.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/e.rs", """
                use std::sync::Mutex;
                fn f(&self, i: usize) {
                    let inner = self.inner.lock().expect("poisoned");
                    let _ = inner.recent[i];
                }
                """)
            self.assertEqual(len(_lp_hits(ws)), 0)

    def test_explicit_drop_suppresses(self):
        # Guard explicitly dropped before the panic op -> lock released, no
        # poison, must not fire.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/g.rs", """
                use std::sync::Mutex;
                fn f(&self, i: usize) {
                    let mut inner = self.inner.lock().expect("poisoned");
                    inner.count += 1;
                    drop(inner);
                    let _ = self.recent[i];
                }
                """)
            self.assertEqual(len(_lp_hits(ws)), 0)

    def test_axis_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(ws, "crates/x/src/a.rs", """
                use std::sync::Mutex;
                fn f(&self, i: usize) {
                    let mut inner = self.inner.lock().expect("poisoned");
                    inner.count += 1;
                    let _ = inner.recent[i];
                }
                """)
            os.environ.pop("AUDITOOR_RUST_LOCKPOISON_AXIS", None)
            summary = MOD.scan_workspace(ws)
            self.assertNotIn("rust_lockpoison_axis", summary)

    def test_committed_fixtures(self):
        # Mutation-kill: pinned base-azul send_state.rs pair (clean=0, mutant=1).
        clean = _lp_hits(FIX / "clean")
        mut = _lp_hits(FIX / "mutant")
        self.assertEqual(len(clean), 0)
        self.assertEqual(len(mut), 1)
        self.assertEqual(mut[0]["extra"]["function"], "process_send_error")


if __name__ == "__main__":
    unittest.main()
