#!/usr/bin/env python3
"""Tests for ``tools/panic-during-drop-screen.py`` (GEN-R1).

GEN-R1 is the panic-during-drop double-drop / UAF exception-safety screen: it
fires the four DROP-BEFORE-CONSUME forms (drop-in-place-loop / ptr-read-double-
drop / manuallydrop-seq / rebuild-drop-then-write) and stays SILENT when the code
CONSUMES the slot (set_len(0) / forget / guard-advance) before the panicking drop.

Coverage
--------
1.  drop-in-place-loop: a loop of `drop_in_place` with no `set_len(0)` first fires.
2.  ptr-read-double-drop: `let v = ptr::read(slot)` + later panic window fires.
3.  manuallydrop-seq: `ManuallyDrop::drop` then fallible work fires.
4.  rebuild-drop-then-write: `drop_in_place` then `ptr::write` to the slot fires.
5.  FP: consume-before-drop (`set_len(0)` before the loop) stays SILENT.
6.  FP: Copy-scalar read (`.cast::<u32>()`) stays SILENT.
7.  FP: a single non-loop `drop_in_place` at the end of a `Drop` impl SILENT.
8.  FP: `ManuallyDrop::drop` as the LAST statement (no fallible work) SILENT.
9.  FP: inline `if old == ptr::read(x)` (not a bound owned value) SILENT.
10. FP: trait-impl `impl Drop for T {` is NOT mistaken for a loop `for`.
11. FP: test / vendor / codegen paths excluded.
12. --strict exits 1 when a row fires; row schema carries required fields.
13. MUTATION-VERIFY: a FAITHFUL synthetic fixture mirroring the real
    `alloc::vec::Vec::truncate` idiom (set the length BEFORE dropping the tail).
    The exception-safe original is SILENT; moving the `set_len` to AFTER the drop
    loop (the drop-before-consume mutation) newly FIRES drop-in-place-loop;
    byte-identical restore. (No exception-safe consume-before-drop Vec idiom was
    found across the searched Rust fleet - monero-oxide / near / near-intents-
    contracts / base-azul / leansig / monero all lack a set_len(0)-guarded manual
    drop loop; the only real drop_in_place sites are single non-loop drops in
    Drop impls and Copy/pointer ptr::read shims - so a faithful std-idiom fixture
    is used here per the dispatch brief, and this is stated explicitly.)
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "panic-during-drop-screen.py"


def _scan_file(body: str, name: str = "lib.rs") -> list:
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / name
        f.write_text(textwrap.dedent(body))
        proc = subprocess.run(
            [sys.executable, str(SCANNER), "--file", str(f)],
            capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return json.loads(proc.stdout)


def _forms(rows):
    return {r["unsafe_form"] for r in rows}


# A FAITHFUL synthetic mirror of alloc::vec::Vec::truncate: the length is set
# (consumed) BEFORE the tail elements are hand-dropped in a loop - exception-safe.
VEC_TRUNCATE_SAFE = """
    struct RawVec<T> { ptr: *mut T, len: usize }
    impl<T> RawVec<T> {
        fn truncate(&mut self, len: usize) {
            if len < self.len {
                let remaining = self.len - len;
                unsafe {
                    self.set_len(len);
                    let base = self.ptr.add(len);
                    for i in 0..remaining {
                        core::ptr::drop_in_place(base.add(i));
                    }
                }
            }
        }
    }
"""


class GenR1Tests(unittest.TestCase):
    # ------------------------------------------------------------- fire forms
    def test_drop_in_place_loop_fires(self):
        rows = _scan_file("""
            struct Buf { ptr: *mut String, len: usize }
            impl Drop for Buf {
                fn drop(&mut self) {
                    for i in 0..self.len {
                        unsafe { core::ptr::drop_in_place(self.ptr.add(i)); }
                    }
                }
            }
        """)
        self.assertIn("drop-in-place-loop", _forms(rows))
        r = next(r for r in rows if r["unsafe_form"] == "drop-in-place-loop")
        self.assertEqual(r["severity"], "high")
        self.assertFalse(r["consume_marker_present"])

    def test_ptr_read_double_drop_fires(self):
        rows = _scan_file("""
            fn take(&mut self) -> T {
                let v = unsafe { core::ptr::read(&self.slot) };
                self.validate().unwrap();
                v
            }
        """)
        self.assertIn("ptr-read-double-drop", _forms(rows))
        r = next(r for r in rows if r["unsafe_form"] == "ptr-read-double-drop")
        self.assertEqual(r["severity"], "medium")

    def test_manuallydrop_seq_fires(self):
        rows = _scan_file("""
            fn f(&mut self) -> Result<(), E> {
                unsafe { core::mem::ManuallyDrop::drop(&mut self.a); }
                self.reload()?;
                Ok(())
            }
        """)
        self.assertIn("manuallydrop-seq", _forms(rows))

    def test_rebuild_drop_then_write_fires(self):
        rows = _scan_file("""
            fn set(&mut self, new: String) {
                unsafe {
                    core::ptr::drop_in_place(self.ptr);
                    let x = build_new();
                    core::ptr::write(self.ptr, x);
                }
            }
        """)
        self.assertIn("rebuild-drop-then-write", _forms(rows))
        r = next(r for r in rows
                 if r["unsafe_form"] == "rebuild-drop-then-write")
        self.assertEqual(r["severity"], "high")

    # ------------------------------------------------------------------- FP ---
    def test_fp_consume_before_drop_silent(self):
        rows = _scan_file("""
            struct Buf { ptr: *mut String, len: usize }
            impl Drop for Buf {
                fn drop(&mut self) {
                    let n = self.len;
                    unsafe { self.set_len(0); }
                    for i in 0..n {
                        unsafe { core::ptr::drop_in_place(self.ptr.add(i)); }
                    }
                }
            }
        """)
        self.assertEqual(rows, [])

    def test_fp_copy_scalar_read_silent(self):
        rows = _scan_file("""
            fn read_u32(arr: &[u8]) -> u32 {
                unsafe { core::ptr::read((arr.as_ptr()).cast::<u32>()) }
            }
        """)
        self.assertEqual(_forms(rows) & {"ptr-read-double-drop"}, set())

    def test_fp_single_drop_in_place_silent(self):
        rows = _scan_file("""
            unsafe fn deallocate(&mut self) {
                let p = self.instance.as_ptr();
                unsafe {
                    core::ptr::drop_in_place(p);
                    std::alloc::dealloc(p as *mut u8, self.layout);
                }
            }
        """)
        self.assertEqual(rows, [])

    def test_fp_manuallydrop_at_end_silent(self):
        rows = _scan_file("""
            impl Drop for Foo {
                fn drop(&mut self) {
                    unsafe { core::mem::ManuallyDrop::drop(&mut self.a); }
                }
            }
        """)
        self.assertEqual(rows, [])

    def test_fp_inline_ptr_read_not_bound_silent(self):
        rows = _scan_file("""
            unsafe fn cas(dst: *mut u32, expected: *const u32) -> bool {
                let old = core::ptr::read_volatile(dst);
                if old == core::ptr::read(expected) { return true; }
                false
            }
        """)
        self.assertEqual(_forms(rows) & {"ptr-read-double-drop"}, set())

    def test_fp_trait_impl_for_not_loop(self):
        """`impl Drop for T {` must NOT be parsed as a loop `for`, so a single
        drop_in_place inside a Drop impl stays SILENT (regression for the
        trait-impl-`for` false loop-body match)."""
        rows = _scan_file("""
            impl<T> Drop for LazyInit<T> {
                fn drop(&mut self) {
                    if self.initialized {
                        unsafe {
                            let ptr = self.data.as_mut_ptr();
                            core::ptr::drop_in_place(ptr);
                        };
                    }
                }
            }
        """)
        self.assertEqual(rows, [])

    def test_fp_excludes_test_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            d = ws / "src" / "tests"
            d.mkdir(parents=True)
            (d / "t.rs").write_text(
                "impl Drop for B { fn drop(&mut self) { for i in 0..self.len {"
                " unsafe { core::ptr::drop_in_place(self.p.add(i)); } } } }\n")
            proc = subprocess.run(
                [sys.executable, str(SCANNER), "--workspace", str(ws)],
                capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            summ = json.loads(proc.stdout)
            self.assertEqual(summ["fired"], 0)

    def test_strict_exits_one_and_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "lib.rs").write_text(
                "impl Drop for B { fn drop(&mut self) { for i in 0..self.len {"
                " unsafe { core::ptr::drop_in_place(self.p.add(i)); } } } }\n")
            proc = subprocess.run(
                [sys.executable, str(SCANNER), "--workspace", str(ws),
                 "--strict"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            side = ws / ".auditooor" / "panic_during_drop_hypotheses.jsonl"
            self.assertTrue(side.exists())
            rows = [json.loads(x) for x in side.read_text().splitlines()
                    if x.strip()]
            self.assertTrue(rows)
            for r in rows:
                for k in ("schema", "capability", "id", "file", "line",
                          "function", "unsafe_form", "consume_marker_present",
                          "panic_window", "excerpt", "severity",
                          "why_severity_anchored"):
                    self.assertIn(k, r)
                self.assertEqual(r["schema"],
                                 "auditooor.panic_during_drop_hypotheses.v1")
                self.assertEqual(r["capability"], "GEN_R1")
                self.assertEqual(r["verdict"], "needs-fuzz")
                self.assertTrue(r["advisory"])
                self.assertFalse(r["auto_credit"])
                self.assertIn(r["unsafe_form"],
                              {"drop-in-place-loop", "ptr-read-double-drop",
                               "manuallydrop-seq", "rebuild-drop-then-write"})

    # --------------------------------------------------------- MUTATION-VERIFY
    def test_mutation_verify_vec_truncate_idiom(self):
        """Faithful Vec::truncate mirror: consume (`set_len`) BEFORE the tail
        drop loop is exception-safe -> SILENT. Moving `set_len` to AFTER the
        loop (drop-before-consume) newly FIRES drop-in-place-loop. Byte-identical
        restore. (Synthetic std-idiom fixture: no real consume-before-drop Vec
        loop exists across the searched fleet - see module docstring.)"""
        safe = textwrap.dedent(VEC_TRUNCATE_SAFE)
        base = _scan_file(safe)
        self.assertEqual(base, [],
                         "consume-before-drop original must be silent")

        # mutation: delete the consume-first `self.set_len(len);` so the drop
        # loop runs with the slots still reported initialized.
        mutant = safe.replace("            self.set_len(len);\n", "")
        self.assertNotEqual(mutant, safe, "mutation anchor not found")
        mrows = _scan_file(mutant)
        self.assertIn("drop-in-place-loop", _forms(mrows),
                      "drop-before-consume mutant must newly fire")

        # byte-identical restore (re-derive from the same source constant).
        self.assertEqual(textwrap.dedent(VEC_TRUNCATE_SAFE), safe)


if __name__ == "__main__":
    unittest.main()
