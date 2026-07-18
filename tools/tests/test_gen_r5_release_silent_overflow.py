#!/usr/bin/env python3
"""GEN-R5 - release-mode silent integer overflow -> alloc/index screen.

Non-vacuous: every POSITIVE asserts a specific (sink, arith_op) hit and every
NEGATIVE asserts the ABSENCE. The mutation-witness pair proves guard-dominance
has TEETH on REAL fleet code:

  near/src/runtime/near-vm/vm/src/instance/mod.rs:182 - the real
  `Instance::vmctx_plus_offset(&self, offset: u32)` guards the narrowing with
  `usize::try_from(offset).unwrap()` before `ptr.add(..)`. The GUARDED original
  is SILENT; the same body with the guard weakened to `offset as usize` (a bare
  narrowing cast, exactly the release-wrap bug) FIRES. An equivalent mutant that
  kept the guard would leave the positive un-fired, so the guard predicate is
  not vacuous.

Covered axes:
  (i)   decode-read length -> `vec![0; n]` / with_capacity via bare `*` -> FIRES
        (untrusted decode taint + memory sink).
  (ii)  the SAME body guarded by `checked_mul(..).ok_or(..)?` -> SILENT (guard
        dominance witness).
  (iii) a bare `i + 1` loop index into owned `v.len()` arithmetic -> SILENT (the
        FP-control boundary: no untrusted taint, `.len()` operands).
  (iv)  narrowing `as usize` from a pub-fn u32 param into `from_raw_parts` /
        slice range -> FIRES.
  (v)   REAL-FLEET mutation pair (guarded try_from silent vs weakened-cast fire).
  (vi)  advisory-first: exit 0 by default, non-zero only under --strict/env.
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
TOOL = ROOT / "tools" / "release-silent-overflow-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("gen_r5_screen", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gen_r5_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


def _scan(body: str):
    """scan_file over an in-memory .rs body; return the fired rows."""
    return MOD.scan_file(Path("x.rs"), "x.rs", file_text=textwrap.dedent(body))


class GenR5Tests(unittest.TestCase):
    # ------------------------------------------------------------------
    # (i) POSITIVE - decode-read length * const -> with_capacity.
    # ------------------------------------------------------------------
    def test_decode_read_mul_into_with_capacity_fires(self):
        rows = _scan("""
            pub fn parse(data: &[u8]) -> Vec<u8> {
                let n = read_u32(data) as usize;
                let total = n * 8;
                let mut out = Vec::with_capacity(total);
                out.push(0);
                out
            }
            """)
        self.assertTrue(rows, "decode-read mul -> with_capacity must fire")
        r = rows[0]
        self.assertEqual(r["sink"], "with_capacity")
        self.assertEqual(r["capability"], "GEN_R5")
        self.assertEqual(r["schema"],
                         "auditooor.release_silent_overflow_hypotheses.v1")
        self.assertTrue(r["guard_absent"])
        self.assertIn("read_u32", r["untrusted_source"])
        self.assertEqual(r["severity"], "high")

    # ------------------------------------------------------------------
    # (ii) NEGATIVE - the SAME body guarded by checked_mul -> SILENT.
    # ------------------------------------------------------------------
    def test_checked_mul_guard_silences(self):
        rows = _scan("""
            pub fn parse(data: &[u8]) -> Option<Vec<u8>> {
                let n = read_u32(data) as usize;
                let total = n.checked_mul(8)?;
                let mut out = Vec::with_capacity(total);
                out.push(0);
                Some(out)
            }
            """)
        self.assertEqual(rows, [], "checked_mul guard must silence the screen")

    # ------------------------------------------------------------------
    # (iii) NEGATIVE - bounded loop index + owned .len() arithmetic.
    # ------------------------------------------------------------------
    def test_owned_len_arith_no_taint_silent(self):
        rows = _scan("""
            fn build(v: Vec<u64>) -> Vec<u64> {
                let mut out = Vec::with_capacity(v.len() + 1);
                for i in 0 .. v.len() {
                    out.push(v[i] + 1);
                }
                out
            }
            """)
        self.assertEqual(rows, [],
                         "owned .len() arithmetic (no untrusted taint) is silent")

    # ------------------------------------------------------------------
    # (iv) POSITIVE - narrowing `as usize` from a pub u32 param -> raw sink.
    # ------------------------------------------------------------------
    def test_pub_param_narrowing_into_from_raw_parts_fires(self):
        rows = _scan("""
            pub unsafe fn view(base: *const u8, len: u32) -> &'static [u8] {
                slice::from_raw_parts(base, len as usize)
            }
            """)
        self.assertTrue(rows, "pub-param narrowing -> from_raw_parts must fire")
        r = rows[0]
        self.assertEqual(r["sink"], "from_raw_parts")
        self.assertEqual(r["arith_op"], "narrowing-as")
        self.assertEqual(r["severity"], "high")  # pub-fn numeric param

    def test_slice_range_narrowing_fires(self):
        rows = _scan("""
            pub fn slice_it(data: &[u8], src: u32, len: u32) -> &[u8] {
                &data[src as usize .. (src + len) as usize]
            }
            """)
        self.assertTrue(rows, "narrowing into slice range must fire")
        self.assertTrue(any(r["sink"] == "slice-range" for r in rows))

    # ------------------------------------------------------------------
    # NEGATIVE - constant-only arithmetic into a sink -> SILENT (no taint).
    # ------------------------------------------------------------------
    def test_constant_only_arith_silent(self):
        rows = _scan("""
            fn header() -> Vec<u8> {
                let mut buf = Vec::with_capacity(32 + 8);
                buf.push(0);
                buf
            }
            """)
        self.assertEqual(rows, [], "constant-only capacity must be silent")

    # ------------------------------------------------------------------
    # (v) REAL-FLEET MUTATION WITNESS - near-vm vmctx_plus_offset.
    #     Guarded original (try_from) SILENT; weakened cast FIRES.
    # ------------------------------------------------------------------
    _REAL_GUARDED = """
        impl Instance {
            unsafe fn vmctx_plus_offset<T>(&self, offset: u32) -> *mut T {
                unsafe { (self.vmctx_ptr() as *mut u8).add(usize::try_from(offset).unwrap()).cast() }
            }
        }
        """
    _REAL_MUTANT = """
        impl Instance {
            unsafe fn vmctx_plus_offset<T>(&self, offset: u32) -> *mut T {
                unsafe { (self.vmctx_ptr() as *mut u8).add(offset as usize).cast() }
            }
        }
        """

    def test_real_fleet_guarded_original_silent(self):
        self.assertEqual(_scan(self._REAL_GUARDED), [],
                         "guarded try_from original must be silent")

    def test_real_fleet_weakened_guard_fires(self):
        rows = _scan(self._REAL_MUTANT)
        self.assertTrue(rows, "weakened guard (as usize) must newly fire")
        r = rows[0]
        self.assertEqual(r["sink"], "ptr-add")
        self.assertEqual(r["arith_op"], "narrowing-as")
        self.assertEqual(r["function"], "vmctx_plus_offset")
        self.assertIn("offset", r["untrusted_source"])

    def test_mutation_witness_pair_distinct(self):
        # The pair must DIFFER: an equivalent mutant would break this.
        self.assertEqual(len(_scan(self._REAL_GUARDED)), 0)
        self.assertGreaterEqual(len(_scan(self._REAL_MUTANT)), 1)

    # ------------------------------------------------------------------
    # NEGATIVE - comment/string masking: a decode read inside a comment or a
    # string literal must not taint.
    # ------------------------------------------------------------------
    def test_masking_ignores_comment_and_string(self):
        rows = _scan("""
            fn c() -> Vec<u8> {
                // read_u32 from the wire then n * 8
                let s = "read_u32 * 8";
                let mut out = Vec::with_capacity(2 + 3);
                out.push(0);
                out
            }
            """)
        self.assertEqual(rows, [], "masked read_u32 must not taint")

    # ------------------------------------------------------------------
    # (vi) advisory-first exit code contract via the CLI.
    # ------------------------------------------------------------------
    def test_cli_advisory_first_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "a.rs").write_text(textwrap.dedent("""
                pub fn parse(data: &[u8]) -> Vec<u8> {
                    let n = read_u32(data) as usize;
                    let mut out = Vec::with_capacity(n * 8);
                    out.push(0);
                    out
                }
                """), encoding="utf-8")
            # default: exit 0 even with a fired row (advisory-first).
            p = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            summ = json.loads(p.stdout)
            self.assertGreaterEqual(summ["fired"], 1)
            side = ws / ".auditooor" / \
                "release_silent_overflow_hypotheses.jsonl"
            self.assertTrue(side.exists(), "sidecar must be emitted")
            # --strict: non-zero when a fired row exists.
            p2 = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws),
                 "--strict"], capture_output=True, text=True)
            self.assertEqual(p2.returncode, 1, "strict must elevate on fire")
            # env opt-in mirrors --strict.
            env = dict(os.environ)
            env["AUDITOOOR_RELEASE_SILENT_OVERFLOW_STRICT"] = "1"
            p3 = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                capture_output=True, text=True, env=env)
            self.assertEqual(p3.returncode, 1, "env strict must elevate")

    def test_check_mode_reads_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "a.rs").write_text(textwrap.dedent("""
                pub fn parse(data: &[u8]) -> Vec<u8> {
                    let n = read_u32(data) as usize;
                    let mut out = Vec::with_capacity(n * 8);
                    out.push(0);
                    out
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
