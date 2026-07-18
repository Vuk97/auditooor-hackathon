#!/usr/bin/env python3
"""Tests for ``tools/transmute-type-confusion-screen.py`` (GEN-R3).

GEN-R3 is the DISCRIMINATING Rust reinterpret-cast soundness screen: it fires the
four UNDISCHARGEABLE forms (generic-param / lifetime / bytes-to-niche /
stricter-align-deref) and stays SILENT on sound POD / repr-transparent /
Pod-derived casts.

Coverage
--------
1. bytes-to-niche: transmute target `bool` fires (bit-validity).
2. bytes-to-niche: transmute `[u8; N]` -> `NonZeroU32` fires HIGH (byte source).
3. lifetime-transmute: transmute to `&'static` fires (lifetime).
4. generic-param-transmute: `transmute::<T, U>` between params-in-scope fires.
5. stricter-align-deref: `*(bytes.as_ptr() as *const u32)` fires (alignment).
6. FP: concrete same-lifetime `transmute::<A, B>` (non-niche) stays SILENT.
7. FP: `transmute::<&T, &Self>` repr-transparent newtype stays SILENT.
8. FP: `bytemuck::from_bytes::<Foo>` with `#[derive(Pod)]` (no hand impl) SILENT.
9. bytemuck: from_bytes to niche WITH a hand `unsafe impl Pod` fires.
10. FP: `read_unaligned` discharges alignment -> stricter-align arm SILENT.
11. FP: test / vendor / codegen paths excluded.
12. --strict exits 1 when a row fires; row schema carries required fields.
13. MUTATION-VERIFY on real fleet code (near key_conversion): sound original is
    silent, target->bool mutant newly fires bytes-to-niche. Skipped if absent.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "transmute-type-confusion-screen.py"
NEAR_KEYCONV = Path(os.path.expanduser(
    "~/audits/near/src/core/crypto/src/key_conversion.rs"))


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
    return {r["unsound_form"] for r in rows}


class GenR3Tests(unittest.TestCase):
    def test_bytes_to_niche_bool(self):
        rows = _scan_file("""
            fn f(x: u8) -> bool {
                unsafe { std::mem::transmute::<u8, bool>(x) }
            }
        """)
        self.assertIn("bytes-to-niche", _forms(rows))
        r = next(r for r in rows if r["unsound_form"] == "bytes-to-niche")
        self.assertEqual(r["obligation_unmet"], "bit-validity")
        self.assertEqual(r["severity"], "high")  # byte source

    def test_bytes_to_niche_nonzero_high(self):
        rows = _scan_file("""
            fn f(b: [u8; 4]) -> core::num::NonZeroU32 {
                unsafe { core::mem::transmute::<[u8; 4], NonZeroU32>(b) }
            }
        """)
        r = next(r for r in rows if r["unsound_form"] == "bytes-to-niche")
        self.assertEqual(r["severity"], "high")

    def test_lifetime_transmute(self):
        rows = _scan_file("""
            fn f<'a>(x: &'a u8) -> &'static u8 {
                unsafe { std::mem::transmute::<&'a u8, &'static u8>(x) }
            }
        """)
        self.assertIn("lifetime-transmute", _forms(rows))
        r = next(r for r in rows if r["unsound_form"] == "lifetime-transmute")
        self.assertEqual(r["obligation_unmet"], "lifetime")
        self.assertEqual(r["severity"], "high")

    def test_generic_param_transmute(self):
        rows = _scan_file("""
            fn convert<T, U>(x: T) -> U {
                unsafe { std::mem::transmute::<T, U>(x) }
            }
        """)
        self.assertIn("generic-param-transmute", _forms(rows))

    def test_stricter_align_deref(self):
        rows = _scan_file("""
            fn read_u32(bytes: &[u8]) -> u32 {
                unsafe { *(bytes.as_ptr() as *const u32) }
            }
        """)
        self.assertIn("stricter-align-deref", _forms(rows))
        r = next(r for r in rows if r["unsound_form"] == "stricter-align-deref")
        self.assertEqual(r["obligation_unmet"], "alignment")

    # ------------------------------------------------------------------ FP ---
    def test_fp_concrete_pod_transmute_silent(self):
        rows = _scan_file("""
            #[repr(C)] struct A { a: u32, b: u32 }
            #[repr(C)] struct B { x: u32, y: u32 }
            fn f(a: A) -> B { unsafe { std::mem::transmute::<A, B>(a) } }
        """)
        self.assertEqual(rows, [])

    def test_fp_repr_transparent_ref_newtype_silent(self):
        rows = _scan_file("""
            #[repr(transparent)] struct Wrap<T>(T);
            impl<T> Wrap<T> {
                fn from_ref(v: &T) -> &Self {
                    unsafe { core::mem::transmute::<&T, &Self>(v) }
                }
            }
        """)
        self.assertEqual(rows, [])

    def test_fp_bytemuck_derive_pod_silent(self):
        rows = _scan_file("""
            #[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
            #[repr(C)] struct Header { a: u32, b: u32 }
            fn parse(b: &[u8]) -> &Header {
                bytemuck::from_bytes::<Header>(b)
            }
        """)
        self.assertEqual(rows, [])

    def test_bytemuck_hand_pod_niche_fires(self):
        rows = _scan_file("""
            unsafe impl bytemuck::Pod for Flag {}
            fn parse(b: &[u8]) -> bool {
                *bytemuck::from_bytes::<bool>(b)
            }
        """)
        self.assertIn("bytes-to-niche", _forms(rows))

    def test_fp_read_unaligned_silent(self):
        rows = _scan_file("""
            fn read_u32(bytes: &[u8]) -> u32 {
                unsafe { (bytes.as_ptr() as *const u32).read_unaligned() }
            }
        """)
        self.assertEqual(_forms(rows) & {"stricter-align-deref"}, set())

    def test_fp_excludes_test_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            d = ws / "src" / "tests"
            d.mkdir(parents=True)
            (d / "t.rs").write_text(
                "fn f(x: u8) -> bool { unsafe { "
                "std::mem::transmute::<u8, bool>(x) } }\n")
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
                "fn f(x: u8) -> bool { unsafe { "
                "std::mem::transmute::<u8, bool>(x) } }\n")
            proc = subprocess.run(
                [sys.executable, str(SCANNER), "--workspace", str(ws),
                 "--strict"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            side = ws / ".auditooor" / \
                "transmute_type_confusion_hypotheses.jsonl"
            self.assertTrue(side.exists())
            rows = [json.loads(x) for x in side.read_text().splitlines()
                    if x.strip()]
            for r in rows:
                for k in ("schema", "capability", "id", "file", "line",
                          "function", "unsound_form", "target_type",
                          "obligation_unmet", "excerpt", "severity",
                          "why_severity_anchored"):
                    self.assertIn(k, r)
                self.assertEqual(r["capability"], "GEN_R3")
                self.assertEqual(r["verdict"], "needs-fuzz")
                # item-7: every emitted GEN_R3 row is a FIRED survivor -> an OPEN
                # obligation, not advisory-green (was self.assertTrue(advisory)).
                self.assertTrue(r["fires"])
                self.assertFalse(r["advisory"])
                self.assertEqual(r["proof_status"], "open")
                self.assertFalse(r["auto_credit"])

    @unittest.skipUnless(NEAR_KEYCONV.exists(),
                         "near fleet snapshot absent")
    def test_mutation_verify_real_fleet(self):
        """near key_conversion.rs: sound concrete transmute (RistrettoPoint) is
        SILENT; target->bool mutant newly fires bytes-to-niche."""
        orig = NEAR_KEYCONV.read_text()
        base = subprocess.run(
            [sys.executable, str(SCANNER), "--file", str(NEAR_KEYCONV)],
            capture_output=True, text=True)
        self.assertEqual(json.loads(base.stdout), [],
                         "sound concrete transmute must be silent")
        mutant = orig.replace(
            "let rp: RistrettoPoint = unsafe { transmute(ep) };",
            "let rp: bool = unsafe { transmute::<EdwardsPoint, bool>(ep) };")
        self.assertNotEqual(mutant, orig, "mutation anchor not found")
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "key_conversion.rs"
            f.write_text(mutant)
            mp = subprocess.run(
                [sys.executable, str(SCANNER), "--file", str(f)],
                capture_output=True, text=True)
            self.assertIn("bytes-to-niche", _forms(json.loads(mp.stdout)))


if __name__ == "__main__":
    unittest.main()
