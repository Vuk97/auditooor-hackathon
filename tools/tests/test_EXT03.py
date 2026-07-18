#!/usr/bin/env python3
"""EXT03 - verifier-executor-divergence-screen regression.

The VERIFIER->EXECUTOR SEMANTIC DIVERGENCE screen: a static verifier establishes
a safety property on representation A (wasm/eBPF bytecode) while a later
JIT/codegen stage emits a DIFFERENT representation B (machine code) that is
actually run - the sBPF-class wrong-width encode (opcode 0x81 vs 0x80) where the
executor does not re-derive the verifier property.

THREE non-vacuity legs (per spec):
  1. PLANTED POSITIVE fires: a codegen arm declaring Size::S64 but emitting a
     32-bit Rd register, in a tree that also carries a verifier -> width-mismatch
     severity-eligible fire.
  2. COVERED/benign NEGATIVE is silent: the same arm emitting the matching 64-bit
     Rq register -> no severity-eligible fire.
  3. NEUTRALIZING the core predicate (_width_mismatch -> constant False) STOPS the
     positive firing -> proves the predicate is load-bearing.

Plus: SEAM-GATE (no verifier in tree -> silent, no FP-spray) and a real-fleet
MUTATION-VERIFY on a mkdtemp COPY of near-vm (the shared WS is never mutated).
"""
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


ext = _load("verifier_executor_divergence_screen",
            "verifier-executor-divergence-screen.py")


# a minimal VERIFIER file: establishes a bounds/writable property on the input form
_VERIFIER_SRC = """\
use wasmparser::Validator;
pub fn validate_module(data: &[u8]) -> Result<(), Error> {
    let mut validator = Validator::new();
    validator.validate_all(data)?;   // property established on WASM bytecode
    Ok(())
}
pub fn is_writable(region: &Region) -> bool { region.writable }
"""

# a CODEGEN/JIT file whose emit ARM's declared size matches (BENIGN) or mismatches
# (POSITIVE) the emitted register width. This is the sBPF x86-encoder shape.
_CODEGEN_TMPL = """\
use dynasm::dynasm;
// single-pass JIT: emits x86 machine code (a DIFFERENT representation than the
// wasm the verifier approved).
fn emit_cmp(&mut self, sz: Size, loc: Location) {{
    match (sz, loc) {{
        (Size::S32, Location::GPR(loc)) => {{
            dynasm!(self ; cmp Rd(loc as u8), 0);
        }},
        (Size::S64, Location::GPR(loc)) => {{
            dynasm!(self ; cmp {reg}(loc as u8), 0);
        }},
        _ => unreachable!()
    }}
}}
"""


def _make_tree(reg, with_verifier=True):
    d = Path(tempfile.mkdtemp(prefix="ext03_"))
    (d / "codegen").mkdir()
    (d / "codegen" / "emitter_x64.rs").write_text(_CODEGEN_TMPL.format(reg=reg))
    if with_verifier:
        (d / "verifier").mkdir()
        (d / "verifier" / "compiler.rs").write_text(_VERIFIER_SRC)
    return d


class TestEXT03(unittest.TestCase):

    def _sev_fires(self, rows):
        return [r for r in rows if r.get("severity_eligible") and r.get("fires")]

    # LEG 1: planted positive fires ----------------------------------------
    def test_planted_positive_fires(self):
        d = _make_tree("Rd")           # S64 arm emits 32-bit Rd -> mismatch
        try:
            rows = ext.scan_tree(d, rel_to=d)
            sev = self._sev_fires(rows)
            self.assertTrue(sev, "expected a width-mismatch fire on S64->Rd")
            r = sev[0]
            self.assertEqual(r["declared_width"], 64)
            self.assertEqual(r["emitted_width"], 32)
            self.assertEqual(r["hazard"], "width-mismatch")
            # item-7: a severity-eligible width-mismatch is a real survivor -> an
            # OPEN obligation, not advisory-green (was assertTrue(advisory)).
            self.assertFalse(r["advisory"])
            self.assertEqual(r["proof_status"], "open")
            self.assertFalse(r["auto_credit"])
            self.assertEqual(r["verdict"], "needs-fuzz")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # LEG 2: benign/covered negative is silent -----------------------------
    def test_benign_negative_silent(self):
        d = _make_tree("Rq")           # S64 arm emits matching 64-bit Rq
        try:
            rows = ext.scan_tree(d, rel_to=d)
            self.assertFalse(self._sev_fires(rows),
                             "matched-width codegen must NOT fire")
            # the seam is still present + the emitter is enumerated as a lead
            self.assertTrue(any(r.get("lead") for r in rows),
                            "benign codegen still enumerated as a fuzz lead")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # LEG 3: neutralizing the core predicate stops the positive ------------
    def test_neutralized_predicate_stops_positive(self):
        d = _make_tree("Rd")
        orig = ext._width_mismatch
        try:
            ext._width_mismatch = lambda *a, **k: False   # neutralize
            rows = ext.scan_tree(d, rel_to=d)
            self.assertFalse(self._sev_fires(rows),
                             "with the predicate neutralized the positive must "
                             "NOT fire (proves _width_mismatch is load-bearing)")
        finally:
            ext._width_mismatch = orig
            shutil.rmtree(d, ignore_errors=True)

    # SEAM-GATE: no verifier in tree -> silent (no FP-spray on plain codegen)
    def test_no_seam_silent(self):
        d = _make_tree("Rd", with_verifier=False)
        try:
            rows = ext.scan_tree(d, rel_to=d)
            self.assertEqual(rows, [],
                             "no verifier role => no divergence seam => silent")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # REAL-FLEET MUTATION-VERIFY (copy only; shared WS never mutated) -------
    def test_real_fleet_mutation_verify(self):
        base = Path("/Users/wolf/audits/near/src/runtime/near-vm")
        emit = base / "compiler-singlepass/src/emitter_x64.rs"
        veri = base / "compiler/src/compiler.rs"
        if not (emit.exists() and veri.exists()):
            self.skipTest("near fleet ws not present")
        d = Path(tempfile.mkdtemp(prefix="ext03_fleet_"))
        try:
            (d / "codegen").mkdir()
            (d / "verifier").mkdir()
            shutil.copy(emit, d / "codegen" / "emitter_x64.rs")
            shutil.copy(veri, d / "verifier" / "compiler.rs")
            # ORIGINAL real code: no width-mismatch fire
            rows0 = ext.scan_tree(d, rel_to=d)
            self.assertFalse(self._sev_fires(rows0),
                             "pristine near-vm codegen must not fire")
            self.assertTrue(any(r.get("lead") for r in rows0),
                            "seam + emitter leads present on real fleet code")
            # MUTATE the copy: the real S64 unop_gpr arm now emits 32-bit Rd
            f = d / "codegen" / "emitter_x64.rs"
            txt = f.read_text().split("\n")
            done = False
            for i, l in enumerate(txt):
                if "(Size::S64, Location::GPR(loc)) =>" in l:
                    for j in range(i, i + 4):
                        if "Rq(loc as u8)" in txt[j]:
                            txt[j] = txt[j].replace("Rq(loc as u8)",
                                                    "Rd(loc as u8)")
                            done = True
                            break
                    break
            self.assertTrue(done, "expected to find the real S64 unop_gpr arm")
            f.write_text("\n".join(txt))
            rows1 = ext.scan_tree(d, rel_to=d)
            self.assertTrue(self._sev_fires(rows1),
                            "the wrong-width (Rq->Rd) mutant MUST fire")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
