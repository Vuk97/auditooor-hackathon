#!/usr/bin/env python3
"""EXT07 RAII / drop-glue-bypass -> multi-path-overwrite screen - regression +
mutation (non-vacuity).

Pins tools/raii-drop-glue-bypass-on-error-path-screen.py, a GENERAL, impact-
agnostic detector for the Rust language-intrinsic resource-safety class: a raw
memory write (`ptr::write`, a raw `*mut = _` store, a `.write()` through a raw
pointer) into a slot that may OWN heap data bypasses Rust's drop glue, and a
SECOND path (a later error / metering trap / early return) overwrites that slot
with another raw write - so the first value's destructor never runs (leak; or,
where the slot is later freed, double-free / UAF). Anchor: Solana sBPF JIT
`OptRetValPtr` (https://www.zellic.io/blog/solana-sbpf).

THREE non-vacuity legs (per the build spec):
  1. PLANTED POSITIVE  - the anchor shape (two raw writes to the same owned
     result slot on error paths, no intervening drop) FIRES.
  2. COVERED / BENIGN NEGATIVE - (a) mutually-exclusive match-arm writes into a
     fresh out-pointer are SILENT, and (b) the same double-write guarded by an
     intervening `mem::replace` + `drop` is SILENT.
  3. NEUTRALISE the core predicate - monkeypatching `_overwrite_plausible` to a
     constant False STOPS the positive firing (proves the predicate is load-
     bearing, not incidental).

Plus a MUTATION-VERIFY on REAL fleet code (near near-vm allocator.rs): the
byte-identical original is SILENT; a behaviour-changing weakening (a second
error-path raw overwrite of the owned result slot) makes the cap FIRE.
"""
import importlib.util
import shutil
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
FLEET = Path("/Users/wolf/audits")


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "raii_drop_glue_bypass_ext07",
        TOOLS / "raii-drop-glue-bypass-on-error-path-screen.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_tool()


def _scan(text):
    return MOD.scan_file(Path("snippet.rs"), "snippet.rs", file_text=text)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# --------------------------------------------------------------------------
# Leg 1 - PLANTED POSITIVE: the sBPF anchor shape fires.
# A host VM struct holds a raw result pointer; a first (unresolved-symbol) error
# raw-writes an owned String into the slot, then a second (metering trap) error
# raw-overwrites the SAME slot without dropping the first value.
# --------------------------------------------------------------------------
POSITIVE = r"""
impl VmHost {
    pub unsafe fn finish_program(&mut self, sym_ok: bool, gas_ok: bool) {
        // path 1: unresolved-symbol error heap-allocates a boxed error String
        let boxed_err = format!("unresolved symbol");
        ptr::write(self.opt_ret_val_ptr, boxed_err);
        if !gas_ok {
            // path 2: metering trap raw-OVERWRITES the same result slot; the
            // first boxed_err's destructor never runs -> leak.
            let trap = format!("out of gas");
            ptr::write(self.opt_ret_val_ptr, trap);
            return;
        }
    }
}
"""


def test_leg1_planted_positive_fires():
    rows = _scan(POSITIVE)
    fired = _fired(rows)
    assert fired, "anchor-shape double-write to owned result slot must fire"
    r = fired[0]
    assert r["slot"] == "self.opt_ret_val_ptr"
    assert r["arm"].startswith("A")
    assert r["capability"] == "EXT07"
    assert r["advisory"] is True and r["auto_credit"] is False
    assert r["verdict"] == "needs-fuzz"


# --------------------------------------------------------------------------
# Leg 2a - BENIGN NEGATIVE: mutually-exclusive match-arm writes into a fresh
# caller out-pointer (the real near-vm `Value::write_value_to` shape) are silent.
# --------------------------------------------------------------------------
BENIGN_MATCH = r"""
impl Value {
    pub unsafe fn write_value_to(&self, p: *mut i128) {
        match self {
            Self::I32(i) => ptr::write(p.cast(), *i),
            Self::I64(i) => ptr::write(p.cast(), *i),
            Self::ExternRef(r) => ptr::write(p.cast(), r.clone()),
        }
    }
}
"""


def test_leg2a_benign_match_arms_silent():
    rows = _scan(BENIGN_MATCH)
    assert rows, "points must still be enumerated (advisory)"
    assert not _fired(rows), "mutually-exclusive match-arm fresh writes must be silent"


# --------------------------------------------------------------------------
# Leg 2b - BENIGN NEGATIVE: the SAME sequential double-write, but the prior owned
# value is disposed via mem::replace + drop before the second raw write -> the
# private invariant holds -> silent.
# --------------------------------------------------------------------------
BENIGN_GUARDED = r"""
impl VmHost {
    pub unsafe fn finish_program(&mut self, gas_ok: bool) {
        let boxed_err = format!("unresolved symbol");
        ptr::write(self.opt_ret_val_ptr, boxed_err);
        if !gas_ok {
            // dispose the prior owned value BEFORE the raw overwrite (sound):
            // run its destructor in place, then overwrite the now-empty slot.
            ptr::drop_in_place(self.opt_ret_val_ptr);
            let trap = format!("out of gas");
            ptr::write(self.opt_ret_val_ptr, trap);
            return;
        }
    }
}
"""


def test_leg2b_intervening_drop_silent():
    rows = _scan(BENIGN_GUARDED)
    assert rows
    assert not _fired(rows), "an intervening drop of the prior owned value must silence the point"
    # and the disposition is recorded honestly
    assert any(r["intervening_drop"] for r in rows)


# --------------------------------------------------------------------------
# Leg 3 - NEUTRALISE the load-bearing core predicate. Monkeypatching
# `_overwrite_plausible` to constant (False, "") must STOP the positive firing.
# --------------------------------------------------------------------------
def test_leg3_neutralising_core_predicate_stops_positive(monkeypatch):
    # sanity: it fires before neutralisation
    assert _fired(_scan(POSITIVE))
    monkeypatch.setattr(MOD, "_overwrite_plausible", lambda *a, **k: (False, ""))
    rows = _scan(POSITIVE)
    assert not _fired(rows), (
        "with the overwrite-plausibility predicate neutralised the positive must "
        "stop firing - proves the predicate is load-bearing")


# --------------------------------------------------------------------------
# Extra load-bearing check: neutralise the owned-heap predicate too.
# --------------------------------------------------------------------------
def test_owned_heap_predicate_is_load_bearing(monkeypatch):
    assert _fired(_scan(POSITIVE))
    monkeypatch.setattr(MOD, "_slot_may_own_heap", lambda *a, **k: False)
    assert not _fired(_scan(POSITIVE))


# --------------------------------------------------------------------------
# Precision: io::Write / RwLock / serialize `.write(w)` must NOT be raw writes.
# --------------------------------------------------------------------------
NON_RAW_WRITES = r"""
impl Ser {
    fn serialize(&self, w: &mut impl std::io::Write) -> std::io::Result<()> {
        self.a.write(w)?;          // trait io::Write, not a raw ptr write
        let mut buf = Vec::new();
        buf.write_all(b"x").unwrap();
        *self.lock.write() = 3;    // RwLock guard deref, not a raw ptr
        Ok(())
    }
}
"""


def test_precision_non_raw_writes_are_not_points():
    rows = _scan(NON_RAW_WRITES)
    assert not rows, "io::Write / RwLock / serialize writes must not be enumerated as raw writes"


# --------------------------------------------------------------------------
# MUTATION-VERIFY on REAL fleet code (near near-vm allocator.rs).
# The byte-identical ORIGINAL is silent; a behaviour-changing weakening (second
# error-path raw overwrite of the owned result slot) makes the cap FIRE.
# --------------------------------------------------------------------------
FLEET_ALLOCATOR = FLEET / "near/src/runtime/near-vm/vm/src/instance/allocator.rs"
ANCHOR_LINE = "            ptr::write(self.instance_ptr.as_ptr(), instance);\n"


@pytest.mark.skipif(not FLEET_ALLOCATOR.exists(),
                    reason="fleet ws near not present")
def test_mutation_verify_real_fleet(tmp_path):
    orig_text = FLEET_ALLOCATOR.read_text()
    assert ANCHOR_LINE in orig_text, "fleet anchor line drifted"

    # ORIGINAL (copied, never mutating the ws) is SILENT
    orig = tmp_path / "allocator.rs"
    shutil.copyfile(FLEET_ALLOCATOR, orig)
    assert not _fired(MOD.scan_file(orig, "allocator.rs")), \
        "benign single-shot fresh field write must be silent"

    # MUTANT: a SECOND error path raw-overwrites the same owned slot, no drop
    mut_text = orig_text.replace(
        ANCHOR_LINE,
        ANCHOR_LINE
        + "            if self.instance_layout.size() == 0 {\n"
        + "                let trap_msg = format!(\"metering trap\");\n"
        + "                ptr::write(self.instance_ptr.as_ptr() as *mut String, trap_msg);\n"
        + "                return Err(());\n"
        + "            }\n",
        1,
    )
    mut = tmp_path / "allocator_mut.rs"
    mut.write_text(mut_text)
    fired = _fired(MOD.scan_file(mut, "allocator_mut.rs"))
    assert fired, "the mutant (second error-path raw overwrite) must FIRE"
    assert any(r["slot"] == "self.instance_ptr" and r["arm"].startswith("A")
               for r in fired)

    # and the ws file was never touched
    assert FLEET_ALLOCATOR.read_text() == orig_text


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
