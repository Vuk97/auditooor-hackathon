#!/usr/bin/env python3
"""test_R13.py - rust-unsafe-soundness-obligation (R13) non-vacuous test suite.

Proves, per the capability contract:
  * a PLANTED POSITIVE fires for each of the 7 enforcement-point arms
    (unsafe_block, unsafe_send_sync, transmute, raw_ptr_reinterpret,
    assume_init, unchecked_str, unchecked_index);
  * a GUARDED NEGATIVE stays silent for each arm - either a documented
    `// SAFETY:` obligation slot or an in-code validating guard;
  * NEUTRALISING the core predicate (obligation_discharged) makes every positive
    VANISH (the discharge check is load-bearing, not decorative);
  * an ordinary (non-SAFETY) comment does NOT discharge the obligation;
  * the safe-caller-reachability gate suppresses private scopes by default,
    `--all` lifts it, and a trait-impl method is reachable through its trait;
  * dedup keeps the most specific arm on a line (unsafe{transmute} -> transmute);
  * every emitted row is advisory-first (verdict=needs-fuzz, no_auto_credit).

Plus an OPTIONAL real-fleet mutation-verify (skipUnless the near slice.rs fixture
is present): the guarded `unsafe { &*self.data }` in RocksSlice::as_slice is
SILENT (it carries a `// SAFETY:` slot); deleting that comment on a TEMP COPY
makes it FIRE. The original ws file is never mutated.
"""
import importlib.util
import re
import shutil
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "rust-unsafe-soundness-obligation.py"
# near core store slice: pub `as_slice` with a `// SAFETY:`-guarded raw deref.
_FLEET = Path("/Users/wolf/audits/near/src/core/store/src/db/slice.rs")


def _load():
    spec = importlib.util.spec_from_file_location("r13soundness", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _load()

# --------------------------------------------------------------------------- #
# fixtures (all pub / trait-impl so they are safe-caller reachable by default)  #
# --------------------------------------------------------------------------- #
UNSAFE_BLOCK_POS = """pub fn read(p: *const u8) -> u8 {
    unsafe { *p }
}
"""
UNSAFE_BLOCK_SAFETY = """pub fn read(p: *const u8) -> u8 {
    // SAFETY: p is valid and aligned by construction.
    unsafe { *p }
}
"""
UNSAFE_BLOCK_ASSERT = """pub fn read(buf: &[u8], i: usize) -> u8 {
    assert!(i < buf.len());
    unsafe { *buf.as_ptr().add(i) }
}
"""
# an ordinary comment must NOT discharge the obligation.
UNSAFE_BLOCK_PLAIN_COMMENT = """pub fn read(p: *const u8) -> u8 {
    // this is fine, trust me
    unsafe { *p }
}
"""
# a MULTI-LINE `// SAFETY:` block (keyword on the FIRST comment line, several
# continuation comment lines before the unsafe op) - the idiomatic clippy form.
# The `SAFETY` keyword here is 4 comment lines above `unsafe`, so a fixed
# 3-line window would MISS it (the fleet FP: near memory.rs view_memory L79/L83).
UNSAFE_BLOCK_MULTILINE_SAFETY = """pub fn view(&self, p: *const u8) -> u8 {
    // SAFETY: Firstly, contracts are executed on a single thread thus we
    // know no one will change guest memory mapping under us.  Secondly, the
    // way the interface is used we know the memory mapping won't be
    // changed by the caller while it holds the slice reference.
    unsafe { *p }
}
"""
# an unrelated comment block far above must NOT discharge a later un-slotted op:
# the SAFETY comment belongs to the FIRST unsafe; the SECOND is un-slotted and
# separated by a non-comment line, so the block walk must stop before it.
UNSAFE_BLOCK_DETACHED_SAFETY = """pub fn two(p: *const u8, q: *const u8) -> u8 {
    // SAFETY: p is valid.
    let a = unsafe { *p };
    let b = unsafe { *q };
    a + b
}
"""

SEND_SYNC_POS = """pub struct W(*const u8);
unsafe impl Send for W {}
"""
SEND_SYNC_SAFETY = """pub struct W(*const u8);
// SAFETY: W's pointer is only ever used single-threaded.
unsafe impl Sync for W {}
"""

TRANSMUTE_POS = """pub fn cast(x: u64) -> f64 {
    unsafe { transmute(x) }
}
"""
TRANSMUTE_SAFETY = """pub fn cast(x: u64) -> f64 {
    // SAFETY: u64 and f64 are both 8 bytes with all-valid bit patterns.
    unsafe { transmute(x) }
}
"""

RAWPTR_POS = """pub fn view(p: *const u8, n: usize) -> &'static [u8] {
    unsafe { std::slice::from_raw_parts(p, n) }
}
"""
RAWPTR_SAFETY = """pub fn view(p: *const u8, n: usize) -> &'static [u8] {
    // SAFETY: caller guarantees p points at n initialised bytes.
    unsafe { std::slice::from_raw_parts(p, n) }
}
"""

ASSUME_INIT_POS = """pub fn get(m: MaybeUninit<u8>) -> u8 {
    unsafe { m.assume_init() }
}
"""
ASSUME_INIT_SAFETY = """pub fn get(m: MaybeUninit<u8>) -> u8 {
    // SAFETY: m was fully written before this call.
    unsafe { m.assume_init() }
}
"""

UTF8_POS = """pub fn s(b: &[u8]) -> &str {
    unsafe { std::str::from_utf8_unchecked(b) }
}
"""
UTF8_SAFETY = """pub fn s(b: &[u8]) -> &str {
    // SAFETY: b is known-ASCII by construction.
    unsafe { std::str::from_utf8_unchecked(b) }
}
"""

INDEX_POS = """pub fn at(v: &[u8], i: usize) -> u8 {
    unsafe { *v.get_unchecked(i) }
}
"""
INDEX_ASSERT = """pub fn at(v: &[u8], i: usize) -> u8 {
    assert!(i < v.len());
    unsafe { *v.get_unchecked(i) }
}
"""

# reachability
PRIVATE_FN = """fn helper(p: *const u8) -> u8 {
    unsafe { *p }
}
"""
TRAIT_IMPL = """impl Deref for W {
    fn deref(&self) -> &u8 {
        unsafe { &*self.0 }
    }
}
"""


class UnsafeBlockArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(UNSAFE_BLOCK_POS, "src/a.rs",
                                arms=["unsafe_block"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "unsafe_block")
        self.assertEqual(rows[0]["function"], "read")

    def test_safety_comment_silent(self):
        rows = M.analyze_source(UNSAFE_BLOCK_SAFETY, "src/a.rs",
                                arms=["unsafe_block"])
        self.assertEqual(rows, [])

    def test_assert_guard_silent(self):
        rows = M.analyze_source(UNSAFE_BLOCK_ASSERT, "src/a.rs",
                                arms=["unsafe_block"])
        self.assertEqual(rows, [])

    def test_plain_comment_still_fires(self):
        # an ordinary comment is not a `// SAFETY:` obligation slot.
        rows = M.analyze_source(UNSAFE_BLOCK_PLAIN_COMMENT, "src/a.rs",
                                arms=["unsafe_block"])
        self.assertEqual(len(rows), 1)

    def test_multiline_safety_block_silent(self):
        # a multi-line `// SAFETY:` block (keyword on the first line, >3 lines
        # above the point) must discharge the obligation -> silent. Regression
        # for the fleet FP: near memory.rs view_memory (SAFETY L79, unsafe L83).
        rows = M.analyze_source(UNSAFE_BLOCK_MULTILINE_SAFETY, "src/a.rs",
                                arms=["unsafe_block"])
        self.assertEqual(rows, [], "a multi-line // SAFETY: block must discharge "
                         "the obligation regardless of continuation-line count")

    def test_detached_safety_does_not_discharge_later_op(self):
        # the SAFETY slot attaches to the FIRST unsafe; the SECOND op is
        # separated by a non-comment line and is un-slotted -> must fire.
        rows = M.analyze_source(UNSAFE_BLOCK_DETACHED_SAFETY, "src/a.rs",
                                arms=["unsafe_block"])
        self.assertEqual(len(rows), 1, "only the un-slotted second op must fire")
        # the fired point is the second unsafe (line 4), not the slotted first.
        self.assertEqual(rows[0]["line"], 4)


class SendSyncArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(SEND_SYNC_POS, "src/a.rs",
                                arms=["unsafe_send_sync"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "unsafe_send_sync")

    def test_safety_comment_silent(self):
        rows = M.analyze_source(SEND_SYNC_SAFETY, "src/a.rs",
                                arms=["unsafe_send_sync"])
        self.assertEqual(rows, [])

    def test_send_sync_reachable_even_without_pub_fn(self):
        # a type-level unsafe impl is public API -> reachable with no enclosing fn.
        rows = M.analyze_source(SEND_SYNC_POS, "src/a.rs",
                                arms=["unsafe_send_sync"])
        self.assertTrue(rows[0]["safe_caller_reachable"])
        self.assertEqual(rows[0]["function"], "<module>")


class TransmuteArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(TRANSMUTE_POS, "src/a.rs", arms=["transmute"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "transmute")

    def test_safety_comment_silent(self):
        rows = M.analyze_source(TRANSMUTE_SAFETY, "src/a.rs", arms=["transmute"])
        self.assertEqual(rows, [])

    def test_dedup_keeps_specific_arm(self):
        # `unsafe { transmute(x) }` must yield exactly ONE row, arm=transmute
        # (the specific intrinsic wins over the generic unsafe_block).
        rows = M.analyze_source(TRANSMUTE_POS, "src/a.rs")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "transmute")


class RawPtrArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(RAWPTR_POS, "src/a.rs",
                                arms=["raw_ptr_reinterpret"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "raw_ptr_reinterpret")

    def test_safety_comment_silent(self):
        rows = M.analyze_source(RAWPTR_SAFETY, "src/a.rs",
                                arms=["raw_ptr_reinterpret"])
        self.assertEqual(rows, [])


class AssumeInitArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(ASSUME_INIT_POS, "src/a.rs",
                                arms=["assume_init"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "assume_init")

    def test_safety_comment_silent(self):
        rows = M.analyze_source(ASSUME_INIT_SAFETY, "src/a.rs",
                                arms=["assume_init"])
        self.assertEqual(rows, [])


class Utf8Arm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(UTF8_POS, "src/a.rs", arms=["unchecked_str"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "unchecked_str")

    def test_safety_comment_silent(self):
        rows = M.analyze_source(UTF8_SAFETY, "src/a.rs", arms=["unchecked_str"])
        self.assertEqual(rows, [])


class UncheckedIndexArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(INDEX_POS, "src/a.rs", arms=["unchecked_index"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "unchecked_index")

    def test_assert_guard_silent(self):
        rows = M.analyze_source(INDEX_ASSERT, "src/a.rs",
                                arms=["unchecked_index"])
        self.assertEqual(rows, [])


class ReachabilityGate(unittest.TestCase):
    def test_private_fn_silent_by_default(self):
        rows = M.analyze_source(PRIVATE_FN, "src/a.rs", arms=["unsafe_block"])
        self.assertEqual(rows, [], "a private (non-pub, non-trait) scope must be "
                         "gated out by default")

    def test_all_scopes_lifts_gate(self):
        rows = M.analyze_source(PRIVATE_FN, "src/a.rs", all_scopes=True,
                                arms=["unsafe_block"])
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["safe_caller_reachable"])

    def test_trait_impl_method_reachable(self):
        rows = M.analyze_source(TRAIT_IMPL, "src/a.rs", arms=["unsafe_block"])
        self.assertEqual(len(rows), 1, "a trait-impl method is reachable through "
                         "its trait even without `pub`")
        self.assertTrue(rows[0]["safe_caller_reachable"])
        self.assertEqual(rows[0]["function"], "deref")


class NonVacuity(unittest.TestCase):
    def test_neutralising_core_predicate_kills_all_positives(self):
        # If obligation_discharged always returns True, no hypothesis can fire ->
        # proves the discharge predicate is the load-bearing core.
        orig = M.obligation_discharged
        try:
            M.obligation_discharged = lambda *a, **k: True
            for src in (UNSAFE_BLOCK_POS, TRANSMUTE_POS, RAWPTR_POS,
                        ASSUME_INIT_POS, UTF8_POS, INDEX_POS, SEND_SYNC_POS):
                rows = M.analyze_source(src, "src/a.rs")
                self.assertEqual(rows, [], "positive must vanish when the "
                                 "discharge predicate is neutralised")
        finally:
            M.obligation_discharged = orig


class AdvisoryContract(unittest.TestCase):
    def test_every_row_advisory(self):
        rows = []
        for src in (UNSAFE_BLOCK_POS, TRANSMUTE_POS, RAWPTR_POS, ASSUME_INIT_POS,
                    UTF8_POS, INDEX_POS, SEND_SYNC_POS):
            rows += M.analyze_source(src, "src/a.rs")
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertIs(r["no_auto_credit"], True)
            self.assertIn("soundness_obligation", r)
            self.assertEqual(r["obligation_slot"], "undischarged")


@unittest.skipUnless(_FLEET.is_file(), "near store/db/slice.rs fixture absent")
class RealFleetMutation(unittest.TestCase):
    """Guarded real file is silent; deleting its `// SAFETY:` slot on a TEMP COPY
    fires. The workspace file is never mutated."""

    def test_clean_silent_then_mutation_fires(self):
        base = Path(tempfile.mkdtemp())
        try:
            d = base / "db"
            d.mkdir()
            tmp = d / "slice.rs"
            shutil.copy(_FLEET, tmp)

            clean = M.analyze_file(tmp)
            self.assertEqual(clean, [], "guarded fleet unsafe point must be "
                             "silent (it carries a // SAFETY: slot)")

            # weaken: delete the `// SAFETY:` obligation-slot comment line(s).
            lines = tmp.read_text().split("\n")
            kept = [l for l in lines if not re.search(r"//\s*SAFETY", l)]
            self.assertLess(len(kept), len(lines),
                            "expected a // SAFETY: comment to remove")
            tmp.write_text("\n".join(kept))

            fired = M.analyze_file(tmp, arms=["unsafe_block"])
            self.assertEqual(len(fired), 1,
                             "un-slotted unsafe point must fire exactly once")
            self.assertEqual(fired[0]["arm"], "unsafe_block")
            self.assertEqual(fired[0]["function"], "as_slice")
        finally:
            shutil.rmtree(base, ignore_errors=True)
        # original fleet file untouched (still carries its SAFETY slot).
        self.assertIn("SAFETY", _FLEET.read_text())


@unittest.skipUnless(_FLEET.is_file(), "near store/db/slice.rs fixture absent")
class RealFleetNoFP(unittest.TestCase):
    """The guarded slice.rs must yield ZERO hypotheses across all arms."""

    def test_no_false_positive(self):
        rows = M.analyze_file(_FLEET)
        self.assertEqual(rows, [], f"guarded fleet file must not fire "
                         f"(got {[(r['arm'], r['line']) for r in rows]})")


if __name__ == "__main__":
    unittest.main(verbosity=2)
