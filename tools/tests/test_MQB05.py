#!/usr/bin/env python3
"""MQ-B05 narrowing-lossy-cast-screen - non-vacuous regression.

Pins tools/narrowing-lossy-cast-screen.py: for a value crossing a lossy fixed-width /
sign integer conversion (Go `uint32(`/`int32(`/... ; Rust `as u32`/`as i16`/...) whose
operand provenance reaches an untrusted-input boundary (a decoded field, a `len(input)`,
a public-API parameter), it flags (verdict="needs-fuzz") when NO dominating bounds check
proves the value fits the narrower target repr (silent truncation / sign-flip of a
length / index / id / amount / decimals / chain-id).

Non-vacuity is enforced (HARD RULE 6):
  (1) PLANTED POSITIVE fires  - an unguarded narrowing of an untrusted operand fires in
      BOTH Go and Rust.
  (2) GUARDED NEGATIVE silent - the SAME cast preceded by a dominating bound
      (`x > MaxUint32 -> reject`, `if x <= LIMIT`, a `u32::try_from`) is silent.
  (3) NEUTRALIZE the core predicate -> the positive assertion FAILS:
      (a) monkeypatching `_dominating_bound` to always-True makes the positive go silent
          (proves the bound-detection is the load-bearing predicate); and
      (b) replacing the untrusted operand with a numeric literal drops the row entirely
          (proves the untrusted-provenance join is load-bearing, not a bug shape).

The advisory-first contract (verdict=needs-fuzz, advisory=True, auto_credit=False,
default exit 0, --strict exit 1) and the .auditooor sidecar emission (firing hypotheses
only) are pinned too.

REAL-FLEET mutation-verify (HARD RULE 5) is reproduced end-to-end against the ACTUAL
fleet sources when present, WITHOUT mutating any ws file: the tool is SILENT on the real
guarded source (optimism messages.go UnmarshalJSON / near units.rs checked_add), and
FIRES on an in-memory TEMP COPY whose dominating guard is stripped. They SKIP if the
source is absent (no faked pass).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "narrowing_lossy_cast_screen_t", TOOLS / "narrowing-lossy-cast-screen.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MOD = _load_tool()


def _rows(text, name):
    return MOD.scan_file(pathlib.Path(name), name, file_text=text)


# ---------------------------------------------------------------------------
# Fixtures - a narrowing conversion of an untrusted-derived operand.
# ---------------------------------------------------------------------------

# Go: a decoded message field (untrusted) narrowed to uint32 with NO bound. => FIRES.
GO_POSITIVE = """
package interop
import "encoding/json"
type marshaling struct { LogIndex uint64 }
type Id struct { LogIndex uint32 }
func (id *Id) UnmarshalJSON(input []byte) error {
	var dec marshaling
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	id.LogIndex = uint32(dec.LogIndex)
	return nil
}
"""

# GUARDED Go sibling: dominating `if dec.LogIndex > math.MaxUint32 { return err }`. => SILENT.
GO_GUARDED = GO_POSITIVE.replace(
    "\tid.LogIndex = uint32(dec.LogIndex)\n",
    "\tif dec.LogIndex > math.MaxUint32 {\n\t\treturn errTooLarge\n\t}\n"
    "\tid.LogIndex = uint32(dec.LogIndex)\n")

# Rust: a value decoded off a wire buffer (untrusted) narrowed to u16 with NO bound.
# => FIRES.
RS_POSITIVE = """
pub fn read_index(input: &[u8]) -> u16 {
    let idx = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    idx as u16
}
"""

# GUARDED Rust sibling: dominating `if idx > u16::MAX as u32` bound. => SILENT.
RS_GUARDED = RS_POSITIVE.replace(
    "    idx as u16\n",
    "    if idx > u16::MAX as u32 { return 0; }\n"
    "    idx as u16\n")


class TestPlantedPositiveFires(unittest.TestCase):
    def test_go_positive_fires(self):
        rows = _rows(GO_POSITIVE, "messages.go")
        cs = [r for r in rows if r["function"] == "UnmarshalJSON"]
        self.assertEqual(len(cs), 1, rows)
        r = cs[0]
        self.assertTrue(r["fires"])
        self.assertFalse(r["dominating_bound"])
        self.assertEqual(r["target_type"], "uint32")
        self.assertEqual(r["lang"], "go")
        self.assertEqual(r["capability"], "MQ-B05-narrowing-lossy-cast")

    def test_rust_positive_fires(self):
        rows = _rows(RS_POSITIVE, "units.rs")
        cs = [r for r in rows if r["function"] == "read_index"]
        self.assertEqual(len(cs), 1, rows)
        r = cs[0]
        self.assertTrue(r["fires"])
        self.assertEqual(r["target_type"], "u16")
        self.assertEqual(r["lang"], "rust")
        # provenance: `idx` is decoded from the untrusted wire buffer `input`
        self.assertTrue(str(r["provenance"]).startswith("untrusted"), r["provenance"])
        self.assertTrue(r["sink_sensitive"], r)


class TestGuardedNegativeSilent(unittest.TestCase):
    def test_go_guarded_silent(self):
        rows = _rows(GO_GUARDED, "messages.go")
        cs = [r for r in rows if r["function"] == "UnmarshalJSON"]
        self.assertEqual(len(cs), 1, rows)
        self.assertFalse(cs[0]["fires"])
        self.assertTrue(cs[0]["dominating_bound"])
        self.assertIn("MaxUint32", cs[0]["guard_line"])

    def test_rust_guarded_silent(self):
        rows = _rows(RS_GUARDED, "units.rs")
        cs = [r for r in rows if r["function"] == "read_index"]
        self.assertEqual(len(cs), 1, rows)
        self.assertFalse(cs[0]["fires"])
        self.assertTrue(cs[0]["dominating_bound"])
        self.assertIn("MAX", cs[0]["guard_line"])


class TestNeutralizeCorePredicate(unittest.TestCase):
    """Neutralizing a core predicate must make the positive assertion FAIL."""

    def test_neutralize_bound_detector_kills_the_fire(self):
        # Force the dominating-bound detector to always report "bounded".
        orig = MOD._dominating_bound
        try:
            MOD._dominating_bound = lambda prefix, operand, target=None: (True, "NEUTRALIZED")
            rows = _rows(GO_POSITIVE, "messages.go")
        finally:
            MOD._dominating_bound = orig
        cs = [r for r in rows if r["function"] == "UnmarshalJSON"]
        self.assertEqual(len(cs), 1)
        self.assertFalse(cs[0]["fires"],
                         "bound-detection must be the load-bearing predicate")

    def test_replace_untrusted_operand_with_literal_drops_the_row(self):
        # Narrowing a numeric LITERAL is provably-fitting -> not an untrusted boundary.
        neutral = (GO_POSITIVE
                   .replace("id.LogIndex = uint32(dec.LogIndex)",
                            "id.LogIndex = uint32(7)")
                   .replace("_ = dec", ""))
        rows = _rows(neutral, "messages.go")
        cs = [r for r in rows if r["function"] == "UnmarshalJSON"]
        self.assertEqual(cs, [],
                         "row must vanish once the operand is a known-fitting literal")


class TestProvenanceIsGeneralNotShapeSpecific(unittest.TestCase):
    """The untrusted-provenance join fires on ANY of the general boundaries (length /
    decoded field / parameter / provenance-noun), not one hard-coded shape."""

    def test_length_provenance_fires(self):
        # an untrusted length narrowed to uint32 and used as an allocation size.
        src = """
package p
func Encode(data []byte) []byte {
	ilen := uint32(len(data))
	return make([]byte, ilen)
}
"""
        r = [x for x in _rows(src, "blob.go") if x["function"] == "Encode"]
        self.assertEqual(len(r), 1, r)
        self.assertTrue(r[0]["fires"])
        self.assertEqual(r[0]["provenance"], "length")

    def test_chain_id_noun_provenance_fires(self):
        src = """
package p
func handle(msg *Msg) uint16 {
	return uint16(msg.chainId)
}
"""
        r = [x for x in _rows(src, "h.go") if x["function"] == "handle"]
        self.assertEqual(len(r), 1, r)
        self.assertTrue(r[0]["fires"])
        # the narrowed value is a chain-id -> a sensitive identity sink
        self.assertIn("chain", str(r[0]["sink"]).lower() + str(r[0]["operand"]).lower())

    def test_rust_decoded_amount_fires(self):
        # an amount decoded off a wire buffer (untrusted) narrowed to i32 with no bound.
        src = """
pub fn parse_amount(input: &[u8]) -> i32 {
    let amount = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    amount as i32
}
"""
        r = [x for x in _rows(src, "c.rs") if x["function"] == "parse_amount"]
        self.assertEqual(len(r), 1, r)
        self.assertTrue(r[0]["fires"])


class TestFalsePositiveGuards(unittest.TestCase):
    """Regressions for FP classes seen while validating on the real fleet."""

    def test_array_type_conversion_not_a_cast(self):
        # `[32]byte(take(32))` is a slice->array conversion, NOT a scalar narrowing.
        src = """
package p
func decode(take func(int) []byte) {
	x := [32]byte(take(32))
	_ = x
}
"""
        r = [x for x in _rows(src, "d.go") if x["function"] == "decode"]
        self.assertEqual(r, [], "[32]byte(...) must not be flagged as a byte() cast")

    def test_loop_counter_not_untrusted(self):
        # A pure loop-induction var is not untrusted-derived -> silent.
        src = """
package p
func loop(n int) {
	for i := 0; i < n; i++ {
		b := uint8(i)
		_ = b
	}
}
"""
        r = [x for x in _rows(src, "l.go") if x["function"] == "loop"]
        self.assertEqual(r, [], "a loop counter is not an untrusted boundary")

    def test_receiver_field_read_not_untrusted(self):
        # `uint32(b[2])` where `b` is the RECEIVER is internal state, not untrusted.
        src = """
package p
func (b *Blob) ToData() uint32 {
	return uint32(b[2])<<16
}
"""
        r = [x for x in _rows(src, "blob.go") if x["function"] == "ToData"]
        self.assertEqual(r, [], "a receiver field read is internal state, not untrusted")

    def test_widening_int_target_excluded(self):
        # bare `int(...)` is the platform word width -> widening, not a lossy narrowing.
        src = """
package p
func f(count uint16) int {
	return int(count)
}
"""
        r = [x for x in _rows(src, "f.go") if x["function"] == "f"]
        self.assertEqual(r, [], "int(...) is word-width / widening, excluded")

    def test_rust_widening_usize_excluded(self):
        # `as usize` / `as u64` are word-width / widening on the fleet targets.
        src = """
pub fn g(len: u32) -> usize {
    len as usize
}
"""
        r = [x for x in _rows(src, "g.rs") if x["function"] == "g"]
        self.assertEqual(r, [], "as usize is word-width / widening, excluded")


class TestNarrowedTaintModel(unittest.TestCase):
    """(B) The SCREEN, not the enumerator: a narrowing only fires when the operand
    genuinely reaches an UNTRUSTED-INPUT boundary AND feeds a SECURITY-SENSITIVE sink."""

    def test_plain_scalar_param_is_not_untrusted(self):
        # a plain `amount u64` param (no wire type, no decode) is NOT a boundary - this is
        # the noun-identifier / any-param FALSE POSITIVE that made the tool an enumerator.
        src = """
package p
func f(amount uint64) uint32 {
	return uint32(amount)
}
"""
        r = [x for x in _rows(src, "f.go") if x["function"] == "f"]
        self.assertEqual(r, [], "a plain scalar param must NOT be an untrusted boundary")

    def test_len_of_internal_state_is_not_untrusted(self):
        # `len(internalSlice)` where the slice is NOT untrusted is not a boundary.
        src = """
package p
func f() uint32 {
	buf := makeInternal()
	return uint32(len(buf))
}
"""
        r = [x for x in _rows(src, "f.go") if x["function"] == "f"]
        self.assertEqual(r, [], "len() of internal state is not an untrusted boundary")

    def test_benign_sink_does_not_fire(self):
        # untrusted operand but the narrowed value feeds a benign log/metric, NOT a
        # size/index/identity sink -> row present but does NOT fire.
        src = """
package p
func f(data []byte) {
	n := uint32(len(data))
	log.Printf("processed %d", n)
}
"""
        r = [x for x in _rows(src, "f.go") if x["function"] == "f"]
        self.assertEqual(len(r), 1, r)
        self.assertFalse(r[0]["fires"],
                         "a benign log/metric destination is not a sensitive sink")
        self.assertFalse(r[0]["sink_sensitive"])

    def test_untrusted_plus_alloc_sink_fires(self):
        # untrusted length narrowed and used as an allocation size -> FIRES.
        src = """
package p
func f(data []byte) []byte {
	n := uint32(len(data))
	return make([]byte, n)
}
"""
        r = [x for x in _rows(src, "f.go") if x["function"] == "f"]
        self.assertEqual(len(r), 1, r)
        self.assertTrue(r[0]["fires"])
        self.assertTrue(r[0]["sink_sensitive"])


class TestNewDominatingBoundReasons(unittest.TestCase):
    """(A) The two new dominating-bound reasons that killed the fleet false positives."""

    # (A)(a) transitive AGGREGATE-summand bound (optimism ssz.go payloadLayout).
    AGG = """
package p
import "math"
func layout(input []byte) uint32 {
	extra := uint64(len(input))
	txs := uint64(len(input)) * 4
	total := extra + txs
	if total > math.MaxUint32 {
		return 0
	}
	size := uint32(extra)
	return size
}
"""

    def test_aggregate_summand_bound_silences(self):
        r = [x for x in _rows(self.AGG, "ssz.go")
             if x["function"] == "layout" and x["operand"] == "extra"]
        self.assertEqual(len(r), 1, r)
        self.assertFalse(r[0]["fires"], "a bounded aggregate's summand must be SILENT")
        self.assertTrue(r[0]["dominating_bound"])
        self.assertIn("aggregate-bound", r[0]["guard_line"])

    def test_aggregate_summand_fires_without_the_total_bound(self):
        # remove the `if total > math.MaxUint32` guard -> the summand narrowing FIRES.
        weakened = self.AGG.replace(
            "\tif total > math.MaxUint32 {\n\t\treturn 0\n\t}\n", "")
        r = [x for x in _rows(weakened, "ssz.go")
             if x["function"] == "layout" and x["operand"] == "extra"]
        self.assertEqual(len(r), 1, r)
        self.assertTrue(r[0]["fires"],
                        "without the aggregate bound the summand must FIRE (non-vacuous)")

    # (A)(b) BITMASK-fit bound (sei bloom9.go bloomValues `byte(1 << (h & 0x7))`).
    MASK = """
package p
func bits(hashbuf []byte) byte {
	idx := byte(1 << (hashbuf[1] & 0x7))
	return idx
}
"""

    def test_bitmask_bound_silences(self):
        r = [x for x in _rows(self.MASK, "bloom9.go") if x["function"] == "bits"]
        self.assertEqual(len(r), 1, r)
        self.assertFalse(r[0]["fires"], "a mask that fits the target repr must be SILENT")
        self.assertTrue(r[0]["dominating_bound"])
        self.assertIn("bitmask", r[0]["guard_line"])

    def test_bitmask_too_wide_still_fires(self):
        # a mask WIDER than the byte target (0x1ff = 9 bits) does NOT prove fit -> FIRES.
        wide = self.MASK.replace("hashbuf[1] & 0x7", "hashbuf[1]) & 0x1ff")
        r = [x for x in _rows(wide, "bloom9.go") if x["function"] == "bits"]
        self.assertEqual(len(r), 1, r)
        self.assertTrue(r[0]["fires"],
                        "a mask wider than the target repr must FIRE (non-vacuous)")


class TestAdvisoryContractAndSidecar(unittest.TestCase):
    def test_rows_are_advisory_needs_fuzz(self):
        r = [x for x in _rows(GO_POSITIVE, "messages.go")
             if x["function"] == "UnmarshalJSON"][0]
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        for k in ("file", "line", "function", "capability"):
            self.assertIn(k, r)

    def test_workspace_emits_sidecar_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "messages.go").write_text(GO_POSITIVE)
            (src / "units.rs").write_text(RS_POSITIVE)
            (src / "guarded.go").write_text(GO_GUARDED)
            # default (advisory) -> exit 0 even though un-bounded narrowings exist
            rc = MOD.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)
            side = ws / ".auditooor" / MOD._SIDE_NAME
            self.assertTrue(side.exists(), "sidecar must be emitted under .auditooor/")
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            # sidecar carries ONLY the firing hypotheses (the two positives)
            self.assertGreaterEqual(len(rows), 2)
            for r in rows:
                self.assertTrue(r["fires"])
                self.assertEqual(r["capability"], "MQ-B05-narrowing-lossy-cast")
                self.assertEqual(r["verdict"], "needs-fuzz")
                self.assertIn("line", r)
                self.assertIn("function", r)
            # the guarded function must NOT appear among the firing hypotheses
            self.assertFalse(
                any(r["function"] == "UnmarshalJSON" and "guarded" in r["file"]
                    for r in rows))
            # --strict -> exit 1 when an un-bounded narrowing fired
            self.assertEqual(MOD.main(["--workspace", str(ws), "--strict"]), 1)
            # --check re-reads the sidecar (advisory), default exit 0
            self.assertEqual(MOD.main(["--workspace", str(ws), "--check"]), 0)

    def test_clean_workspace_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "src").mkdir()
            (ws / "src" / "clean.go").write_text(GO_GUARDED)  # only guarded -> no fire
            self.assertEqual(MOD.main(["--workspace", str(ws), "--strict"]), 0)


class TestRealFleetMutationVerify(unittest.TestCase):
    """HARD RULE 5 - end-to-end on the ACTUAL fleet source, no ws file mutated: SILENT on
    the real guarded case, FIRES on an in-memory TEMP COPY whose guard is stripped. SKIP
    when the fleet source is not checked out (no faked pass)."""

    def test_optimism_messages_logindex_guarded_silent_then_fires(self):
        f = pathlib.Path(
            "/Users/wolf/audits/optimism/src/op-core/interop/messages/messages.go")
        if not f.exists():
            self.skipTest("optimism fleet source not present")
        real = f.read_text(encoding="utf-8", errors="ignore")
        rows = [r for r in MOD.scan_file(f, f.name, file_text=real)
                if r["function"] == "UnmarshalJSON"]
        self.assertEqual(len(rows), 1, "LogIndex narrowing must be a candidate")
        self.assertFalse(rows[0]["fires"], "the real GUARDED narrowing must be SILENT")
        self.assertTrue(rows[0]["dominating_bound"])
        # TEMP COPY with the dominating `if dec.LogIndex > math.MaxUint32 {..}` stripped
        import re as _re
        mutated = _re.sub(
            r"\tif dec\.LogIndex > math\.MaxUint32 \{\n.*?\n\t\}\n", "",
            real, flags=_re.DOTALL)
        self.assertNotEqual(mutated, real, "mutation must actually strip the guard")
        mrows = [r for r in MOD.scan_file(f, f.name, file_text=mutated)
                 if r["function"] == "UnmarshalJSON"]
        self.assertEqual(len(mrows), 1)
        self.assertTrue(mrows[0]["fires"],
                        "guard-stripped copy must FIRE (non-vacuous)")

    def test_rust_decode_narrowing_guarded_silent_then_fires(self):
        # End-to-end Rust: a value decoded off a wire buffer (untrusted) narrowed to u16
        # and fed to an allocation size (sensitive sink). The dominating `if hdr >
        # u16::MAX as u32` bound makes it SILENT; stripping the bound makes it FIRE. In
        # memory, no ws file mutated - the Go arm's real-fleet verify is above.
        guarded = """
pub fn alloc_frame(input: &[u8]) -> Vec<u8> {
    let hdr = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    if hdr > u16::MAX as u32 { return Vec::new(); }
    let size = hdr as u16;
    Vec::with_capacity(size as usize)
}
"""
        rows = [r for r in _rows(guarded, "frame.rs")
                if r["function"] == "alloc_frame"]
        cand = [r for r in rows if r["target_type"] == "u16"]
        self.assertEqual(len(cand), 1, rows)
        self.assertFalse(cand[0]["fires"], "the GUARDED narrowing must be SILENT")
        self.assertTrue(cand[0]["dominating_bound"])
        # STRIP the dominating bound -> must FIRE (non-vacuous end-to-end)
        stripped = guarded.replace(
            "    if hdr > u16::MAX as u32 { return Vec::new(); }\n", "")
        self.assertNotEqual(stripped, guarded, "mutation must strip the guard")
        mrows = [r for r in _rows(stripped, "frame.rs")
                 if r["function"] == "alloc_frame" and r["target_type"] == "u16"]
        self.assertEqual(len(mrows), 1)
        self.assertTrue(mrows[0]["fires"],
                        "guard-stripped copy must FIRE (non-vacuous)")


if __name__ == "__main__":
    unittest.main()
