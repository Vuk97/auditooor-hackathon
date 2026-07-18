#!/usr/bin/env python3
"""EXT01 multi-source authoritative-field parser-differential screen - non-vacuous
regression.

Pins tools/multi-source-field-authority-differential-screen.py. For a serialized
artifact whose SAME logical field (size/length/count/offset) is carried in >=2
encodings/headers, the screen flags a parse routine that SELECTS one authority by
precedence (combinator `unwrap_or`/`?:`, or a conditional reassignment override)
and drives a length/cursor sink with the chosen value WITHOUT asserting the two
sources agree - the tokio-tar RUSTSEC-2025-0111 class (ustar-size vs PAX-size). A
field that IS consistency-checked is emitted COVERED (fires=False). Every row is
advisory verdict="needs-fuzz".

Non-vacuity (all three legs REQUIRED by the build spec):
  (1) PLANTED POSITIVE fires  - a dual-source size select feeding a read/alloc
      sink with no cross-source assert flags (rust combinator, go conditional
      override, solidity ternary all covered).
  (2) COVERED / benign NEGATIVE silent  - the SAME select guarded by a
      `src_a != src_b -> reject` consistency assert is COVERED (fires=False); a
      `unwrap_or(0)` default (single authority) and a select with NO sink do not
      emit at all.
  (3) NEUTRALIZE the core predicate - monkeypatch `_has_consistency` to a constant
      truthy value ("a consistency assert is always present"); the planted
      positive must then STOP firing (become covered). Proves the no-cross-source-
      assert predicate is load-bearing, not decoration. A second neutralization
      (`_is_size_ident` -> constant False) empties the enumeration entirely.
Plus: the advisory contract holds on every row; machine-generated and test sources
are excluded; a real-shape Go format-reader fixture fires.
"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
_TOOL = TOOLS / "multi-source-field-authority-differential-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("ext01_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MSFA = _load()


def _rows(src: str, rel: str):
    return MSFA.scan_file(pathlib.Path(rel), rel, file_text=src)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# --- planted positives ------------------------------------------------------
# tokio-tar shape: ustar size vs PAX size selected by precedence, no consistency
# assert, chosen size drives the read cursor.
RUST_POSITIVE = """
pub fn read_entry(&mut self, ustar_size: u64, pax_size: Option<u64>) -> Result<Entry> {
    let size = pax_size.unwrap_or(ustar_size);
    let mut buf = vec![0u8; size as usize];
    self.reader.read_exact(&mut buf)?;
    self.pos += size;
    Ok(Entry { data: buf })
}
"""

# Go: a header length overridden by an "extended" length source inside a
# conditional, no consistency assert, chosen length drives make([]byte, length).
GO_POSITIVE = """
package p
func (r *Reader) ReadAt(entry *Entry, off int64) (int, error) {
	typ, length, err := r.ReadMetadataAt(off)
	if err != nil {
		return 0, err
	}
	extLen := binary.LittleEndian.Uint32(r.extra)
	if extLen != 0 {
		length = extLen
	}
	val := make([]byte, length)
	r.r.ReadAt(val, off+headerSize)
	entry.Value = val
	return int(headerSize + length), nil
}
"""

# Solidity ternary: declared vs advertised length select feeding a slice + cursor.
SOL_POSITIVE = """
pragma solidity ^0.8.0;
contract P {
  function decode(bytes calldata data, uint256 declaredLen, uint256 advertisedLen) external {
    uint256 len = advertisedLen > 0 ? advertisedLen : declaredLen;
    bytes memory chunk = data[0:len];
    cursor += len;
  }
}
"""

# --- covered / benign negatives --------------------------------------------
# Same dual-source select BUT asserts the two sources agree first.
RUST_COVERED = """
pub fn read_entry(&mut self, ustar_size: u64, pax_size: Option<u64>) -> Result<Entry> {
    let size = pax_size.unwrap_or(ustar_size);
    if let Some(px) = pax_size {
        if px != ustar_size { return Err(Error::Inconsistent); }
    }
    let mut buf = vec![0u8; size as usize];
    self.reader.read_exact(&mut buf)?;
    Ok(Entry { data: buf })
}
"""

GO_COVERED = """
package p
func (r *Reader) ReadAt(entry *Entry, off int64) (int, error) {
	typ, length, err := r.ReadMetadataAt(off)
	if err != nil {
		return 0, err
	}
	extLen := binary.LittleEndian.Uint32(r.extra)
	if extLen != 0 {
		if extLen != length {
			return 0, fmt.Errorf("inconsistent length")
		}
		length = extLen
	}
	val := make([]byte, length)
	r.r.ReadAt(val, off+headerSize)
	return int(headerSize + length), nil
}
"""

# unwrap_or(0) is a DEFAULT, not a redundant second authority -> no row.
RUST_DEFAULT = """
pub fn read_entry(&mut self, pax_size: Option<u64>) -> Result<Entry> {
    let size = pax_size.unwrap_or(0);
    let mut buf = vec![0u8; size as usize];
    self.reader.read_exact(&mut buf)?;
    Ok(Entry { data: buf })
}
"""

# dual-source select but NO length/cursor sink (a config, not a parser) -> no row.
RUST_NOSINK = """
pub fn pick_limit(&self, initial: Option<u64>, maximum: u64) -> u64 {
    let initial_size = initial.unwrap_or(maximum);
    initial_size
}
"""

# single authority (header length only) - no second source -> no row.
GO_SINGLE = """
package p
func (r *Reader) ReadAt(entry *Entry, off int64) (int, error) {
	typ, length, err := r.ReadMetadataAt(off)
	if err != nil { return 0, err }
	if length > valueSizeLimit { return 0, fmt.Errorf("too large") }
	val := make([]byte, length)
	r.r.ReadAt(val, off+headerSize)
	return int(headerSize + length), nil
}
"""

# two independent fresh `:=` bindings of the same name in sibling if/else branches
# are NOT an override (regression: this was a real FP on sei consensus.go).
GO_SIBLING_DECL = """
package p
func Count(req Req) int {
	if req.cached {
		totalCount := len(req.cachedVals)
		return totalCount
	}
	totalCount := len(req.liveVals)
	buf := make([]byte, totalCount)
	_ = buf
	return totalCount
}
"""

# REGRESSION (EXT01 fix): a size field zero-initialized then conditionally
# reassigned ONCE from a single source is SINGLE-AUTHORITY - the 0 is an
# uninitialized default, not a second encoding of the field, so no two consumers
# can disagree. The conditional-override arm used to spray on this common Go
# idiom (the exact class the RUST_DEFAULT test excludes for the combinator arm).
# Literal default `size := 0` -> must NOT fire.
GO_LITERAL_DEFAULT_OVERRIDE = """
package p
func R(cond bool) {
	size := 0
	if cond {
		size = chunkSize
	}
	buf := make([]byte, size)
	_ = buf
}
"""

# Same idiom with the default carried through a numeric CAST (`uint32(0)`); the
# cast-strip must still recognise it as a literal default -> must NOT fire.
GO_CASTED_DEFAULT_OVERRIDE = """
package p
func P1(hdr Header) {
	length := uint32(0)
	if hdr.present {
		length = hdr.recordLen
	}
	buf := make([]byte, length)
	_ = buf
}
"""

# PRESERVED POSITIVE: the base binding is a GENUINE second source (tar ustar-size
# vs PAX-size), zero-init nowhere in sight - the override reassigns from a rival
# encoding, so the differential IS real and must STILL fire.
GO_TAR_TWO_SOURCE_OVERRIDE = """
package p
func Tar(pax bool) {
	length := ustarSize
	if pax {
		length = paxSize
	}
	buf := make([]byte, length)
	_ = buf
}
"""


class Ext01NonVacuous(unittest.TestCase):

    # -- leg 1: planted positives fire -------------------------------------
    def test_rust_combinator_positive_fires(self):
        rows = _fired(_rows(RUST_POSITIVE, "tar.rs"))
        self.assertEqual(len(rows), 1, rows)
        r = rows[0]
        self.assertEqual(r["field"], "size")
        self.assertEqual(sorted(r["sources"]), ["pax_size", "ustar_size"])
        self.assertEqual(r["precedence"], "combinator")
        self.assertFalse(r["consistency_checked"])

    def test_go_conditional_override_positive_fires(self):
        rows = _fired(_rows(GO_POSITIVE, "reader.go"))
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["field"], "length")
        self.assertEqual(rows[0]["precedence"], "conditional-override")

    def test_solidity_ternary_positive_fires(self):
        rows = _fired(_rows(SOL_POSITIVE, "P.sol"))
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["field"], "len")
        self.assertEqual(rows[0]["precedence"], "ternary")

    # -- leg 2: covered / benign negatives silent --------------------------
    def test_rust_covered_is_not_fired(self):
        rows = _rows(RUST_COVERED, "tar.rs")
        self.assertEqual(len(rows), 1, rows)          # emitted as a COVERED lead
        self.assertFalse(rows[0]["fires"])
        self.assertTrue(rows[0]["consistency_checked"])
        self.assertEqual(_fired(rows), [])

    def test_go_covered_is_not_fired(self):
        rows = _rows(GO_COVERED, "reader.go")
        self.assertEqual(_fired(rows), [])
        self.assertTrue(all(r["consistency_checked"] for r in rows))

    def test_default_fallback_emits_nothing(self):
        self.assertEqual(_rows(RUST_DEFAULT, "d.rs"), [])

    def test_select_without_sink_emits_nothing(self):
        self.assertEqual(_rows(RUST_NOSINK, "cfg.rs"), [])

    def test_single_authority_emits_nothing(self):
        self.assertEqual(_rows(GO_SINGLE, "s.go"), [])

    def test_sibling_fresh_decls_no_false_positive(self):
        # two `totalCount := ...` in disjoint branches are distinct bindings,
        # never a base+override -> no row at all.
        self.assertEqual(_rows(GO_SIBLING_DECL, "sib.go"), [])

    def test_literal_default_override_no_false_positive(self):
        # `size := 0; if cond { size = chunkSize }` is single-authority (the 0 is
        # an uninitialized default, not a second encoding) -> must NOT fire.
        self.assertEqual(_fired(_rows(GO_LITERAL_DEFAULT_OVERRIDE, "r.go")), [])

    def test_casted_zero_default_override_no_false_positive(self):
        # a casted-zero default `length := uint32(0)` is still a literal default
        # (cast-strip) -> must NOT fire.
        self.assertEqual(_fired(_rows(GO_CASTED_DEFAULT_OVERRIDE, "p1.go")), [])

    def test_two_source_override_still_fires(self):
        # the base binding is a GENUINE rival encoding (ustarSize vs paxSize), not
        # a literal default -> the differential IS real and must STILL fire.
        rows = _fired(_rows(GO_TAR_TWO_SOURCE_OVERRIDE, "tar.go"))
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["field"], "length")
        self.assertEqual(rows[0]["precedence"], "conditional-override")
        self.assertFalse(rows[0]["consistency_checked"])

    def test_is_literal_alt_strips_one_cast(self):
        # part (B) of the fix: a single wrapping numeric cast/paren layer around a
        # zero default is recognised as a literal; a real source (even one wrapped
        # in a cast of a *field*, or a `.`-qualified call) is NOT.
        for lit in ("0", "uint32(0)", "u64(0)", "(0)", "0 as u64", "MAX", "None"):
            self.assertTrue(MSFA._is_literal_alt(lit), lit)
        for src in ("ustar_size", "chunkSize", "hdr.recordLen",
                    "r.ReadMetadataAt(off)", "uint32(x)"):
            self.assertFalse(MSFA._is_literal_alt(src), src)

    # -- leg 3: neutralize the core predicate ------------------------------
    def test_neutralize_consistency_predicate_stops_fire(self):
        # Force `_has_consistency` to always report an assert present. The planted
        # positive must then flip to COVERED (stop firing) - proving the
        # no-cross-source-assert predicate is what drives the fire.
        orig = MSFA._has_consistency
        try:
            MSFA._has_consistency = lambda *a, **k: 999
            rows = _rows(RUST_POSITIVE, "tar.rs")
            self.assertEqual(_fired(rows), [], "fire survived neutralized predicate")
            self.assertTrue(rows and all(r["consistency_checked"] for r in rows))
        finally:
            MSFA._has_consistency = orig
        # sanity: predicate restored -> positive fires again
        self.assertEqual(len(_fired(_rows(RUST_POSITIVE, "tar.rs"))), 1)

    def test_neutralize_size_classifier_empties_enumeration(self):
        orig = MSFA._is_size_ident
        try:
            MSFA._is_size_ident = lambda name: False
            self.assertEqual(_rows(RUST_POSITIVE, "tar.rs"), [])
            self.assertEqual(_rows(GO_POSITIVE, "reader.go"), [])
        finally:
            MSFA._is_size_ident = orig
        self.assertEqual(len(_fired(_rows(RUST_POSITIVE, "tar.rs"))), 1)

    # -- exclusions --------------------------------------------------------
    def test_generated_source_excluded(self):
        gen = "// Code generated by protoc. DO NOT EDIT.\n" + GO_POSITIVE
        # via the file walker: generated header suppresses the file
        import tempfile, os
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "x.go"
            p.write_text(gen)
            self.assertNotIn(p, list(MSFA._iter_source_files(pathlib.Path(d))))

    def test_test_file_excluded(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "reader_test.go"
            p.write_text(GO_POSITIVE)
            self.assertNotIn(p, list(MSFA._iter_source_files(pathlib.Path(d))))

    # -- advisory contract on every row ------------------------------------
    def test_advisory_contract(self):
        for src, rel in ((RUST_POSITIVE, "tar.rs"), (GO_POSITIVE, "reader.go"),
                         (SOL_POSITIVE, "P.sol"), (RUST_COVERED, "tar.rs")):
            for r in _rows(src, rel):
                self.assertEqual(r["capability"], "EXT01")
                self.assertTrue(r["advisory"])
                self.assertFalse(r["auto_credit"])
                self.assertEqual(r["verdict"], "needs-fuzz")
                self.assertIn("sources", r)
                self.assertIn("sink_line", r)


if __name__ == "__main__":
    unittest.main()
