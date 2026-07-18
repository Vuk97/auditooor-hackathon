#!/usr/bin/env python3
"""test_E7.py - deserialize/allocate-before-cap pre-auth amplification screen (E7).

E7 is a GENERAL cross-language ENFORCEMENT screen (Go / Rust / Solidity). It
enumerates ONE delegated-and-trusted invariant - "an attacker-decoded length/
count/size is BOUNDED before it drives an allocation or bounded loop" - states
the private invariant (a dominating cap N<=K / clamp) and attacks it (a site
that reaches the alloc/loop with NO cap => pre-auth memory/CPU amplification).
It is NOT a bug-shape detector; every hit is advisory verdict='needs-fuzz'.

NON-VACUITY (all asserted below):
  * planted POSITIVE fires - unguarded alloc sized by a decoded/param length,
    in each of Go / Rust / Solidity;
  * guarded NEGATIVE is silent - the same site with a dominating cap;
  * NEUTRALISING the core predicate kills the positive - monkeypatching
    has_cap_before -> always-True (pretend every site is capped) makes the
    planted positive vanish, and so does monkeypatching is_attacker_derived
    -> always-benign. Either alone proves both halves of the predicate are
    load-bearing;
  * FP-guards - a constant size, a `.len()` of an already-materialised
    collection, and an inline-clamped size are each silent.

MUTATION-VERIFY on REAL fleet source (read-only; shared WS never git-mutated):
  near core/primitives/src/reed_solomon.rs caps `encoded_length >
  MAX_ENCODED_LENGTH` BEFORE `Vec::with_capacity(encoded_length)`.
  * the CLEAN real file is SILENT;
  * a mkdtemp COPY with that cap block deleted (a behaviour-changing DoS-guard
    removal, not an EVM/compiler-enforced no-op) FIRES exactly on the
    with_capacity line -> mutation-kill.
"""
import importlib.util
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "deserialize-precap-amplification-screen.py"
_REAL_NEAR = Path(
    "/Users/wolf/audits/near/src/core/primitives/src/reed_solomon.rs")


def _load():
    spec = importlib.util.spec_from_file_location("e7_screen", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["e7_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---- synthetic fixtures (inline, so the test is self-contained) ----------- #

RUST_VULN = """\
pub fn decode(reader: &mut R, count: usize) -> Vec<Item> {
    // count arrives from the wire, never bounded
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(Item::default());
    }
    out
}
"""

RUST_GUARDED = """\
pub fn decode(reader: &mut R, count: usize) -> Result<Vec<Item>, Error> {
    if count > MAX_ITEMS {
        return Err(Error::TooMany);
    }
    let mut out = Vec::with_capacity(count);
    out
}
"""

RUST_DECODE_LOCAL = """\
pub fn read(buf: &[u8]) -> Vec<u8> {
    let n = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    let m = decode_length(buf);
    let mut out = Vec::with_capacity(m);
    out
}
"""

RUST_FP_CONSTANT = """\
pub fn build() -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 * 32);
    buf
}
"""

RUST_FP_LEN = """\
pub fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    out
}
"""

RUST_FP_CLAMP = """\
pub fn decode(count: usize) -> Vec<Item> {
    let mut out = Vec::with_capacity(count.min(MAX_ITEMS));
    out
}
"""

GO_VULN = """\
func Decode(r io.Reader, length int) []byte {
	buf := make([]byte, length)
	return buf
}
"""

GO_GUARDED = """\
func Decode(r io.Reader, length int) ([]byte, error) {
	if length > MaxLen {
		return nil, errors.New("too large")
	}
	buf := make([]byte, length)
	return buf, nil
}
"""

GO_FP_LEN = """\
func Copy(parts [][]byte) []byte {
	buf := make([]byte, len(parts))
	return buf
}
"""

SOL_VULN = """\
function decode(uint256 count) public pure returns (bytes memory) {
    bytes memory out = new bytes(count);
    return out;
}
"""

SOL_GUARDED = """\
function decode(uint256 count) public pure returns (bytes memory) {
    require(count <= MAX_LEN, "too large");
    bytes memory out = new bytes(count);
    return out;
}
"""

SOL_ARRAY_VULN = """\
function build(uint256 numItems) public pure returns (uint256[] memory) {
    uint256[] memory arr = new uint256[](numItems);
    for (uint256 i = 0; i < numItems; i++) {
        arr[i] = i;
    }
    return arr;
}
"""


class TestE7Screen(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _fires(self, text, lang):
        return self.m.screen_text(text, lang, "<t>")

    # -------- planted positives fire (each language) ---------------------- #
    def test_rust_positive_fires(self):
        hits = self._fires(RUST_VULN, "rust")
        self.assertTrue(hits, "unguarded Rust with_capacity(count) must fire")
        self.assertTrue(any(h["size_operand"] == "count" and
                            h["verdict"] == "needs-fuzz" for h in hits))

    def test_rust_decode_local_fires(self):
        hits = self._fires(RUST_DECODE_LOCAL, "rust")
        self.assertTrue(any(h["origin"] == "decoded" for h in hits),
                        "a decode-sourced local must be flagged as attacker-origin")

    def test_go_positive_fires(self):
        hits = self._fires(GO_VULN, "go")
        self.assertTrue(any(h["alloc_kind"] == "make-alloc" and
                            h["size_operand"] == "length" for h in hits))

    def test_solidity_positive_fires(self):
        hits = self._fires(SOL_VULN, "solidity")
        self.assertTrue(any(h["alloc_kind"] == "new-bytes" and
                            h["size_operand"] == "count" for h in hits))

    def test_solidity_array_and_loop_fire(self):
        hits = self._fires(SOL_ARRAY_VULN, "solidity")
        kinds = {h["alloc_kind"] for h in hits}
        self.assertIn("new-array", kinds)
        self.assertIn("bounded-loop", kinds)

    # -------- guarded negatives are silent -------------------------------- #
    def test_rust_guarded_silent(self):
        self.assertEqual(self._fires(RUST_GUARDED, "rust"), [])

    def test_go_guarded_silent(self):
        self.assertEqual(self._fires(GO_GUARDED, "go"), [])

    def test_solidity_guarded_silent(self):
        self.assertEqual(self._fires(SOL_GUARDED, "solidity"), [])

    # -------- FP-guards ---------------------------------------------------- #
    def test_fp_constant_silent(self):
        self.assertEqual(self._fires(RUST_FP_CONSTANT, "rust"), [])

    def test_fp_len_of_collection_silent(self):
        self.assertEqual(self._fires(RUST_FP_LEN, "rust"), [])
        self.assertEqual(self._fires(GO_FP_LEN, "go"), [])

    def test_fp_inline_clamp_silent(self):
        self.assertEqual(self._fires(RUST_FP_CLAMP, "rust"), [])

    # -------- neutralising the CORE predicate kills the positive ---------- #
    def test_neutralise_cap_predicate_kills_positive(self):
        # Pretend every site is already capped -> the positive must vanish.
        orig = self.m.has_cap_before
        self.m.has_cap_before = lambda *a, **k: True
        try:
            self.assertEqual(self._fires(RUST_VULN, "rust"), [],
                             "if has_cap_before is load-bearing, forcing it True "
                             "must silence the planted positive")
        finally:
            self.m.has_cap_before = orig
        # sanity: restored predicate fires again
        self.assertTrue(self._fires(RUST_VULN, "rust"))

    def test_neutralise_attacker_origin_kills_positive(self):
        orig = self.m.is_attacker_derived
        self.m.is_attacker_derived = lambda *a, **k: (False, "benign", None)
        try:
            self.assertEqual(self._fires(RUST_VULN, "rust"), [],
                             "if attacker-origin is load-bearing, forcing it "
                             "benign must silence the planted positive")
        finally:
            self.m.is_attacker_derived = orig

    # -------- advisory-only contract --------------------------------------- #
    def test_every_hit_is_needs_fuzz(self):
        for txt, lang in ((RUST_VULN, "rust"), (GO_VULN, "go"),
                          (SOL_VULN, "solidity")):
            for h in self._fires(txt, lang):
                self.assertEqual(h["verdict"], "needs-fuzz")
                self.assertIn("delegated_invariant", h)
                self.assertIn("private_invariant", h)


@unittest.skipUnless(_REAL_NEAR.exists(),
                     "near fleet source not present on this host")
class TestE7FleetMutationVerify(unittest.TestCase):
    """SILENT on the guarded real file; FIRES on a temp copy with the cap gone."""

    def setUp(self):
        self.m = _load()

    def test_real_guarded_file_silent(self):
        hits = self.m.screen_file(str(_REAL_NEAR))
        self.assertEqual(hits, [],
                         "reed_solomon_decode caps encoded_length before "
                         "Vec::with_capacity -> the screen must be SILENT")

    def test_mutant_copy_fires(self):
        src = _REAL_NEAR.read_text()
        # remove the dominating cap guard (behaviour-changing DoS-guard removal)
        mutant = re.sub(
            r"\n\s*if encoded_length > MAX_ENCODED_LENGTH \{\n"
            r"\s*return Err\(Error::other\(\"encoded length is too large\"\)\);\n"
            r"\s*\}\n",
            "\n", src)
        self.assertNotEqual(mutant, src, "mutation must actually apply")
        tmp = Path(tempfile.mkdtemp()) / "reed_solomon.rs"
        try:
            tmp.write_text(mutant)
            hits = self.m.screen_file(str(tmp))
            self.assertTrue(hits, "mutant (cap removed) must fire")
            self.assertTrue(
                any(h["size_operand"] == "encoded_length" and
                    h["alloc_kind"] == "with_capacity" and
                    h["origin"] == "param" for h in hits),
                "the fire must land on with_capacity(encoded_length)")
        finally:
            shutil.rmtree(tmp.parent, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
