"""Tests for ``tools/nested-length-prefix-parent-bound-screen.py``  (EXT05).

The NESTED length-prefix PARENT-BOUND reconciliation screen.  Three mandatory
NON-VACUITY legs (each proves a different part of the detector is load-bearing):

  1. PLANTED POSITIVE fires  - a length-prefixed decoder that advances a raw
     memory pointer by a child self-declared length with NO parent-bound
     reconciliation guard  ->  fires=True.
  2. COVERED / benign NEGATIVE is silent  - the SAME decoder with a parent-bound
     reconciliation guard added  ->  still enumerated as an enforcement point, but
     fires=False.
  3. NEUTRALISE the core predicate  - monkeypatching ``_find_parent_bound_guard``
     to a constant (always "a guard exists") STOPS the positive firing; likewise
     monkeypatching ``_raw_memory_context`` to constant-False.  Proves both core
     predicates are load-bearing (non-vacuity).

Plus: cross-language (Rust unsafe) positive/negative, generated/test exclusion,
sidecar-emission schema, and the real Polygon RLPReader fleet anchor
(silent-on-original / fires-on-mutant).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "nested-length-prefix-parent-bound-screen.py"
FLEET_ANCHOR = Path(
    "/Users/wolf/audits/polygon/src/sPOL-contracts/src/msg/lib/RLPReader.sol")


def _load_tool() -> Any:
    name = "_ext05_nested_lenprefix_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _scan(src: str, fname: str):
    """Write src to a temp file with the given name and scan it -> rows."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / fname
        p.write_text(textwrap.dedent(src))
        return tool.scan_file(p, fname)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
# Solidity: last item's declared length advances a raw memPtr past the parent,
# NO parent-bound reconciliation. (Polygon RLPReader.toList shape.)
_SOL_POSITIVE = """
    library BadRLP {
        struct Item { uint256 len; uint256 memPtr; }
        function toList(Item memory item) internal pure returns (uint256) {
            uint256 memPtr = item.memPtr;
            uint256 dataLen;
            uint256 sum;
            for (uint256 i = 0; i < 4; i++) {
                dataLen = _itemLength(memPtr);
                memPtr = memPtr + dataLen;
                sum += dataLen;
            }
            return sum;
        }
        function _itemLength(uint256 p) private pure returns (uint256 l) {
            assembly { l := byte(0, mload(p)) }
        }
    }
"""

# Same decoder, but WITH the parent-bound reconciliation guard (child_end must
# stay inside the parent extent) before the advance is trusted.
_SOL_NEGATIVE = """
    library GoodRLP {
        struct Item { uint256 len; uint256 memPtr; }
        function toList(Item memory item) internal pure returns (uint256) {
            uint256 memPtr = item.memPtr;
            uint256 endPtr = item.memPtr + item.len;
            uint256 dataLen;
            uint256 sum;
            for (uint256 i = 0; i < 4; i++) {
                dataLen = _itemLength(memPtr);
                require(memPtr + dataLen <= endPtr, "child runs past parent");
                memPtr = memPtr + dataLen;
                sum += dataLen;
            }
            return sum;
        }
        function _itemLength(uint256 p) private pure returns (uint256 l) {
            assembly { l := byte(0, mload(p)) }
        }
    }
"""

# Rust: unsafe pointer read + advance by a child length, no bound reconciliation.
# The lifetime `<'a>` / `&'a` regression-guards the char-literal masking (a
# lifetime must NOT be masked as a char literal, which would scramble the body).
_RUST_POSITIVE = """
    fn decode_items<'a>(buf: &'a [u8]) -> u64 {
        let mut pos: usize = 0;
        let mut total: u64 = 0;
        for _ in 0..4 {
            let n = read_u32(buf, pos) as usize;
            unsafe {
                let p = buf.as_ptr().add(pos);
                total += *p as u64;
            }
            pos += n;
        }
        total
    }
"""

_RUST_NEGATIVE = """
    fn decode_items(buf: &[u8]) -> u64 {
        let mut pos: usize = 0;
        let mut total: u64 = 0;
        for _ in 0..4 {
            let n = read_u32(buf, pos) as usize;
            if pos + n > buf.len() { break; }
            unsafe {
                let p = buf.as_ptr().add(pos);
                total += *p as u64;
            }
            pos += n;
        }
        total
    }
"""

# Go: the canonical varint 2-tuple idiom  `n, _ := binary.Uvarint(buf[off:])`
# advances an unsafe cursor by the decoded child length with NO parent-bound
# reconciliation.  This is the exact API named in the class general_question and
# was SILENTLY DROPPED before the fix (the single-var _ASSIGN_LEN_RE matched the
# blank identifier `_` first, so the length var `n` was lost and 0 enforcement
# points were emitted). Must fire.
_GO_TUPLE_POSITIVE = """
    package codec
    import ("encoding/binary"; "unsafe")
    func decodeItems(buf []byte) uint64 {
        off := 0
        var total uint64 = 0
        for i := 0; i < 4; i++ {
            n, _ := binary.Uvarint(buf[off:])
            p := unsafe.Pointer(&buf[off])
            total += uint64(*(*byte)(p))
            off = off + int(n)
        }
        return total
    }
"""

# Same Go decoder WITH a parent-bound reconciliation guard: the reconciled/benign
# sibling must stay silent (enumerated, fires=False). This pins the fix does not
# over-fire on the guarded form.
_GO_TUPLE_NEGATIVE = """
    package codec
    import ("encoding/binary"; "unsafe")
    func decodeItems(buf []byte, end int) uint64 {
        off := 0
        var total uint64 = 0
        for i := 0; i < 4; i++ {
            n, _ := binary.Uvarint(buf[off:])
            if off + int(n) > end { break }
            p := unsafe.Pointer(&buf[off])
            total += uint64(*(*byte)(p))
            off = off + int(n)
        }
        return total
    }
"""

# Non-blank 2-tuple  `value, cnt := binary.Uvarint(...)`: the VALUE var (position 1)
# is the decoded payload length and must be the bound length var - NOT the
# bytes-consumed count `cnt` (position 2). Before the fix the single-var regex
# bound `cnt`, a systematically-wrong length var.
_GO_TUPLE_NONBLANK = """
    package codec
    import ("encoding/binary"; "unsafe")
    func decodeItems(buf []byte) uint64 {
        off := 0
        var total uint64 = 0
        for i := 0; i < 4; i++ {
            value, cnt := binary.Uvarint(buf[off:])
            _ = cnt
            p := unsafe.Pointer(&buf[off])
            total += uint64(*(*byte)(p))
            off = off + int(value)
        }
        return total
    }
"""


class Ext05NonVacuity(unittest.TestCase):

    # --- LEG 1: planted positive fires ------------------------------------
    def test_leg1_planted_positive_fires(self):
        rows = _scan(_SOL_POSITIVE, "BadRLP.sol")
        fired = [r for r in rows if r["fires"]]
        self.assertTrue(fired, "expected the unreconciled raw-pointer decoder to fire")
        r = next(r for r in fired if r["function"] == "toList")
        self.assertFalse(r["has_parent_bound_guard"])
        self.assertTrue(r["raw_memory"])
        self.assertEqual(r["disposition"], "unreconciled-raw-memory-overread")
        self.assertEqual(r["cursor_var"], "memPtr")
        self.assertEqual(r["length_var"], "dataLen")
        # required advisory-sidecar schema keys
        for k in ("capability", "fires", "file", "line", "function", "advisory",
                  "auto_credit", "verdict"):
            self.assertIn(k, r)
        self.assertEqual(r["capability"], "EXT05")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        self.assertEqual(r["verdict"], "needs-fuzz")

    # --- LEG 2: covered / benign negative is silent (but enumerated) ------
    def test_leg2_covered_negative_silent(self):
        rows = _scan(_SOL_NEGATIVE, "GoodRLP.sol")
        toList = [r for r in rows if r["function"] == "toList"]
        self.assertTrue(toList, "the reconciled decoder must still be an enforcement point")
        r = toList[0]
        self.assertFalse(r["fires"], "a parent-bound-reconciled decoder must NOT fire")
        self.assertTrue(r["has_parent_bound_guard"])
        self.assertEqual(r["disposition"], "parent-bound-reconciled")
        self.assertIsNotNone(r["guard_evidence"])

    # --- LEG 3a: neutralise the guard-absence predicate -> stops firing ---
    def test_leg3a_neutralize_guard_predicate_stops_fire(self):
        # baseline: it fires
        self.assertTrue(any(r["fires"] for r in _scan(_SOL_POSITIVE, "BadRLP.sol")))
        orig = tool._find_parent_bound_guard
        try:
            # constant: "a parent-bound guard ALWAYS exists"
            tool._find_parent_bound_guard = lambda *a, **k: "NEUTRALIZED-CONSTANT-GUARD"
            rows = _scan(_SOL_POSITIVE, "BadRLP.sol")
        finally:
            tool._find_parent_bound_guard = orig
        self.assertFalse(
            any(r["fires"] for r in rows),
            "neutralising the guard-absence predicate must stop the positive firing")
        # and the seam restored -> fires again
        self.assertTrue(any(r["fires"] for r in _scan(_SOL_POSITIVE, "BadRLP.sol")))

    # --- LEG 3b: neutralise the raw-memory predicate -> stops firing ------
    def test_leg3b_neutralize_rawmem_predicate_stops_fire(self):
        orig = tool._raw_memory_context
        try:
            tool._raw_memory_context = lambda *a, **k: False
            rows = _scan(_SOL_POSITIVE, "BadRLP.sol")
        finally:
            tool._raw_memory_context = orig
        self.assertFalse(
            any(r["fires"] for r in rows),
            "neutralising the raw-memory predicate must stop the positive firing")
        # it is still enumerated as an enforcement point, now memory-safe-labelled
        disp = {r["disposition"] for r in rows}
        self.assertIn("memory-safe-slice-panic", disp)


class Ext05CrossLanguage(unittest.TestCase):

    def test_rust_positive_fires(self):
        rows = _scan(_RUST_POSITIVE, "decode.rs")
        fired = [r for r in rows if r["fires"]]
        self.assertTrue(fired, "unsafe Rust pointer decoder without bound check must fire")
        r = fired[0]
        self.assertEqual(r["lang"], "rust")
        self.assertEqual(r["cursor_var"], "pos")
        self.assertTrue(r["raw_memory"])

    def test_rust_negative_silent(self):
        rows = _scan(_RUST_NEGATIVE, "decode.rs")
        self.assertTrue(rows, "reconciled Rust decoder must still be enumerated")
        self.assertFalse(any(r["fires"] for r in rows),
                         "a bound-checked Rust decoder must NOT fire")
        self.assertTrue(all(r["has_parent_bound_guard"] for r in rows))

    # --- REGRESSION: Go varint 2-tuple idiom (was a silent false-negative) -----
    def test_go_tuple_uvarint_positive_fires(self):
        # `n, _ := binary.Uvarint(buf[off:])` + unsafe advance, no bound guard.
        # Before the fix this yielded 0 enforcement points (silently dropped).
        rows = _scan(_GO_TUPLE_POSITIVE, "codec.go")
        self.assertTrue(rows, "the Go varint 2-tuple decoder must be enumerated")
        fired = [r for r in rows if r["fires"]]
        self.assertTrue(
            fired, "the Go `n, _ := binary.Uvarint(...)` unsafe decoder must fire")
        r = fired[0]
        self.assertEqual(r["lang"], "go")
        self.assertEqual(r["cursor_var"], "off")
        # the DECODED VALUE var (tuple position 1), not the blank `_`
        self.assertEqual(r["length_var"], "n")
        self.assertTrue(r["raw_memory"])
        self.assertEqual(r["disposition"], "unreconciled-raw-memory-overread")

    def test_go_tuple_uvarint_negative_silent(self):
        # the reconciled/benign sibling must stay silent (enumerated, fires=False)
        rows = _scan(_GO_TUPLE_NEGATIVE, "codec.go")
        self.assertTrue(rows, "the reconciled Go varint decoder must be enumerated")
        self.assertFalse(
            any(r["fires"] for r in rows),
            "a parent-bound-reconciled Go varint decoder must NOT fire")
        self.assertTrue(all(r["has_parent_bound_guard"] for r in rows))

    def test_go_tuple_nonblank_binds_value_not_count(self):
        # `value, cnt := binary.Uvarint(...)`: bind the payload-length VALUE var
        # (tuple position 1), never the bytes-consumed count `cnt`.
        rows = _scan(_GO_TUPLE_NONBLANK, "codec.go")
        fired = [r for r in rows if r["fires"]]
        self.assertTrue(fired, "the non-blank Go tuple decoder must fire")
        self.assertEqual(fired[0]["length_var"], "value")


class Ext05Exclusions(unittest.TestCase):

    def test_generated_file_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            gen = root / "src" / "codec.pb.go"
            gen.parent.mkdir(parents=True)
            gen.write_text("// Code generated by protoc. DO NOT EDIT.\n" + _RUST_POSITIVE)
            files = list(tool._iter_source_files(root))
            self.assertEqual(files, [], "generated .pb.go must be excluded")

    def test_test_and_fuzz_dirs_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for sub in ("near-test-contracts", "contract-for-fuzzing-rs", "tests"):
                p = root / "src" / sub / "lib.rs"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(_RUST_POSITIVE)
            files = list(tool._iter_source_files(root))
            self.assertEqual(files, [], "test/fuzz fixture dirs must be pruned")

    def test_nested_inscope_lib_not_pruned(self):
        # a nested src/**/lib/ dir is in-scope and must be scanned (RLPReader lives there)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / "src" / "msg" / "lib" / "Reader.sol"
            p.parent.mkdir(parents=True)
            p.write_text(_SOL_POSITIVE)
            files = [str(f) for f in tool._iter_source_files(root)]
            self.assertTrue(any("Reader.sol" in f for f in files),
                            "nested src/**/lib/ must NOT be pruned as a dependency dir")


class Ext05SidecarEmission(unittest.TestCase):

    def test_workspace_mode_emits_advisory_sidecar(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            src = ws / "src"
            src.mkdir()
            (src / "BadRLP.sol").write_text(textwrap.dedent(_SOL_POSITIVE))
            rc = tool.main(["--workspace", str(ws)])
            side = ws / ".auditooor" / "nested_length_prefix_parent_bound_hypotheses.jsonl"
            self.assertTrue(side.exists(), "sidecar must be emitted under <ws>/.auditooor/")
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            self.assertTrue(rows)
            self.assertTrue(any(r["fires"] for r in rows))
            for r in rows:
                self.assertEqual(r["capability"], "EXT05")
                self.assertTrue(r["advisory"])
                self.assertFalse(r["auto_credit"])
                self.assertEqual(r["verdict"], "needs-fuzz")
            # default mode is advisory: exit 0 even with a fired point
            self.assertEqual(rc, 0)

    def test_strict_exit_code_on_fired_point(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            src = ws / "src"
            src.mkdir()
            (src / "BadRLP.sol").write_text(textwrap.dedent(_SOL_POSITIVE))
            rc = tool.main(["--workspace", str(ws), "--strict"])
            self.assertEqual(rc, 1, "--strict must exit 1 on a fired severity-eligible point")

    def test_source_mode_writes_no_sidecar(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "BadRLP.sol").write_text(textwrap.dedent(_SOL_POSITIVE))
            tool.main(["--source", str(root)])
            self.assertFalse((root / ".auditooor").exists(),
                             "--source must NOT write a sidecar")


class Ext05FleetAnchor(unittest.TestCase):
    """Real Polygon RLPReader.toList: silent on the guarded original, fires when
    the parent-bound reconciliation require is removed (behaviour-changing)."""

    @unittest.skipUnless(FLEET_ANCHOR.exists(), "polygon fleet ws not present")
    def test_original_silent(self):
        rows = tool.scan_file(FLEET_ANCHOR, FLEET_ANCHOR.name)
        funcs = {r["function"] for r in rows}
        self.assertIn("toList", funcs, "toList must be enumerated as an enforcement point")
        self.assertFalse(any(r["fires"] for r in rows),
                         "the guarded upstream RLPReader must be silent")

    @unittest.skipUnless(FLEET_ANCHOR.exists(), "polygon fleet ws not present")
    def test_mutant_fires(self):
        src = FLEET_ANCHOR.read_text()
        needle = '        require(memPtr - item.memPtr == item.len, "Wrong total length.");\n'
        self.assertIn(needle, src)
        mutated = src.replace(needle, "")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "RLPReader.sol"
            p.write_text(mutated)
            rows = tool.scan_file(p, "RLPReader.sol")
        toList = next(r for r in rows if r["function"] == "toList")
        self.assertTrue(toList["fires"],
                        "removing the parent-bound reconciliation must make toList fire")
        self.assertEqual(toList["disposition"], "unreconciled-raw-memory-overread")


if __name__ == "__main__":
    unittest.main()
