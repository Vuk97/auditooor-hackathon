#!/usr/bin/env python3
"""Tests for GEN-4C width-narrowing-cast screen (tools/width-narrowing-cast-screen.py).

Non-vacuous: each FIRE case is paired with a near-identical SILENT case so a
mutant that drops an FP-control (or a narrowing arm) is killed. Covers all four
langs (Solidity / Rust / Go / Move) plus the schema / advisory-contract shape.
"""
import importlib.util
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "width-narrowing-cast-screen.py"
_spec = importlib.util.spec_from_file_location("gen4c", _TOOL)
gen4c = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen4c)


def _scan(name, text):
    return gen4c.scan_file(Path(name), name, file_text=text)


def _fired_lines(rows):
    return sorted(r["line"] for r in rows if r.get("fires"))


class SolidityArm(unittest.TestCase):
    def test_fires_on_narrowing_of_amount(self):
        src = ("contract C {\n"
               "  function f(uint256 amount) external {\n"
               "    uint64 a = uint64(amount);\n"
               "  }\n}\n")
        rows = _scan("A.sol", src)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["lang"], "solidity")
        self.assertEqual(r["target_type"], "uint64")
        self.assertEqual(r["severity"], "high")
        self.assertTrue(r["fires"])

    def test_silent_on_safecast_touint(self):
        # OZ SafeCast `.toUint128()` (capital U) must NOT be flagged.
        src = ("contract C {\n"
               "  function f(uint256 newTotalAssets) external {\n"
               "    uint128 t = newTotalAssets.toUint128();\n"
               "  }\n}\n")
        self.assertEqual(_scan("A.sol", src), [])

    def test_silent_on_widening_uint256(self):
        src = ("contract C {\n"
               "  function f(uint64 amount) external {\n"
               "    uint256 w = uint256(amount);\n"
               "  }\n}\n")
        self.assertEqual(_scan("A.sol", src), [])

    def test_silent_on_masked_operand(self):
        src = ("contract C {\n"
               "  function f(uint256 amount) external {\n"
               "    uint16 b = uint16(amount & 0xffff);\n"
               "  }\n}\n")
        self.assertEqual(_scan("A.sol", src), [])

    def test_silent_on_literal_operand(self):
        src = ("contract C {\n"
               "  function f() external {\n"
               "    uint8 c = uint8(3);\n"
               "  }\n}\n")
        self.assertEqual(_scan("A.sol", src), [])

    def test_silent_on_dominating_bound(self):
        src = ("contract C {\n"
               "  function f(uint256 amount) external {\n"
               "    require(amount <= type(uint64).max);\n"
               "    uint64 a = uint64(amount);\n"
               "  }\n}\n")
        self.assertEqual(_scan("A.sol", src), [])

    def test_silent_without_value_hint(self):
        src = ("contract C {\n"
               "  function f(uint256 foo) external {\n"
               "    uint32 z = uint32(foo);\n"
               "  }\n}\n")
        self.assertEqual(_scan("A.sol", src), [])


class GoArm(unittest.TestCase):
    def test_fires_on_uint32_of_amount(self):
        src = ("func f(amount uint64) {\n"
               "    a := uint32(amount)\n"
               "}\n")
        rows = _scan("b.go", src)
        self.assertEqual(_fired_lines(rows), [2])
        self.assertEqual(rows[0]["target_type"], "uint32")

    def test_silent_on_word_width_int(self):
        src = ("func f(amount uint64) {\n"
               "    n := int(amount)\n"
               "}\n")
        self.assertEqual(_scan("b.go", src), [])

    def test_silent_on_byte_slice_conversion(self):
        # `[]byte(buf)` is a slice conversion, not a scalar narrowing.
        src = ("func f(payload []byte) {\n"
               "    b := []byte(payload)\n"
               "    _ = b\n"
               "}\n")
        self.assertEqual(_scan("b.go", src), [])


class RustArm(unittest.TestCase):
    def test_fires_on_amount_as_u32(self):
        src = ("fn f(amount: u128) {\n"
               "    let a = amount as u32;\n"
               "}\n")
        rows = _scan("c.rs", src)
        self.assertEqual(_fired_lines(rows), [2])
        self.assertEqual(rows[0]["target_type"], "u32")

    def test_silent_on_word_width_u64(self):
        # `as u64` is word width on 64-bit targets -> not a narrowing target.
        src = ("fn f(amount: u128) {\n"
               "    let w = amount as u64;\n"
               "}\n")
        self.assertEqual(_scan("c.rs", src), [])

    def test_silent_on_index_var_no_hint(self):
        src = ("fn f(i: usize) {\n"
               "    let j = i as u32;\n"
               "}\n")
        self.assertEqual(_scan("c.rs", src), [])


class MoveArm(unittest.TestCase):
    def test_fires_on_amount_as_u64(self):
        src = ("public fun f(amount: u128) {\n"
               "    let a = (amount as u64);\n"
               "}\n")
        rows = _scan("d.move", src)
        self.assertEqual(_fired_lines(rows), [2])
        self.assertEqual(rows[0]["target_type"], "u64")

    def test_silent_on_widening_u256(self):
        src = ("public fun f(amount: u128) {\n"
               "    let w = (amount as u256);\n"
               "}\n")
        self.assertEqual(_scan("d.move", src), [])


class ContractShape(unittest.TestCase):
    def test_row_schema_and_advisory_contract(self):
        src = ("contract C {\n"
               "  function f(uint256 amount) external {\n"
               "    uint64 a = uint64(amount);\n"
               "  }\n}\n")
        r = _scan("A.sol", src)[0]
        self.assertEqual(r["schema"], "auditooor.width_narrowing_cast_hypotheses.v1")
        self.assertEqual(r["capability"], "GEN_4C")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        for k in ("id", "file", "line", "function", "lang", "target_type",
                  "operand", "value_hint", "why_severity_anchored"):
            self.assertIn(k, r)

    def test_non_source_extension_ignored(self):
        self.assertEqual(_scan("readme.md", "uint64(amount)"), [])


class MutationWitness(unittest.TestCase):
    """The mutation the dispatch mandates: a guarded narrowing (`.toUint128()`)
    stays SILENT; replacing it with a bare `uint128(x)` cast on the same
    value-bearing operand FIRES. Byte-for-byte the same operand + hint."""

    _GUARDED = ("contract V {\n"
                "  function f(uint256 newTotalAssets) external {\n"
                "    _totalAssets = newTotalAssets.toUint128();\n"
                "  }\n}\n")
    _BARE = ("contract V {\n"
             "  function f(uint256 newTotalAssets) external {\n"
             "    _totalAssets = uint128(newTotalAssets);\n"
             "  }\n}\n")

    def test_guarded_silent(self):
        self.assertEqual(_scan("V.sol", self._GUARDED), [])

    def test_bare_fires(self):
        rows = _scan("V.sol", self._BARE)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target_type"], "uint128")
        self.assertTrue(rows[0]["fires"])


if __name__ == "__main__":
    unittest.main()
