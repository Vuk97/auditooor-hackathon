#!/usr/bin/env python3
"""Regression tests for per-fn-mimo-batch-gen.py excerpt resolution.

SEI 2026-07-04: 355/475 residual-hunt tasks emitted "(excerpt unavailable - file
or fn not found)" with `LINE RANGE: 0..0`. Root cause: read_file_excerpt matched
a definition site with `(func|function|...)\\s+NAME`, which silently fails on
- every Go METHOD (`func (s *StateDB) SubRefund(` - the receiver sits between the
  keyword and the name), and
- every qualified / signatured NAME (`Type.method`, `foo(uint256)`),
while the authoritative `:line` suffix already present on many `file` fields was
discarded (and, for Solidity, broke file resolution outright). The hunt still
worked (agents fell back to R76 real-source reads) but wasted tool-calls and lost
precision. These tests pin the fix and must never false-pass.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "pfmbg", str(Path(__file__).resolve().parent.parent / "per-fn-mimo-batch-gen.py"))
pfmbg = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pfmbg)

GO_SRC = """package state

import "fmt"

// NewDBImpl is a plain constructor (matched even by the old regex).
func NewDBImpl(ctx Context) *DBImpl {
	return &DBImpl{ctx: ctx}
}

// SubRefund is a METHOD with a pointer receiver - the historical miss.
func (s *StateDB) SubRefund(gas uint64) {
	if gas > s.refund {
		panic("refund underflow")
	}
	s.refund -= gas
}

func (s *StateDB) AddRefund(gas uint64) {
	s.refund += gas
}
"""

SOL_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EVMCompatibilityTester {
    function callAnotherContract(address target, bytes calldata data) external {
        target.call(data);
    }
}
"""


class SplitPathLineTest(unittest.TestCase):
    def test_path_with_line(self):
        self.assertEqual(pfmbg._split_path_line("src/x/Foo.sol:94"), ("src/x/Foo.sol", 94))

    def test_bare_path_none(self):
        self.assertEqual(pfmbg._split_path_line("src/x/Foo.go"), ("src/x/Foo.go", None))

    def test_path_line_col(self):
        self.assertEqual(pfmbg._split_path_line("src/x/Foo.go:12:7"), ("src/x/Foo.go", 12))

    def test_non_digit_colon_left_intact(self):
        # a ':' not followed by digits (e.g. a Windows drive) must not be split
        self.assertEqual(pfmbg._split_path_line("C:/x/Foo.go"), ("C:/x/Foo.go", None))

    def test_empty(self):
        self.assertEqual(pfmbg._split_path_line(""), ("", None))
        self.assertEqual(pfmbg._split_path_line(None), ("", None))


class DebaseFnNameTest(unittest.TestCase):
    def test_qualified(self):
        self.assertEqual(pfmbg._debase_fn_name("HookedStateDB.SetState"), "SetState")

    def test_signatured(self):
        self.assertEqual(
            pfmbg._debase_fn_name("EVMCompatibilityTester.callAnotherContract(address,bytes)"),
            "callAnotherContract")

    def test_go_colons(self):
        self.assertEqual(pfmbg._debase_fn_name("pkg::doThing"), "doThing")

    def test_bare(self):
        self.assertEqual(pfmbg._debase_fn_name("SubRefund"), "SubRefund")

    def test_placeholder(self):
        self.assertEqual(pfmbg._debase_fn_name("?"), "")
        self.assertEqual(pfmbg._debase_fn_name(""), "")


class ReadFileExcerptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.go = Path(self.tmp.name) / "statedb.go"
        self.go.write_text(GO_SRC, encoding="utf-8")
        self.sol = Path(self.tmp.name) / "EVMCompatibilityTester.sol"
        self.sol.write_text(SOL_SRC, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_go_method_with_receiver_matches(self):
        # THE regression: a pointer-receiver method must resolve.
        exc, start, end = pfmbg.read_file_excerpt(str(self.go), "SubRefund")
        self.assertTrue(exc, "receiver-method excerpt must not be empty")
        self.assertIn("func (s *StateDB) SubRefund", exc.splitlines()[0])
        self.assertGreater(start, 0)
        self.assertGreater(end, start)

    def test_go_plain_constructor_still_matches(self):
        exc, start, _ = pfmbg.read_file_excerpt(str(self.go), "NewDBImpl")
        self.assertIn("func NewDBImpl", exc.splitlines()[0])
        self.assertGreater(start, 0)

    def test_qualified_name_resolves_to_method(self):
        exc, start, _ = pfmbg.read_file_excerpt(str(self.go), "StateDB.AddRefund")
        self.assertIn("func (s *StateDB) AddRefund", exc.splitlines()[0])
        self.assertGreater(start, 0)

    def test_known_line_is_authoritative(self):
        # even a bogus fn name resolves when the enumerator supplies the line
        exc, start, _ = pfmbg.read_file_excerpt(str(self.go), "ZZZnotreal", known_line=11)
        self.assertEqual(start, 11)
        self.assertIn("SubRefund", exc)

    def test_path_line_anchor_without_split(self):
        # a 'path:line' anchor passed straight to read_file_excerpt still works
        exc, start, _ = pfmbg.read_file_excerpt(str(self.go) + ":11", "whatever")
        self.assertEqual(start, 11)
        self.assertTrue(exc)

    def test_solidity_signatured_qualified_name(self):
        exc, start, _ = pfmbg.read_file_excerpt(
            str(self.sol), "EVMCompatibilityTester.callAnotherContract(address,bytes)")
        self.assertIn("function callAnotherContract", exc.splitlines()[0])
        self.assertGreater(start, 0)

    def test_missing_fn_returns_empty(self):
        # never-false-pass: a genuinely absent fn must NOT fabricate an excerpt
        exc, start, end = pfmbg.read_file_excerpt(str(self.go), "totallyAbsentFunction")
        self.assertEqual((exc, start, end), ("", 0, 0))

    def test_missing_file_returns_empty(self):
        exc, start, end = pfmbg.read_file_excerpt(str(self.go) + ".nope", "SubRefund")
        self.assertEqual((exc, start, end), ("", 0, 0))

    def test_prefix_name_not_falsely_matched(self):
        # searching 'Sub' must not match 'SubRefund' (opener guard)
        exc, start, end = pfmbg.read_file_excerpt(str(self.go), "Sub")
        self.assertEqual((exc, start, end), ("", 0, 0))


if __name__ == "__main__":
    unittest.main()
