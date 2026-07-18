# <!-- r36-rebuttal: lane FIX-BODY-PACK-EXTRACTOR registered via agent-pathspec-register.py -->
"""Guard: language-agnostic function-body extractor (sol/go/rust brace-matching + abstract decl
+ runaway cap). Basis: body-carrying packs (optimism 2026-06-16 2-arm proof) are R76-clean
(0/10 hallucinated) + ~28x fewer tokens than whole-file reads."""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "function-source-extractor.py"


def _load():
    spec = importlib.util.spec_from_file_location("function_source_extractor", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["function_source_extractor"] = m
    spec.loader.exec_module(m)
    return m


class ExtractorTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_solidity_body(self):
        lines = [
            "contract C {",                                  # 1
            "    function f(uint x) public returns (uint) {",  # 2
            "        if (x > 0) { return x; }",              # 3
            "        return 0;",                             # 4
            "    }",                                         # 5
            "    uint y;",                                   # 6
        ]
        body, end = self.m.extract_body(lines, 2)
        self.assertIn("function f(uint x)", body)
        self.assertIn("return 0;", body)
        self.assertNotIn("uint y;", body)   # stops at the closing brace, not the next decl
        self.assertEqual(end, 5)

    def test_go_body(self):
        lines = [
            "package x",                                  # 1
            "func Foo(a int) int {",                      # 2
            "    if a > 0 { return a }",                  # 3
            "    return 0",                               # 4
            "}",                                          # 5
        ]
        body, end = self.m.extract_body(lines, 2)
        self.assertIn("func Foo(a int)", body)
        self.assertIn("return 0", body)
        self.assertEqual(end, 5)

    def test_rust_body(self):
        lines = [
            "impl T {",                                   # 1
            "    pub fn bar(&self) -> u64 {",             # 2
            "        let x = if true { 1 } else { 2 };",  # 3
            "        x",                                  # 4
            "    }",                                      # 5
            "}",                                          # 6
        ]
        body, end = self.m.extract_body(lines, 2)
        self.assertIn("pub fn bar", body)
        self.assertIn("let x =", body)
        self.assertEqual(end, 5)

    def test_abstract_decl_no_body(self):
        # interface/abstract: signature ends in ';' before any '{'
        lines = ["interface I {", "    function g(uint x) external returns (uint);", "}"]
        body, end = self.m.extract_body(lines, 2)
        self.assertIn("function g(uint x) external returns (uint);", body)
        self.assertEqual(end, 2)   # single signature line only

    def test_runaway_cap(self):
        # an unbalanced open brace must not run past max_lines
        lines = ["func Bad() {"] + ["    work()" for _ in range(50)]
        body, end = self.m.extract_body(lines, 1, max_lines=10)
        self.assertLessEqual(len(body.splitlines()), 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
