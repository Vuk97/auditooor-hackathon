"""Focused tests for tools/ast-engine.py tree-sitter s-expression support."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE.parent
AST_ENGINE_PATH = TOOLS_DIR / "ast-engine.py"


def _load_ast_engine():
    spec = importlib.util.spec_from_file_location(
        "ast_engine", AST_ENGINE_PATH
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ast_engine"] = mod
    spec.loader.exec_module(mod)
    return mod


AST = _load_ast_engine()

RUST_FIXTURE = b"fn f(){ items[key] = call(arg); let x = arr[i]; }"
GO_FIXTURE = (
    b"package p\n"
    b"func f(){ items[key] = call(arg); x := arr[i]; }"
)
MOVE_FIXTURE = (
    b"module audit::m { "
    b"fun callme(y: u64): u64 { y } "
    b"public fun f(v: vector<u64>, i: u64, y: u64) { "
    b"let x = v[i]; v[i] = callme(y); } }"
)
MOVE_NON_CALL_RHS_FIXTURE = (
    b"module audit::m { "
    b"public fun f(v: vector<u64>, i: u64, y: u64) { "
    b"v[i] = (y); } }"
)


def _installed(lang: str) -> bool:
    return any(st.lang == lang and st.installed for st in AST.check_languages())


@unittest.skipUnless(_installed("rust"), "tree-sitter Rust grammar missing")
class RustSexpQueryTests(unittest.TestCase):
    def test_query_with_sexp_matches_assignment_subscript_call(self):
        query = (
            "(assignment_expression "
            "left: (index_expression) @subscript "
            "right: (call_expression) @call) @assignment"
        )
        result = AST.query_with_sexp("rust", query, RUST_FIXTURE)

        self.assertTrue(result.ok, result.error)
        self.assertEqual(
            result.capture_texts("assignment"),
            ["items[key] = call(arg)"],
        )
        self.assertEqual(result.capture_texts("subscript"), ["items[key]"])
        self.assertEqual(result.capture_texts("call"), ["call(arg)"])

    def test_builtin_structural_predicates_match_fixture_shapes(self):
        engine = AST.AstEngine("rust", RUST_FIXTURE)
        engine.parse()
        fn = next(engine.functions())
        body = engine.fn_body(fn)

        assignments = engine.query_structural("assignment", node=body)
        subscripts = engine.query_structural("subscript", node=body)
        calls = engine.query_structural("call", node=body)

        self.assertTrue(assignments.ok, assignments.error)
        self.assertIn("items[key] = call(arg)",
                      assignments.capture_texts("assignment"))
        self.assertTrue(subscripts.ok, subscripts.error)
        self.assertGreaterEqual(len(subscripts.capture_texts("subscript")), 2)
        self.assertTrue(calls.ok, calls.error)
        self.assertEqual(calls.capture_texts("call"), ["call(arg)"])
        self.assertTrue(
            engine.predicate_structural_match(
                fn, "assignment_to_subscript_call"
            )
        )

    def test_query_degrades_when_language_query_support_is_unavailable(self):
        engine = AST.AstEngine("rust", RUST_FIXTURE)
        engine.parse()
        engine._language = object()

        result = engine.query_with_sexp("(call_expression) @call")

        self.assertFalse(result.ok)
        self.assertTrue(result.degraded)
        self.assertIn("query unavailable", result.error)


@unittest.skipUnless(_installed("go"), "tree-sitter Go grammar missing")
class GoSexpQueryTests(unittest.TestCase):
    def test_query_with_sexp_matches_assignment_subscript_call(self):
        query = (
            "(assignment_statement "
            "left: (expression_list (index_expression) @subscript) "
            "right: (expression_list (call_expression) @call)) @assignment"
        )
        result = AST.query_with_sexp("go", query, GO_FIXTURE)

        self.assertTrue(result.ok, result.error)
        self.assertEqual(
            result.capture_texts("assignment"),
            ["items[key] = call(arg)"],
        )
        self.assertEqual(result.capture_texts("subscript"), ["items[key]"])
        self.assertEqual(result.capture_texts("call"), ["call(arg)"])

    def test_builtin_structural_predicates_match_fixture_shapes(self):
        engine = AST.AstEngine("go", GO_FIXTURE)
        engine.parse()
        fn = next(engine.functions())
        body = engine.fn_body(fn)

        assignments = engine.query_structural("assignment", node=body)
        subscripts = engine.query_structural("subscript", node=body)
        calls = engine.query_structural("call", node=body)

        self.assertTrue(assignments.ok, assignments.error)
        self.assertIn("items[key] = call(arg)",
                      assignments.capture_texts("assignment"))
        self.assertIn("x := arr[i]", assignments.capture_texts("assignment"))
        self.assertTrue(subscripts.ok, subscripts.error)
        self.assertEqual(
            subscripts.capture_texts("subscript"),
            ["items[key]", "arr[i]"],
        )
        self.assertTrue(calls.ok, calls.error)
        self.assertEqual(calls.capture_texts("call"), ["call(arg)"])
        self.assertTrue(
            engine.predicate_structural_match(
                fn, "assignment_to_subscript_call"
            )
        )


@unittest.skipUnless(_installed("move"), "tree-sitter Move grammar missing")
class MoveSexpQueryTests(unittest.TestCase):
    def test_query_with_sexp_matches_assignment_subscript(self):
        query = "(assignment (mem_access) @subscript) @assignment"
        result = AST.query_with_sexp("move", query, MOVE_FIXTURE)

        self.assertTrue(result.ok, result.error)
        self.assertEqual(
            result.capture_texts("assignment"),
            ["v[i] = callme(y)"],
        )
        self.assertEqual(result.capture_texts("subscript"), ["v[i]"])

    def test_builtin_structural_predicates_match_fixture_shapes(self):
        engine = AST.AstEngine("move", MOVE_FIXTURE)
        engine.parse()
        fn = next(engine.function_with_name_matching(r"^f$"))
        body = engine.fn_body(fn)

        assignments = engine.query_structural("assignment", node=body)
        subscripts = engine.query_structural("subscript", node=body)
        calls = engine.query_structural("call", node=body)

        self.assertTrue(assignments.ok, assignments.error)
        self.assertIn("let x = v[i]", assignments.capture_texts("assignment"))
        self.assertIn("v[i] = callme(y)", assignments.capture_texts("assignment"))
        self.assertTrue(subscripts.ok, subscripts.error)
        self.assertGreaterEqual(subscripts.capture_texts("subscript").count("v[i]"), 2)
        self.assertTrue(calls.ok, calls.error)
        self.assertEqual(calls.capture_texts("call"), ["callme(y)"])
        self.assertTrue(engine.is_public(fn))
        self.assertTrue(
            engine.predicate_structural_match(fn, "assignment_to_subscript")
        )
        self.assertTrue(
            engine.predicate_structural_match(
                fn, "assignment_to_subscript_call"
            )
        )

    def test_assignment_to_subscript_call_rejects_parenthesized_non_call_rhs(self):
        engine = AST.AstEngine("move", MOVE_NON_CALL_RHS_FIXTURE)
        engine.parse()
        fn = next(engine.function_with_name_matching(r"^f$"))

        self.assertTrue(
            engine.predicate_structural_match(fn, "assignment_to_subscript")
        )
        self.assertFalse(
            engine.predicate_structural_match(
                fn, "assignment_to_subscript_call"
            )
        )


class ParserCompatibilityTests(unittest.TestCase):
    def test_parse_source_compat_falls_back_to_text(self):
        calls = []

        class FakeParser:
            def parse(self, source):
                calls.append(type(source))
                if isinstance(source, (bytes, bytearray)):
                    raise TypeError("bytes unsupported")
                return "parsed-tree"

        tree = AST._parse_source_compat(FakeParser(), b"module 0x1::m {}")

        self.assertEqual(tree, "parsed-tree")
        self.assertEqual(calls, [bytes, str])


class GracefulDegradationTests(unittest.TestCase):
    def test_missing_move_parser_returns_degraded_result(self):
        if _installed("move"):
            self.skipTest("Move parser installed in this environment")

        result = AST.query_with_sexp(
            "move", "(call_expression) @call", b"module 0x1::m {}"
        )

        self.assertFalse(result.ok)
        self.assertTrue(result.degraded)
        self.assertIn("parser unavailable", result.error)


if __name__ == "__main__":
    unittest.main()
