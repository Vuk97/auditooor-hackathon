#!/usr/bin/env python3
"""
ast-engine.py — R74-C unified tree-sitter backbone for auditooor detectors.

A single AstEngine class that works across Rust, Go, Python, JS, Move, Cairo
(any language with a tree-sitter grammar). Exposes:

  1. Raw tree-sitter primitives (`engine.tree`, `engine.source`) for
     back-compat with the existing rust_wave1 detectors that take
     (tree, source, filepath).
  2. Language-neutral navigation helpers (`functions()`,
     `body_contains_regex()`, `is_public()`, etc.) for cross-language
     detectors that don't care about Rust-specific node types.
  3. Cross-language predicate registry
     (`predicate_missing_call`, `predicate_state_write_no_auth`,
     `predicate_paired_function_asymmetry`) backing the top-N
     cross-language DSL predicates.
  4. Non-throwing tree-sitter s-expression queries (`query_with_sexp()`)
     for structural Rust/Go/Move predicates when parser/query support exists.

Usage as library:
    from ast_engine import AstEngine
    engine = AstEngine("rust", source_bytes)
    engine.parse()
    for fn in engine.functions():
        if engine.is_public(fn) and engine.body_contains_regex(fn, "unwrap"):
            print(engine.text(fn), engine.line(fn))

Usage as CLI:
    python3 tools/ast-engine.py --info       # which grammars are installed
    python3 tools/ast-engine.py --lang go --file foo.go   # dump fn list
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import re
import sys
import warnings
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple


# ---- language registry -----------------------------------------------------

# (pypi_grammar_module, language_pack_key). The language-pack key is also
# the `lang` argument callers pass to AstEngine().
LANGS = {
    "rust":       ("tree_sitter_rust",       "rust"),
    "solidity":   ("tree_sitter_solidity",   "solidity"),
    "move":       ("tree_sitter_move",       "move"),
    "go":         ("tree_sitter_go",         "go"),
    "python":     ("tree_sitter_python",     "python"),
    "javascript": ("tree_sitter_javascript", "javascript"),
    "cairo":      ("tree_sitter_cairo",      "cairo"),
}

# Per-language node type names. Tree-sitter grammars don't standardise
# node names (Rust has `function_item`, Go has `function_declaration`,
# Python has `function_definition`), so we map them here.
# "fn" is the function-declaration node; "id" is the identifier field that
# holds its name; "body" is the block child. "param_list" is the formal-
# parameter list node. "call" is the call-expression node.
LANG_NODES = {
    "rust": {
        "fn": ("function_item",),
        "id": "identifier",
        "body": "block",
        "param_list": "parameters",
        "call": "call_expression",
        "method_field": "field_expression",
        "method_ident": "field_identifier",
        "visibility": "visibility_modifier",
        "attribute": "attribute_item",
        "return_type_field": "return_type",
    },
    "solidity": {
        "fn": ("function_definition",),
        "id": "identifier",
        "body": "function_body",
        "param_list": "parameters",
        "call": "call_expression",
        "method_field": "member_access",
        "method_ident": "identifier",
        "visibility": "visibility",
        "attribute": "modifier_invocation",
        "return_type_field": "return_type",
    },
    "move": {
        "fn": ("function_decl", "function_definition", "function_item"),
        "id": "identifier",
        "body": "block",
        "param_list": "parameters",
        "call": "call_expr",
        "method_field": "name_access_chain",
        "method_ident": "identifier",
        "visibility": "module_member_modifier",
        "attribute": None,
        "return_type_field": "type",
    },
    "go": {
        # Go has both `function_declaration` (package-level) and
        # `method_declaration` (receiver methods). Treat both as functions.
        "fn": ("function_declaration", "method_declaration"),
        "id": "identifier",
        "body": "block",
        "param_list": "parameter_list",
        "call": "call_expression",
        "method_field": "selector_expression",
        "method_ident": "field_identifier",
        "visibility": None,  # Go uses capitalisation
        "attribute": None,
        "return_type_field": "result",
    },
    "python": {
        "fn": ("function_definition",),
        "id": "identifier",
        "body": "block",
        "param_list": "parameters",
        "call": "call",
        "method_field": "attribute",
        "method_ident": "identifier",
        "visibility": None,
        "attribute": "decorator",
        "return_type_field": "return_type",
    },
    "javascript": {
        "fn": ("function_declaration", "method_definition",
               "arrow_function", "function_expression"),
        "id": "identifier",
        "body": "statement_block",
        "param_list": "formal_parameters",
        "call": "call_expression",
        "method_field": "member_expression",
        "method_ident": "property_identifier",
        "visibility": None,
        "attribute": None,
        "return_type_field": None,
    },
    "cairo": {
        "fn": ("function_item", "function_definition"),
        "id": "identifier",
        "body": "block",
        "param_list": "parameters",
        "call": "call_expression",
        "method_field": "field_expression",
        "method_ident": "field_identifier",
        "visibility": "visibility_modifier",
        "attribute": "attribute_item",
        "return_type_field": "return_type",
    },
}


# Small structural predicate query catalog for non-Solidity languages where
# name-based regexes tend to miss equivalent code shapes. Values are tuples so
# grammars with uncertain node names (notably Move variants) can degrade by
# trying each s-expression independently.
STRUCTURAL_SEXP_QUERIES = {
    "rust": {
        "assignment": (
            "(assignment_expression) @assignment",
        ),
        "subscript": (
            "(index_expression) @subscript",
        ),
        "call": (
            "(call_expression) @call",
        ),
        "assignment_to_subscript": (
            "(assignment_expression "
            "left: (index_expression) @subscript) @assignment",
        ),
        "assignment_to_subscript_call": (
            "(assignment_expression "
            "left: (index_expression) @subscript "
            "right: (call_expression) @call) @assignment",
        ),
    },
    "go": {
        "assignment": (
            "(assignment_statement) @assignment\n"
            "(short_var_declaration) @assignment",
        ),
        "subscript": (
            "(index_expression) @subscript",
        ),
        "call": (
            "(call_expression) @call",
        ),
        "assignment_to_subscript": (
            "(assignment_statement "
            "left: (expression_list (index_expression) @subscript)) "
            "@assignment",
        ),
        "assignment_to_subscript_call": (
            "(assignment_statement "
            "left: (expression_list (index_expression) @subscript) "
            "right: (expression_list (call_expression) @call)) "
            "@assignment",
        ),
    },
    "move": {
        "assignment": (
            "(assignment) @assignment",
            "(let_expr) @assignment",
            "(assignment_statement) @assignment",
            "(assignment_expression) @assignment",
            "(let_statement) @assignment",
        ),
        "subscript": (
            "(mem_access) @subscript",
            "(index_expression) @subscript",
            "(index_expr) @subscript",
            "(subscript_expression) @subscript",
        ),
        "call": (
            "(call_expr) @call",
            "(call_expression) @call",
            "(function_call_expression) @call",
            "(macro_call_expression) @call",
        ),
        "assignment_to_subscript": (
            "(assignment (mem_access) @subscript) @assignment",
            "(assignment_statement "
            "left: (index_expression) @subscript) @assignment",
            "(assignment_expression "
            "left: (index_expression) @subscript) @assignment",
            "(assignment_statement "
            "left: (subscript_expression) @subscript) @assignment",
        ),
        "assignment_to_subscript_call": (
            "(assignment "
            "(mem_access) @subscript "
            "(call_expr) @call) @assignment",
            "(assignment_statement "
            "left: (index_expression) @subscript "
            "right: (call_expression) @call) @assignment",
            "(assignment_expression "
            "left: (index_expression) @subscript "
            "right: (call_expression) @call) @assignment",
            "(assignment_statement "
            "left: (subscript_expression) @subscript "
            "right: (call_expression) @call) @assignment",
        ),
    },
}


class SexpQueryResult:
    """Non-throwing result for tree-sitter s-expression queries."""

    def __init__(
        self,
        lang: str,
        query: str,
        ok: bool,
        matches: Optional[List[Dict[str, Any]]] = None,
        captures: Optional[List[Dict[str, Any]]] = None,
        error: Optional[str] = None,
        degraded: bool = False,
    ):
        self.lang = lang
        self.query = query
        self.ok = ok
        self.matches = matches or []
        self.captures = captures or []
        self.error = error
        self.degraded = degraded

    def __bool__(self) -> bool:
        return self.ok and bool(self.matches or self.captures)

    def __len__(self) -> int:
        return self.hit_count

    def __iter__(self):
        return iter(self.matches if self.matches else self.captures)

    def __getitem__(self, key):
        if isinstance(key, str):
            return self.as_dict()[key]
        return (self.matches if self.matches else self.captures)[key]

    @property
    def hit_count(self) -> int:
        return len(self.matches) if self.matches else len(self.captures)

    def capture_texts(self, name: str) -> List[str]:
        return [c["text"] for c in self.captures if c.get("name") == name]

    def as_dict(self) -> Dict[str, Any]:
        def scrub_capture(capture: Dict[str, Any]) -> Dict[str, Any]:
            return {k: v for k, v in capture.items() if k != "node"}

        return {
            "ok": self.ok,
            "lang": self.lang,
            "query": self.query,
            "error": self.error,
            "degraded": self.degraded,
            "captures": [scrub_capture(c) for c in self.captures],
            "matches": [
                {
                    "pattern_index": m.get("pattern_index", -1),
                    "captures": [
                        scrub_capture(c) for c in m.get("captures", [])
                    ],
                }
                for m in self.matches
            ],
        }


class LangStatus:
    """Probe result for one language."""
    def __init__(self, lang, grammar_module, direct_ok, pack_ok, error=None):
        self.lang = lang
        self.grammar_module = grammar_module
        self.direct_ok = direct_ok
        self.pack_ok = pack_ok
        self.error = error

    @property
    def installed(self) -> bool:
        return self.direct_ok or self.pack_ok


def check_languages() -> List[LangStatus]:
    """Probe each language for availability via direct grammar + language-pack."""
    results = []
    pack_avail = importlib.util.find_spec("tree_sitter_language_pack") is not None
    for lang, (mod, pack_key) in LANGS.items():
        direct_ok = importlib.util.find_spec(mod) is not None
        pack_ok = False
        err = None
        if pack_avail:
            try:
                from tree_sitter_language_pack import get_parser
                get_parser(pack_key)
                pack_ok = True
            except Exception as e:
                err = str(e)[:80]
        if not direct_ok and not pack_ok and err is None:
            err = f"{mod} not installed and language-pack absent"
        results.append(LangStatus(lang, mod, direct_ok, pack_ok, err))
    return results


# ---- parser/query loading --------------------------------------------------

def _parser_for_language(language):
    """Build a Parser across py-tree-sitter constructor variants."""
    from tree_sitter import Parser

    try:
        return Parser(language)
    except TypeError:
        parser = Parser()
        try:
            parser.set_language(language)
        except AttributeError:
            parser.language = language
        return parser


def _language_from_direct_module(mod):
    """Return a tree_sitter.Language from a grammar module."""
    from tree_sitter import Language

    raw_language = mod.language()
    try:
        return Language(raw_language)
    except TypeError:
        # Older grammar wheels can already return a Language object.
        return raw_language


def _load_parser_and_language(lang: str):
    """Load parser and Language for `lang`, trying direct grammar first,
    then language-pack."""
    mod_name, pack_key = LANGS[lang]
    errors = []

    # Try direct grammar module (e.g. tree_sitter_rust)
    try:
        mod = importlib.import_module(mod_name)
        language = _language_from_direct_module(mod)
        return _parser_for_language(language), language
    except Exception as e:
        errors.append(f"direct {mod_name}: {e}")

    # Fall back to language-pack.
    try:
        from tree_sitter_language_pack import get_parser
        parser = get_parser(pack_key)
        language = getattr(parser, "language", None)
        if language is None:
            try:
                from tree_sitter_language_pack import get_language
                language = get_language(pack_key)
            except Exception:
                language = None
        return parser, language
    except Exception as e:
        errors.append(f"language-pack: {e}")

    raise RuntimeError(
        f"could not load tree-sitter parser for {lang}: "
        + " | ".join(errors)
    )

def _load_parser(lang: str):
    """Load a tree-sitter parser for `lang`, trying direct grammar first,
    then language-pack."""
    parser, _language = _load_parser_and_language(lang)
    return parser


def _parse_source_compat(parser, source: bytes):
    """Parse source across parser wrappers that accept bytes or str."""
    try:
        return parser.parse(source)
    except TypeError as exc:
        if not isinstance(source, (bytes, bytearray)):
            raise
        try:
            return parser.parse(bytes(source).decode("utf-8", errors="replace"))
        except TypeError:
            raise exc


def _compile_sexp_query(language, query_str: str):
    """Compile a tree-sitter query across API versions.

    The task asks for Language.query() support. Newer py-tree-sitter versions
    deprecate that method in favour of Query(language, sexp), so support both.
    """
    errors = []
    if hasattr(language, "query"):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                return language.query(query_str)
        except Exception as e:
            errors.append(f"Language.query: {e}")

    try:
        from tree_sitter import Query
        return Query(language, query_str)
    except Exception as e:
        errors.append(f"Query: {e}")

    raise RuntimeError("could not compile tree-sitter query: "
                       + " | ".join(errors))


def _run_compiled_query(query, root):
    """Run compiled query and return raw (matches, captures)."""
    cursor_errors = []
    try:
        from tree_sitter import QueryCursor
        try:
            cursor = QueryCursor(query)
            matches = cursor.matches(root) if hasattr(cursor, "matches") else None
            captures = (cursor.captures(root)
                        if hasattr(cursor, "captures") else None)
            return matches, captures
        except TypeError:
            cursor = QueryCursor()
            matches = (cursor.matches(query, root)
                       if hasattr(cursor, "matches") else None)
            captures = (cursor.captures(query, root)
                        if hasattr(cursor, "captures") else None)
            return matches, captures
        except Exception as e:
            cursor_errors.append(f"QueryCursor: {e}")
    except Exception as e:
        cursor_errors.append(f"QueryCursor import: {e}")

    # Older py-tree-sitter exposed execution on Query itself.
    try:
        matches = query.matches(root) if hasattr(query, "matches") else None
        captures = query.captures(root) if hasattr(query, "captures") else None
        return matches, captures
    except Exception as e:
        cursor_errors.append(f"Query methods: {e}")

    raise RuntimeError("could not run tree-sitter query: "
                       + " | ".join(cursor_errors))


def _node_capture_name(query, capture_id) -> str:
    try:
        return query.capture_name(capture_id)
    except Exception:
        return str(capture_id)


def _capture_items(query, raw_captures) -> List[Tuple[str, Any]]:
    """Normalise capture payloads across tree-sitter API versions."""
    items = []
    if raw_captures is None:
        return items
    if isinstance(raw_captures, dict):
        for name, nodes in raw_captures.items():
            if not isinstance(nodes, (list, tuple)):
                nodes = [nodes]
            for node in nodes:
                items.append((str(name), node))
        return items
    for capture in raw_captures:
        if hasattr(capture, "node") and hasattr(capture, "name"):
            items.append((str(capture.name), capture.node))
            continue
        if hasattr(capture, "node") and hasattr(capture, "index"):
            items.append((_node_capture_name(query, capture.index),
                          capture.node))
            continue
        if isinstance(capture, tuple) and len(capture) == 2:
            first, second = capture
            if isinstance(second, str):
                items.append((second, first))
            elif isinstance(first, str):
                items.append((first, second))
            elif isinstance(second, int):
                items.append((_node_capture_name(query, second), first))
            else:
                items.append((str(first), second))
    return items


def _capture_record(engine, name: str, node) -> Dict[str, Any]:
    return {
        "name": name,
        "node": node,
        "node_type": getattr(node, "type", ""),
        "text": engine.text(node),
        "line": engine.line(node),
        "col": engine.col(node),
        "start_byte": getattr(node, "start_byte", None),
        "end_byte": getattr(node, "end_byte", None),
    }


def _normalise_matches(engine, query, raw_matches) -> List[Dict[str, Any]]:
    matches = []
    if raw_matches is None:
        return matches
    for raw_match in raw_matches:
        pattern_index = -1
        raw_captures = None
        if isinstance(raw_match, tuple) and len(raw_match) == 2:
            pattern_index, raw_captures = raw_match
        else:
            pattern_index = getattr(raw_match, "pattern_index", -1)
            raw_captures = getattr(raw_match, "captures", None)
        captures = [
            _capture_record(engine, name, node)
            for name, node in _capture_items(query, raw_captures)
        ]
        matches.append({
            "pattern_index": int(pattern_index),
            "captures": captures,
        })
    return matches


def _flatten_match_captures(matches: Sequence[Dict[str, Any]]) \
        -> List[Dict[str, Any]]:
    captures = []
    for match in matches:
        captures.extend(match.get("captures", []))
    return captures


def _normalise_captures(engine, query, raw_captures) -> List[Dict[str, Any]]:
    return [
        _capture_record(engine, name, node)
        for name, node in _capture_items(query, raw_captures)
    ]


def query_with_sexp(lang: str, query_str: str, source: bytes) \
        -> SexpQueryResult:
    """Convenience API: parse `source` and run a tree-sitter s-expression.

    This is intentionally non-throwing so detector pipelines can degrade
    cleanly when a grammar, parser, or query API is unavailable.
    """
    try:
        engine = AstEngine(lang, source)
    except Exception as e:
        return SexpQueryResult(
            lang, query_str, ok=False, error=str(e), degraded=True
        )
    return engine.query_with_sexp(query_str)


# ---- AstEngine -------------------------------------------------------------

class AstEngine:
    """Language-agnostic façade over a tree-sitter parse tree.

    Back-compat note: detectors that want raw tree-sitter access can grab
    `engine.tree` and `engine.source` directly — the existing rust_wave1
    detectors rely on this.
    """

    def __init__(self, lang: str, source: bytes):
        if lang not in LANGS:
            raise ValueError(f"unsupported language: {lang!r} "
                             f"(known: {sorted(LANGS)})")
        self.lang = lang
        self.source = source if isinstance(source, (bytes, bytearray)) \
            else source.encode("utf-8")
        self._nodes = LANG_NODES.get(lang, LANG_NODES["rust"])
        self._parser = None
        self._language = None
        self.tree = None

    # ---- parse -----------------------------------------------------------
    def parse(self):
        self._parser, self._language = _load_parser_and_language(self.lang)
        self.tree = _parse_source_compat(self._parser, self.source)
        if self._language is None:
            self._language = getattr(self._parser, "language", None)
        return self.tree

    @property
    def root(self):
        if self.tree is None:
            self.parse()
        return self.tree.root_node

    @property
    def language(self):
        if self._language is None and self._parser is not None:
            self._language = getattr(self._parser, "language", None)
        return self._language

    # ---- fundamental helpers --------------------------------------------
    def text(self, node) -> str:
        return self.source[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace")

    def line(self, node) -> int:
        """1-based line number."""
        return node.start_point[0] + 1

    def col(self, node) -> int:
        return node.start_point[1]

    # ---- tree-sitter s-expression queries ------------------------------
    def query_with_sexp(self, query_str: str, node=None) -> SexpQueryResult:
        """Run a tree-sitter s-expression query against this engine.

        Returns SexpQueryResult instead of raising for missing grammars,
        unavailable Language/Query support, or invalid query syntax.
        """
        if not isinstance(query_str, str) or not query_str.strip():
            return SexpQueryResult(
                self.lang, str(query_str), ok=False,
                error="empty tree-sitter query", degraded=True
            )
        try:
            root = node if node is not None else self.root
        except Exception as e:
            return SexpQueryResult(
                self.lang, query_str, ok=False,
                error=f"parser unavailable: {e}", degraded=True
            )
        language = self.language
        if language is None:
            return SexpQueryResult(
                self.lang, query_str, ok=False,
                error="tree-sitter Language unavailable for parser",
                degraded=True,
            )
        try:
            query = _compile_sexp_query(language, query_str)
        except Exception as e:
            return SexpQueryResult(
                self.lang, query_str, ok=False,
                error=f"query unavailable: {e}", degraded=True
            )
        try:
            raw_matches, raw_captures = _run_compiled_query(query, root)
        except Exception as e:
            return SexpQueryResult(
                self.lang, query_str, ok=False,
                error=f"query execution failed: {e}", degraded=True
            )
        matches = _normalise_matches(self, query, raw_matches)
        captures = _flatten_match_captures(matches)
        if not captures:
            captures = _normalise_captures(self, query, raw_captures)
        return SexpQueryResult(
            self.lang, query_str, ok=True,
            matches=matches, captures=captures,
        )

    def query_structural(self, predicate: str, node=None) -> SexpQueryResult:
        """Run a built-in structural predicate (`assignment`, `call`, ...)."""
        queries = STRUCTURAL_SEXP_QUERIES.get(self.lang, {}).get(predicate)
        if not queries:
            return SexpQueryResult(
                self.lang, predicate, ok=False,
                error=f"unknown structural predicate: {predicate}",
                degraded=True,
            )
        all_matches = []
        all_captures = []
        errors = []
        for query_str in queries:
            result = self.query_with_sexp(query_str, node=node)
            if result.ok:
                all_matches.extend(result.matches)
                all_captures.extend(result.captures)
            else:
                errors.append(result.error or "unknown query error")
        if all_matches or all_captures or len(errors) < len(queries):
            return SexpQueryResult(
                self.lang, "\n".join(queries), ok=True,
                matches=all_matches, captures=all_captures,
                error=" | ".join(errors) if errors else None,
                degraded=bool(errors),
            )
        return SexpQueryResult(
            self.lang, "\n".join(queries), ok=False,
            error=" | ".join(errors), degraded=True,
        )

    def body_contains_sexp(self, fn, query_str: str) -> bool:
        body = self.fn_body(fn)
        if body is None:
            return False
        return bool(self.query_with_sexp(query_str, node=body))

    def body_contains_structural(self, fn, predicate: str) -> bool:
        body = self.fn_body(fn)
        if body is None:
            return False
        return bool(self.query_structural(predicate, node=body))

    def _walk(self, node):
        yield node
        for c in node.children:
            yield from self._walk(c)

    def _walk_no_nested_fn(self, node):
        """Walk but skip entering nested function definitions so a
        function's body is isolated from its inner closures/fns."""
        yield node
        fn_types = self._nodes["fn"]
        if node.type in fn_types or node.type in (
                "closure_expression", "arrow_function",
                "function_expression", "lambda"):
            # only skip descent for nested fns, not for the root fn itself
            pass
        for c in node.children:
            yield from self._walk_no_nested_fn_inner(c, fn_types)

    def _walk_no_nested_fn_inner(self, node, fn_types):
        yield node
        if node.type in fn_types or node.type in (
                "closure_expression", "arrow_function",
                "function_expression", "lambda"):
            return
        for c in node.children:
            yield from self._walk_no_nested_fn_inner(c, fn_types)

    # ---- function navigation --------------------------------------------
    def functions(self) -> Iterator:
        """Yield every function/method node in the tree."""
        fn_types = self._nodes["fn"]
        for n in self._walk(self.root):
            if n.type in fn_types:
                yield n

    def function_with_name_matching(self, regex: str) -> Iterator:
        """Yield functions whose name matches `regex`."""
        rx = re.compile(regex)
        for fn in self.functions():
            name = self.fn_name(fn)
            if name and rx.search(name):
                yield fn

    def fn_name(self, fn) -> str:
        """Return the function's declared name, or '?' if unknown."""
        # tree-sitter typically exposes the name as field "name"
        try:
            nm = fn.child_by_field_name("name")
            if nm is not None:
                return self.text(nm)
        except Exception:
            pass
        for c in fn.children:
            if c.type in ("identifier", "property_identifier",
                          "field_identifier"):
                return self.text(c)
        return "?"

    def fn_body(self, fn):
        body_type = self._nodes["body"]
        try:
            b = fn.child_by_field_name("body")
            if b is not None:
                return b
        except Exception:
            pass
        for c in fn.children:
            if c.type == body_type:
                return c
        return None

    def parameters(self, fn) -> List:
        """Return a list of formal parameter nodes."""
        pl_type = self._nodes["param_list"]
        try:
            pl = fn.child_by_field_name("parameters")
            if pl is None:
                for c in fn.children:
                    if c.type == pl_type:
                        pl = c
                        break
            if pl is None:
                return []
            return [c for c in pl.children
                    if c.type not in ("(", ")", ",", "self", "&", "mut")]
        except Exception:
            return []

    # ---- call-site navigation -------------------------------------------
    def call_sites(self, fn) -> Iterator:
        """Yield every call_expression inside a function body (not nested
        fn bodies)."""
        body = self.fn_body(fn)
        if body is None:
            return
        call_type = self._nodes["call"]
        for n in self._walk_no_nested_fn(body):
            if n.type == call_type:
                yield n

    def call_callee_text(self, call) -> str:
        """Return the textual form of the call's callee (e.g. 'foo.bar')."""
        try:
            callee = call.child_by_field_name("function")
            if callee is not None:
                return self.text(callee)
        except Exception:
            pass
        if call.children:
            return self.text(call.children[0])
        return ""

    # ---- cross-language predicates --------------------------------------
    def body_contains_regex(self, fn, rx: str) -> bool:
        """True if the function's body text matches `rx` (Python re)."""
        body = self.fn_body(fn)
        if body is None:
            return False
        try:
            return re.search(rx, self.text(body)) is not None
        except re.error:
            return False

    def body_contains_call_to(self, fn, callee_regex: str) -> bool:
        """True if any call inside the body has a callee matching regex."""
        try:
            rx = re.compile(callee_regex)
        except re.error:
            return False
        for call in self.call_sites(fn):
            if rx.search(self.call_callee_text(call)):
                return True
        return False

    def is_public(self, fn) -> bool:
        """Cross-language notion of 'public':
          - Rust: child visibility_modifier contains `pub`
          - Go: capitalised name (no explicit modifier)
          - Python: name doesn't start with `_`
          - JS: always True (modules don't restrict by default)
          - Move/Cairo: check for `public` keyword in preceding tokens
        """
        if self.lang == "rust":
            vis = self._nodes["visibility"]
            for c in fn.children:
                if c.type == vis and "pub" in self.text(c):
                    return True
            return False
        if self.lang == "go":
            name = self.fn_name(fn)
            return bool(name) and name[:1].isupper()
        if self.lang == "python":
            name = self.fn_name(fn)
            return bool(name) and not name.startswith("_")
        if self.lang == "javascript":
            return True
        if self.lang == "move":
            prev = fn.prev_named_sibling
            if prev is not None and re.search(r'\b(pub|public)\b', self.text(prev)):
                return True
            parent = getattr(fn, "parent", None)
            body = self.fn_body(fn)
            if parent is not None and getattr(parent, "type", None) == "declaration":
                header_start = parent.start_byte
                header_end = body.start_byte if body else fn.end_byte
                header = self.source[header_start:header_end].decode(
                    "utf-8", errors="replace")
                return bool(re.search(r'\b(pub|public)\b', header))
            return False
        if self.lang == "cairo":
            # Scan the full text of the fn for a leading `public` /
            # `pub` keyword before the body.
            body = self.fn_body(fn)
            prefix_end = body.start_byte if body else fn.end_byte
            header = self.source[fn.start_byte:prefix_end].decode(
                "utf-8", errors="replace")
            return bool(re.search(r'\b(pub|public)\b', header))
        return False

    def has_attribute(self, fn, attr_pattern: str) -> bool:
        """True if the fn is preceded by an attribute/annotation/decorator
        whose text matches `attr_pattern` (regex)."""
        try:
            rx = re.compile(attr_pattern)
        except re.error:
            return False
        attr_type = self._nodes["attribute"]
        if attr_type is None:
            return False
        prev = fn.prev_named_sibling
        while prev is not None and prev.type == attr_type:
            if rx.search(self.text(prev)):
                return True
            prev = prev.prev_named_sibling
        # Also: python decorators are often the fn's own children
        if self.lang == "python":
            for c in fn.children:
                if c.type == "decorator" and rx.search(self.text(c)):
                    return True
        return False

    def returns_type_matching(self, fn, ty: str) -> bool:
        """True if the return-type annotation text matches `ty` (regex)."""
        try:
            rx = re.compile(ty)
        except re.error:
            return False
        # Try field lookup first
        try:
            rt = fn.child_by_field_name("return_type")
            if rt is None:
                rt = fn.child_by_field_name("result")
            if rt is not None:
                return rx.search(self.text(rt)) is not None
        except Exception:
            pass
        return False

    # ---- cross-language PREDICATE registry ------------------------------
    # Named `predicate_*` per R74-C spec. Each returns bool.

    def predicate_structural_match(self, fn, predicate: str) -> bool:
        """True if the fn body matches a built-in structural s-expression
        predicate such as `assignment_to_subscript_call`."""
        return self.body_contains_structural(fn, predicate)

    def predicate_missing_call(self, fn, required_call: str) -> bool:
        """True if the fn body does NOT contain any call matching
        `required_call` regex. Matches wave9-style 'missing required
        authorisation/effect' class across languages."""
        return not self.body_contains_call_to(fn, required_call)

    def predicate_state_write_no_auth(self, fn, write_pattern: str,
                                      auth_pattern: str) -> bool:
        """True if the fn body contains a call matching `write_pattern`
        but not a call matching `auth_pattern`. Encodes the
        'missing require_auth on mutation' class in a language-neutral
        way (caller supplies the patterns)."""
        has_write = self.body_contains_call_to(fn, write_pattern)
        if not has_write:
            return False
        has_auth = self.body_contains_call_to(fn, auth_pattern)
        return not has_auth

    def predicate_paired_function_asymmetry(
        self, fn1_regex: str, fn2_regex: str, write_pattern: str
    ) -> bool:
        """True if this engine's tree has TWO functions matching
        `fn1_regex` / `fn2_regex` that touch different sets of write
        targets (matched by `write_pattern` at call-site argument level).
        Purely a heuristic for mirror/paired-fn divergence across langs."""
        try:
            rx1 = re.compile(fn1_regex)
            rx2 = re.compile(fn2_regex)
        except re.error:
            return False
        fn1_writes = set()
        fn2_writes = set()
        fn1_present = fn2_present = False
        for fn in self.functions():
            name = self.fn_name(fn)
            if rx1.search(name):
                fn1_present = True
                for call in self.call_sites(fn):
                    txt = self.call_callee_text(call)
                    if re.search(write_pattern, txt):
                        fn1_writes.add(txt)
            if rx2.search(name):
                fn2_present = True
                for call in self.call_sites(fn):
                    txt = self.call_callee_text(call)
                    if re.search(write_pattern, txt):
                        fn2_writes.add(txt)
        if not (fn1_present and fn2_present):
            return False
        if not fn1_writes and not fn2_writes:
            return False
        return fn1_writes != fn2_writes


# ---- CLI -------------------------------------------------------------------

def _print_info():
    print("ast-engine.py — language availability")
    print(f"{'lang':<12}{'grammar module':<26}{'direct':<8}"
          f"{'via pack':<10}{'status'}")
    print("-" * 72)
    statuses = check_languages()
    for st in statuses:
        status = "OK" if st.installed else f"MISSING ({st.error or 'n/a'})"
        print(f"{st.lang:<12}{st.grammar_module:<26}"
              f"{'yes' if st.direct_ok else 'no':<8}"
              f"{'yes' if st.pack_ok else 'no':<10}{status}")
    installed = [s.lang for s in statuses if s.installed]
    missing = [s.lang for s in statuses if not s.installed]
    print()
    print(f"Installed ({len(installed)}): {', '.join(installed) or '(none)'}")
    if missing:
        print(f"Missing   ({len(missing)}): {', '.join(missing)}")
        print("  Hint: pip install --user --break-system-packages "
              "tree_sitter_language_pack")


def _dump_functions(lang: str, path: Path):
    src = path.read_bytes()
    engine = AstEngine(lang, src)
    engine.parse()
    print(f"[ok] parsed {path} as {lang}")
    for fn in engine.functions():
        name = engine.fn_name(fn)
        line = engine.line(fn)
        pub = "pub" if engine.is_public(fn) else "   "
        print(f"  L{line:<5} {pub}  {name}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--info", action="store_true",
                    help="List installed tree-sitter grammars and exit.")
    ap.add_argument("--lang", help="Language key (rust, go, python, ...).")
    ap.add_argument("--file", type=Path,
                    help="Source file to dump functions for.")
    args = ap.parse_args()

    if args.info or (not args.lang and not args.file):
        _print_info()
        return 0

    if args.lang and args.file:
        _dump_functions(args.lang, args.file)
        return 0

    ap.error("need both --lang and --file, or --info")


if __name__ == "__main__":
    sys.exit(main() or 0)
