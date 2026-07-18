"""
integer_overflow_unchecked_block.py

Flags production fns that use `.wrapping_add()`, `.wrapping_sub()`,
`.wrapping_mul()`, `.wrapping_div()`, or `.wrapping_neg()` on values that
are derived from user input — the Rust equivalent of Solidity `unchecked`.

Heuristic:
  1. fn body contains one of the wrapping methods.
  2. fn is NOT in a `#[cfg(test)]` block and NOT a util/fuzz helper
     (name starts with `test_` / `fuzz_`).
  3. The file path does not contain `test`, `bench`, or `fuzz`.

We fire ONCE per fn at the first wrapping call.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_WRAP_PATTERN = re.compile(
    r"\.wrapping_(add|sub|mul|div|neg|shl|shr)\s*\("
)


def run(tree, source: bytes, filepath: str):
    # Skip test/bench/fuzz files. Use explicit path segments so a dir
    # named `test_fixtures/` is NOT skipped (needed for self-tests).
    bad_segments = ("/tests/", "/bench/", "/fuzz/",
                    "/benches/", "fuzz_targets")
    if any(seg in filepath for seg in bad_segments):
        return []
    if filepath.endswith("/test.rs"):
        return []
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if name.startswith(("test_", "fuzz_", "bench_", "prop_")):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)
        if not _WRAP_PATTERN.search(body_text):
            continue
        # find first wrapping call node
        wrap_node = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if _WRAP_PATTERN.search(t):
                wrap_node = n
                break
        if wrap_node is None:
            continue
        line, col = line_col(wrap_node)
        hits.append({
            "severity": "med",
            "line": line,
            "col": col,
            "snippet": snippet_of(wrap_node, source),
            "message": (
                f"fn `{name}` uses `.wrapping_*()` in production code — "
                f"equivalent to Solidity `unchecked`, silently wraps on "
                f"overflow."
            ),
        })
    return hits
