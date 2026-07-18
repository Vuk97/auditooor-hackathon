"""
unchecked_unwrap_in_public_fn.py

Flags `.unwrap()` and `.expect(...)` inside a `pub fn` that sits inside an
#[contractimpl] block. Such calls turn a malformed Option/Result into a
panic-based DoS vector on the contract's public surface.

Filters:
  - Skip functions in #[cfg(test)] / #[test] contexts.
  - Skip unwrap on string literals (`.to_string().unwrap()` pattern is rare).
"""

from __future__ import annotations

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of, in_test_cfg,
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            callee = None
            args = None
            for c in n.children:
                if c.type == "field_expression" and callee is None:
                    callee = c
                elif c.type == "arguments":
                    args = c
            if callee is None:
                continue
            method = None
            for c in callee.children:
                if c.type == "field_identifier":
                    method = text_of(c, source)
            if method not in ("unwrap", "expect"):
                continue
            # Check args — unwrap() should have 0 args, expect(..) has 1
            if method == "unwrap":
                # require no args between ( and )
                real_args = [c for c in args.children
                             if c.type not in ("(", ")", ",")]
                if real_args:
                    continue
            line, col = line_col(n)
            hits.append({
                "severity": "med",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": (f"`{method}()` inside pub fn `{name}` "
                            f"(#[contractimpl]) — panic-on-malformed-input "
                            f"DoS surface. Prefer `unwrap_or_else(|| "
                            f"panic_with_error!(...))`."),
            })
    return hits
