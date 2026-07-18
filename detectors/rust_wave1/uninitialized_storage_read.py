"""
uninitialized_storage_read.py

Flags `.get(...).unwrap_or(<default>)` on storage keys where the <default>
is a non-zero sentinel that is NOT obviously a safe fallback, combined
with no `.has(...)` check in the body.

The narrow bug class: user calls a read fn, underlying key was never
written, so the fn silently returns a default/sentinel value that the
caller interprets as real data (e.g. returns `0` for price, `1e18` for
index, etc.).

To keep low noise, we flag ONLY when BOTH hold:
  1. Default is a numeric literal that is not `0`, `0i128`, `0u128`,
     `false`, `Vec::new(...)`, `Map::new(...)`, `BytesN::from_array(...)`,
     or `<Type>::default()`.
  2. fn name matches a reader-style pattern: starts with `get_`, `read_`,
     `query_`, `price_of`, `balance_of`, or `view_`.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_READER_PREFIXES = ("get_", "read_", "query_", "price_of", "balance_of",
                    "view_", "rate_of")

_SAFE_DEFAULTS_SUBSTR = (
    "Vec::new", "Map::new", "BytesN::from_array",
    "::default()", "Default::default",
    "None", "false",
)


def _default_literal_is_nonzero(default_text: str) -> bool:
    t = default_text.strip()
    if any(s in t for s in _SAFE_DEFAULTS_SUBSTR):
        return False
    # strip casts / underscores / suffixes: 0i128 → 0
    m = re.match(r"[-+]?\s*([0-9_]+)(i\d+|u\d+)?\s*$", t)
    if m:
        digits = m.group(1).replace("_", "")
        return int(digits) != 0
    # hex
    m = re.match(r"0x[0-9A-Fa-f_]+(i\d+|u\d+)?\s*$", t)
    if m:
        return int(t.replace("_", ""), 16) != 0
    # any expression with `+` or `*` or an ident like `INIT_INDEX` — treat
    # as sentinel → flag
    if re.match(r"[A-Z_][A-Z0-9_]+$", t):
        return True
    return False


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not any(name.startswith(p) for p in _READER_PREFIXES):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)
        # Must not .has(...) check
        if re.search(r"\.has\s*\(", body_text):
            continue
        # Find unwrap_or(<X>) with dangerous default
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            m = re.search(
                r"\.unwrap_or\s*\(\s*([^)]+?)\s*\)$", t, re.DOTALL
            )
            if not m:
                continue
            default = m.group(1)
            if not _default_literal_is_nonzero(default):
                continue
            # must be on a storage read
            if "storage()" not in t and ".get(" not in t:
                continue
            line, col = line_col(n)
            hits.append({
                "severity": "med",
                "line": line,
                "col": col,
                "snippet": snippet_of(n, source),
                "message": (
                    f"fn `{name}` returns `.unwrap_or({default.strip()})` on "
                    f"an uninitialized storage read — caller cannot "
                    f"distinguish a never-written key from a real value of "
                    f"`{default.strip()}`."
                ),
            })
    return hits
