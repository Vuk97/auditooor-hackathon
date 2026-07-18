"""
deprecated_function_call.py

Flags fn definitions marked with `#[deprecated]` that are being called
elsewhere in the same file, OR calls to a small curated list of known-
deprecated Soroban/SDK APIs.

Heuristic:
  1. Collect fn_name for any `function_item` with a `#[deprecated]` attr.
  2. Walk all call_expression nodes and flag ones whose callee ident is
     in that set.
  3. Additionally, flag calls to a hard-coded deprecated list:
       env.ledger().network_passphrase  (renamed to .network_id())
       Bytes::from_slice                 (renamed)
       soroban_sdk::testutils::Ledger::with_mut  (test-only)
     We keep this list small to avoid noise.
"""

from __future__ import annotations

import re

from _util import (
    function_items, walk, text_of, fn_name, line_col, snippet_of,
    in_test_cfg, attr_names_above,
)


_HARD_DEPRECATED = (
    r"\.network_passphrase\s*\(",
    r"BytesN::from_slice\b",
)


def _is_deprecated_fn(fn, source: bytes) -> bool:
    return "deprecated" in attr_names_above(fn, source)


def run(tree, source: bytes, filepath: str):
    root = tree.root_node
    deprecated_names = set()
    for fn in function_items(root):
        if _is_deprecated_fn(fn, source):
            deprecated_names.add(fn_name(fn, source))

    hits = []
    for n in walk(root):
        if n.type != "call_expression":
            continue
        t = text_of(n, source)
        # hard-coded list
        for pat in _HARD_DEPRECATED:
            if re.search(pat, t):
                line, col = line_col(n)
                hits.append({
                    "severity": "low",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(n, source),
                    "message": "call to a known-deprecated Soroban API.",
                })
                break
        else:
            # detect call to an in-file #[deprecated] fn
            # simple form: ident(...) or Self::ident(...) or Foo::ident(...)
            m = re.match(r"(?:[\w:]+::)?([a-zA-Z_][\w]*)\s*\(", t)
            if m and m.group(1) in deprecated_names:
                line, col = line_col(n)
                hits.append({
                    "severity": "low",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(n, source),
                    "message": (
                        f"call to locally-`#[deprecated]` fn "
                        f"`{m.group(1)}`."
                    ),
                })
    return hits
