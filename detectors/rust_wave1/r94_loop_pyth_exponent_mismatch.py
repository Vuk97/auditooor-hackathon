"""
r94_loop_pyth_exponent_mismatch.py

Flags Pyth consumers that read `price.price` but never read `price.expo`
to scale into the pool's fixed-decimal basis. Mixing different-expo
feeds leads to off-by-10^n pricing.

Class: pyth-exponent-mismatch (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_PYTH_PRICE_RE = re.compile(
    r"pyth::get_price|\.get_price_feed|price_feed\.price|"
    r"\bPriceUpdate\b|\.price\s*\(|\.get_price_no_older|pyth\.price|"
    r"pyth_\w+\.price|\w+_feed\.price|\.price\s+as\s+\w"
)
_EXPO_RE = re.compile(
    r"\.expo\b|price_expo|price\.expo|expo\s*=|expo_\w+|"
    r"scale_by_expo|adjust_for_expo|apply_exponent"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _PYTH_PRICE_RE.search(body_nc):
            continue
        if _EXPO_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads a Pyth price without reading / "
                f"scaling by `price.expo`. Different feeds have different "
                f"exponents — off-by-10^n pricing."
            ),
        })
    return hits
