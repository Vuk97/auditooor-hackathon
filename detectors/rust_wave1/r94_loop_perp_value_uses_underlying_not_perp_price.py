"""
r94_loop_perp_value_uses_underlying_not_perp_price.py

Flags perp-position value fns that compute value as
`size * underlying_price` (spot) — funding and skew aren't
accounted for, mark-to-market vs execution price diverge.

Source: Solodit #64516 (Cyfrin Deriverse).
Class: perp-value-uses-underlying-not-perp-price (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(position_value|compute_position_value|mark_to_market|get_position_value|perp_value)")
_USES_UNDERLYING_RE = re.compile(
    r"(underlying_price|underlying\.price|spot_price|oracle_underlying|index_price_underlying)"
)
_USES_PERP_PRICE_RE = re.compile(
    r"(perp_price|get_perp_price|mark_price|mark_to_market_price|"
    r"perp_index_price)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _USES_UNDERLYING_RE.search(body_nc):
            continue
        if _USES_PERP_PRICE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes perp position value using "
                f"underlying/spot price instead of perp mark price — "
                f"funding and skew aren't reflected, mark-to-market "
                f"diverges from execution (perp-value-uses-underlying-"
                f"not-perp-price). See Solodit #64516 (Deriverse)."
            ),
        })
    return hits
