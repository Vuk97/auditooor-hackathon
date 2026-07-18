"""
r94_loop_perp_underlying_px_from_orderbook_last_px.py

Flags perp `get_underlying_price` / `mark_to_market` / `liquidate`
fns that fall back to `last_px` from the spot order book when no
dedicated oracle feed is configured — attacker posts a small
crossing order to move last_px and trigger unfair liquidation.

Source: Solodit #64517 (Cyfrin Deriverse).
Class: perp-underlying-px-from-orderbook-last-px (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(get_underlying_price|mark_to_market|liquidate|compute_underlying_px|"
    r"perp_underlying_px|get_perp_underlying)"
)
_LAST_PX_ACCESS_RE = re.compile(
    r"\b(last_px|last_price|last_trade_price|orderbook\.last_px|"
    r"market\.last_px|spot_last_px|pair\.last_px)\b"
)
_ORACLE_PATH_RE = re.compile(
    r"(oracle_feed|oracle\.get|chainlink|mark_price_oracle|has_oracle\s*\(|"
    r"price_feed\.get|fresh_twap|twap_price)"
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
        if not _LAST_PX_ACCESS_RE.search(body_nc):
            continue
        if _ORACLE_PATH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads `last_px` from spot order "
                f"book as underlying price with no oracle fallback "
                f"— attacker posts a small crossing order to move "
                f"last_px and trigger unfair liquidation "
                f"(perp-underlying-px-from-orderbook-last-px). "
                f"See Solodit #64517 (Deriverse)."
            ),
        })
    return hits
