"""
r94_loop_nav_uses_spot_not_perp_mark.py

Flags NAV / total_value / account_value fns that mark perp positions
to spot price (`oracle_price`, `spot_price`) instead of using
`mark_price` / `perp_mark_price` — NAV drifts from true liquidation
value.

Source: Solodit #64772 (Quantstamp Dipcoin Vault).
Class: nav-uses-spot-not-perp-mark (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(calculate_nav|compute_nav|total_value|account_value|vault_value|net_asset_value)")
_USES_PERP_POSITION_RE = re.compile(
    r"(perp_position|open_position|perp_size|perp_balance|position\.size|open_interest)"
)
_SPOT_PRICING_RE = re.compile(
    r"(oracle_price|spot_price|underlying_price|price_feed\.get|oracle\.get_price)\s*\("
)
_MARK_PRICING_RE = re.compile(
    r"(mark_price|perp_mark_price|get_mark_price|mark_price_oracle|index_price|perp_index)"
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
        if not _USES_PERP_POSITION_RE.search(body_nc):
            continue
        if not _SPOT_PRICING_RE.search(body_nc):
            continue
        if _MARK_PRICING_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` marks perp position to spot / "
                f"oracle / underlying price instead of perp mark "
                f"price — NAV drifts from true liquidation value "
                f"(nav-uses-spot-not-perp-mark). See Solodit #64772 "
                f"(Dipcoin Vault)."
            ),
        })
    return hits
