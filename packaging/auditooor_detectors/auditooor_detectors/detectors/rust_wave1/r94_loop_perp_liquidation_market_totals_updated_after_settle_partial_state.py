"""
r94_loop_perp_liquidation_market_totals_updated_after_settle_partial_state.py

Flags perp-liquidation fns that call `settle_position` / `close_position`
FIRST and then mutate global market totals (open_interest, global_skew,
total_notional) AFTER — if settle reverts on stale price or oracle
issues, the partial state mutation leaves market totals off-by-position.

Source: Solodit #37986 (Codehawks Zaros).
Class: perp-liquidation-market-totals-updated-after-settle-partial-state (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(^liquidate$|liquidate_position|liquidatePosition|"
    r"execute_liquidation|process_liquidation|force_close)"
)
_BAD_ORDER_RE = re.compile(
    r"((settle_position|settlePosition|close_position|closePosition|settle_funding)"
    r"\s*\([\s\S]{0,400}?)"
    r"((open_interest|openInterest|global_skew|globalSkew|"
    r"total_notional|totalNotional|market_totals)\s*[-+]?=)"
)
_SAFE_RE = re.compile(
    r"(open_interest|openInterest|global_skew|globalSkew|"
    r"total_notional|totalNotional)\s*[-+]?=[\s\S]{0,400}?"
    r"(settle_position|closePosition|settle_funding)|"
    r"non_reentrant|checks_effects_interactions"
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
        if not _BAD_ORDER_RE.search(body_nc):
            continue
        if _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} updates market totals "
                f"(open_interest, skew, notional) AFTER settling the "
                f"position — if settle reverts on stale price / oracle "
                f"issues, partial state mutation leaves market totals "
                f"off-by-position "
                f"(perp-liquidation-market-totals-updated-after-settle-partial-state). "
                f"See Solodit #37986 (Codehawks Zaros)."
            ),
        })
    return hits
