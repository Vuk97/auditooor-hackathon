"""
r94_loop_perp_post_liquidation_market_state_not_reset.py

Flags liquidate_position fns that clear the user's position but
don't decrement market-level aggregates (open_interest,
position_count, taker/maker imbalance) — subsequent ops revert or
produce wrong funding.

Source: Solodit #37986 (Codehawks Zaros).
Class: perp-post-liquidation-market-state-not-reset (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(liquidate_position|liquidate_perp|close_liquidated|settle_liquidation)")
_CLEARS_POSITION_RE = re.compile(
    r"(position\s*=\s*Position::default|\.remove\s*\(\s*&?position_id|"
    r"positions\.remove\s*\(|set_position_zero|clear_position)"
)
_DECREMENTS_AGGREGATES_RE = re.compile(
    r"(open_interest|total_long|total_short|position_count|"
    r"taker_imbalance|maker_imbalance|market\.total_size|aggregate_size)\s*[-=]="
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
        if not _CLEARS_POSITION_RE.search(body_nc):
            continue
        if _DECREMENTS_AGGREGATES_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` clears user's position on "
                f"liquidation but doesn't decrement market-level "
                f"aggregates (open_interest, position_count, "
                f"imbalance) — subsequent ops produce wrong funding "
                f"or revert (perp-post-liquidation-market-state-"
                f"not-reset). See Solodit #37986 (Zaros)."
            ),
        })
    return hits
