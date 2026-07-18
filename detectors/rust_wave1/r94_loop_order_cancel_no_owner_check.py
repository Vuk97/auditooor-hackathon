"""
r94_loop_order_cancel_no_owner_check.py

Flags cancel_order / close_order fns that reference the order
by id (order_id / short_order_id / bid_id) but DON'T verify that
`caller == order.owner`.

Source: Solodit #34172 (C4 DittoETH LibSRUtil).
Class: order-cancel-no-owner-check (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(cancel_order|close_order|cancel_short|cancel_bid|remove_order)")
_LOOKS_UP_ORDER_RE = re.compile(
    fr"(orders|short_orders|bids|asks)\s*\[\s*{IDENT}(order_id|short_order_id|bid_id|ask_id)[^\]]*\]|"
    fr"orders\s*\.\s*get\s*\(\s*&?\s*{IDENT}(order_id|short_order_id)"
)
_OWNER_CHECK_RE = re.compile(
    fr"(caller\s*==\s*{IDENT}order\.owner|"
    fr"require\s*\(\s*{IDENT}order\.owner\s*==\s*{IDENT}caller|"
    fr"msg\.sender\s*==\s*{IDENT}order\.owner|"
    fr"env\.invoker\s*\(\s*\)\s*==\s*{IDENT}order\.owner|"
    fr"assert[!_]?eq\s*\(\s*caller\s*,\s*{IDENT}order\.owner)"
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
        if not _LOOKS_UP_ORDER_RE.search(body_nc):
            continue
        if _OWNER_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` references an order by id but "
                f"doesn't verify caller owns it — attacker cancels "
                f"arbitrary orders (order-cancel-no-owner-check). "
                f"See Solodit #34172 (DittoETH)."
            ),
        })
    return hits
