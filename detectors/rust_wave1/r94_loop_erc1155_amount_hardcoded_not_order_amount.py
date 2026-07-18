"""
r94_loop_erc1155_amount_hardcoded_not_order_amount.py

Flags matching-policy fns that build an ERC-1155 order result tuple
with a literal `1` for the `amount` field instead of `order.amount`
— attacker lists N units, fills only 1, carrying the rest.

Source: Solodit #3803 (Blur Exchange StandardPolicyERC1155).
Class: erc1155-amount-hardcoded-not-order-amount (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(can_match_maker_ask|can_match|match_policy|build_order_result|can_match_maker_bid)")
_HARDCODED_ONE_RE = re.compile(
    r"\b(amount|qty|token_amount)\s*:\s*1\s*[,)}]|"
    r",\s*1\s*\)\s*;?\s*$|"
    r"return\s*\([^)]*,\s*1\s*\)",
    re.MULTILINE,
)
_ORDER_AMOUNT_RE = re.compile(
    r"(order|taker_order|maker_order|ask|bid)\.\s*(amount|qty|token_amount)"
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
        if not _HARDCODED_ONE_RE.search(body_nc):
            continue
        if _ORDER_AMOUNT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` returns hardcoded `amount = 1` for "
                f"an ERC-1155 match instead of `order.amount` — "
                f"attacker lists N units and matcher fills only 1 "
                f"(erc1155-amount-hardcoded-not-order-amount). "
                f"See Solodit #3803 (Blur)."
            ),
        })
    return hits
