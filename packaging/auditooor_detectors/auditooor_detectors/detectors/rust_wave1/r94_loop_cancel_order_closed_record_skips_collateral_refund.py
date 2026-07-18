"""
r94_loop_cancel_order_closed_record_skips_collateral_refund.py

Flags cancel_order / close_order fns that branch on
`status == Closed` (or `Completed`/`Matched`) and DELETE the record
without calling a collateral-refund / reconciliation helper.

Source: Solodit #34173 (C4 DittoETH cancelOrder on closed SR).
Class: cancel-order-closed-record-skips-collateral-refund (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(cancel_order|close_order|cancel_short|remove_order)")
_CLOSED_BRANCH_RE = re.compile(
    fr"(status\s*==\s*(SR::Closed|Status::Closed|OrderStatus::Closed|OrderStatus::Matched|Closed|Matched)|"
    fr"if\s+{IDENT}\.\s*(status|state)\s*==\s*{IDENT}(Closed|Matched|Completed))"
)
_DELETE_RE = re.compile(
    fr"(delete\s+{IDENT}(orders|record)|self\.orders\s*\.\s*remove|"
    fr"\.remove\s*\(\s*&?\s*{IDENT}(order_id|record_id|nft_id)|"
    fr"memset_default\s*\(\s*record)"
)
_REFUND_RE = re.compile(
    r"(refund_collateral|return_collateral|reconcile_collateral|"
    r"release_collateral|transfer_back_collateral|collateral\.transfer)"
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
        if not _CLOSED_BRANCH_RE.search(body_nc):
            continue
        if not _DELETE_RE.search(body_nc):
            continue
        if _REFUND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` deletes a closed/matched order "
                f"record without calling a collateral-refund helper "
                f"— attacker gets free debt token (cancel-order-"
                f"closed-record-skips-collateral-refund). See "
                f"Solodit #34173 (DittoETH)."
            ),
        })
    return hits
