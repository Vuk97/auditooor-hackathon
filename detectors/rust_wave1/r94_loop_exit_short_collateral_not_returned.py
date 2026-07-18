"""
r94_loop_exit_short_collateral_not_returned.py

Flags `exit_short` / `close_short` / `settle_short` fns that pay
out `payout` / `proceeds` but DON'T also transfer the SR's locked
`collateral` back to the shorter — collateral stranded.

Source: Solodit #27476 (Codehawks DittoETH ExitShortFacet).
Class: exit-short-collateral-not-returned (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(exit_short|close_short|settle_short|close_position|unwind_short)")
_PAYOUT_TRANSFER_RE = re.compile(
    fr"(payout|proceeds|amount_out|settlement_amount)\s*[.,)].{{0,40}}(transfer|safe_transfer|\.send)"
    fr"|transfer\s*\(\s*{IDENT}(user|owner|shorter)\s*,\s*{IDENT}(payout|proceeds)"
)
_COLLATERAL_RETURN_RE = re.compile(
    fr"(transfer\s*\(\s*{IDENT}(user|owner|shorter)\s*,\s*{IDENT}collateral|"
    fr"return_collateral|refund_collateral|collateral\.transfer|"
    fr"collateral_to_owner|unlock_collateral)"
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
        if not _PAYOUT_TRANSFER_RE.search(body_nc):
            continue
        if _COLLATERAL_RETURN_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` transfers payout/proceeds but "
                f"doesn't also return the SR's locked collateral "
                f"to the shorter — collateral stranded (exit-"
                f"short-collateral-not-returned). See Solodit "
                f"#27476 (DittoETH ExitShortFacet)."
            ),
        })
    return hits
