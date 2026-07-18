"""
r94_loop_update_price_fee_unvalidated.py

Flags `update_price_feeds` / `update_oracle` fns that call the oracle's
fee-charging update method without verifying that the caller's
`msg_amount()` / `msg.value` covers the fee.

Source: Solodit #50586 (Halborn Swaylend).
Class: update-price-fee-unvalidated (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment, IDENT, CALL,
)

_FN_NAME_RE = re.compile(r"(?i)(update_price_feeds|update_oracle|push_price|refresh_oracle)")
_UPDATE_CALL_RE = re.compile(
    fr"update_price_feeds\s*\(|updatePriceFeeds\s*\(|\.update\s*\(\s*{IDENT}update_fee|"
    fr"pyth\.update_price_feeds|pyth\.update"
)
_FEE_VALIDATION_RE = re.compile(
    fr"require!?\s*\([^)]*(msg_amount|msg\.value)\s*(>=|==)\s*{IDENT}update_fee|"
    fr"assert!?\s*\([^)]*(msg_amount|msg\.value)\s*(>=|==)\s*{IDENT}update_fee|"
    fr"if\s+(msg_amount|msg\.value)\s*<\s*update_fee"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _UPDATE_CALL_RE.search(body_nc):
            continue
        if _FEE_VALIDATION_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls the oracle's fee-charging update "
                f"method without asserting `msg_amount >= update_fee`. "
                f"Market's own balance drains to cover the oracle fee. "
                f"See Solodit #50586 (Swaylend)."
            ),
        })
    return hits
