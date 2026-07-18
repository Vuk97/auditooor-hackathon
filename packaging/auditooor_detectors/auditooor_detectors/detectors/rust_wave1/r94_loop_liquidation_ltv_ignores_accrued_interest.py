"""
r94_loop_liquidation_ltv_ignores_accrued_interest.py

Flags liquidate fns that gate on an LTV check using
`position.amount / position.size` (or similar) where `size` is the
principal — without adding accrued interest — loan stays "healthy"
as interest grows.

Source: Solodit #33178 (Code4rena Lavarage).
Class: liquidation-ltv-ignores-accrued-interest (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(liquidate|check_liquidatable|is_liquidatable|health_check)")
_LTV_CHECK_RE = re.compile(
    r"(position\.amount|collateral|position_amount|pos_amount)\s*\*\s*1000\s*/\s*(position\.size|position_size|principal|borrow_amount|pos_size)\s*[<>]=?"
)
_INTEREST_IN_CHECK_RE = re.compile(
    r"(debt_with_interest|accrued_interest|total_owed|interest_accrued|"
    r"position\.total_debt|principal\s*\+\s*interest|add_interest)"
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
        if not _LTV_CHECK_RE.search(body_nc):
            continue
        if _INTEREST_IN_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` performs LTV check using principal "
                f"(position.size) without adding accrued interest — "
                f"loan stays healthy as interest grows, bad debt "
                f"(liquidation-ltv-ignores-accrued-interest). See "
                f"Solodit #33178 (Lavarage)."
            ),
        })
    return hits
