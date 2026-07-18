"""
r94_loop_tax_refund_post_fee_amount.py

Flags tax/fee refund fns that compute refund from POST-fee transfer
amount instead of pre-fee input — refund double-subtracts fee.

Source: Solodit #31190 (Zap Protocol tax-refund bug).
Class: tax-refund-post-fee-amount (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(refund|rebate|tax_refund|fee_refund|reimburse)")
_POST_FEE_RE = re.compile(
    r"(amount_after_fee|amt_post_fee|net_amount|received_amount|transferred)\s*[\*/]|"
    r"(balanceOf|balance_of)\s*\([^)]*\)\s*-\s*(balance_before|prev_balance)|"
    fr"refund\s*=\s*{IDENT}after_fee"
)
_PRE_FEE_RE = re.compile(r"pre_fee_amount|input_amount|original_amount|gross_amount|amount_in\b")
_SAFE_RE = re.compile(r"pre_fee|gross|input_amount_raw")


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
        if not _POST_FEE_RE.search(body_nc):
            continue
        if _PRE_FEE_RE.search(body_nc) or _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes tax/fee refund from POST-fee "
                f"amount (amount_after_fee / balanceOf-diff) — refund "
                f"double-subtracts fee, user loses. See Solodit #31190 "
                f"(Zap Protocol)."
            ),
        })
    return hits
