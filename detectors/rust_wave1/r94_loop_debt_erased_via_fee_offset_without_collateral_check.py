"""
r94_loop_debt_erased_via_fee_offset_without_collateral_check.py

Flags FeeManager / fee-offset fns that decrement user debt by fee
pool amount without a collateralization / health-factor check —
user triggers fee accrual, wipes debt for free.

Source: Solodit #32086 (C4 Wise Lending FeeManager).
Class: debt-erased-via-fee-offset-without-collateral-check (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(offset_debt|fee_offset|apply_fee|distribute_fee|refund_fee_to_debt)")
_DEBT_DECREMENT_RE = re.compile(
    r"(user_debt|user_borrow|position\.debt|debt_of\s*\(|principal)\s*(-=|\s*=\s*\w+\s*-)"
)
_HEALTH_CHECK_RE = re.compile(
    r"(health_factor|check_health|require_healthy|is_solvent|assert_healthy|"
    r"collateral_ratio\s*>\s*MIN|collateralization_check|verify_collateral)"
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
        if not _DEBT_DECREMENT_RE.search(body_nc):
            continue
        if _HEALTH_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` decrements user debt via fee pool "
                f"offset without a collateralization / health check "
                f"— user times fee accrual, wipes debt for free "
                f"(debt-erased-via-fee-offset-without-collateral-"
                f"check). See Solodit #32086 (Wise Lending)."
            ),
        })
    return hits
