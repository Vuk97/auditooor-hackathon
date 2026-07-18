"""
r94_loop_deposit_balance_delta_no_reentrancy_guard_erc777_inflate.py

Flags vault `_deposit` / `deposit` fns that measure
`balance_before` / `balance_after` around `transfer_from` then
mint shares proportional to the delta — but have no reentrancy
guard. ERC777 `tokensReceived` hook re-enters the deposit path
and double-counts the delta.

Source: Solodit #2497 (Code4rena Rubicon BathToken).
Class: deposit-balance-delta-no-reentrancy-guard-erc777-inflate (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(^_deposit$|^deposit$|mint_shares|join_vault|"
    r"supply|stake|add_liquidity|provide_liquidity)"
)
# Measures before/after balance AND mints shares.
_DELTA_AND_MINT_RE = re.compile(
    r"(?i)(balance_before[\s\S]{0,400}?balance_after[\s\S]{0,400}?(_mint|mint_shares|shares\s*\+=)|"
    r"balanceBefore[\s\S]{0,400}?balanceAfter[\s\S]{0,400}?(_mint|mintShares|shares\s*\+=)|"
    r"pre_balance[\s\S]{0,400}?post_balance[\s\S]{0,400}?(_mint|mint_shares))"
)
_GUARD_RE = re.compile(
    r"(?i)(non_reentrant|nonReentrant|reentrancy_guard|"
    r"ReentrancyGuard|mutex|_status\s*=\s*ENTERED|"
    r"lock_acquire|deposit_lock)"
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
        if not _DELTA_AND_MINT_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` measures balance_before/after "
                f"around a transfer and mints shares proportional to "
                f"the delta, but has no reentrancy guard — ERC777 "
                f"`tokensReceived` hook re-enters the deposit to "
                f"double-count the delta and mint extra shares "
                f"(deposit-balance-delta-no-reentrancy-guard-erc777-inflate). "
                f"See Solodit #2497 (Code4rena Rubicon BathToken)."
            ),
        })
    return hits
