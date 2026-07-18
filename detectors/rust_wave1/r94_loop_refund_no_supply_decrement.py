"""
r94_loop_refund_no_supply_decrement.py

Flags refund/redeem/withdraw fns that set a user's claim-flag / debit a
user balance but forget to decrement the matching aggregate supply
counter (claimed_supply, total_claimed, total_allocated).

Source: Solodit #55454 (Pashov / DesciLaunchpad).
Rust side of `paired-refund-accounting` canonical class.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)^(withdraw_?tokens|refund|redeem|reclaim|unstake|withdraw|claim_?back|"
    r"emergency_?withdraw)$"
)

_USER_DEBIT_RE = re.compile(
    # Direct assignment: `has_claimed[user] = true;`, `user_shares[u] = 0;`
    r"(\bclaimed\b|has_claimed|claim_status|user_claim|user_shares|"
    r"user_balance|staked_amount).*?=\s*(true|false|0u|\d)|"
    r"(\bbalances\b|\buser_shares\b|\bstaked_amount\b).*?-=\s*\w|"
    # Setter helper: `set_has_claimed(…, true)`, `set_user_shares(…, 0)`
    r"(set|update|clear|zero)_(has_claimed|user_shares|user_balance|"
    r"staked_amount|claim|claimed)\s*\(|"
    # Self::set_user_*(…)
    r"Self::(set|update|clear)_\w*(claimed|user_shares|user_balance|"
    r"staked_amount)\w*\s*\(",
    re.MULTILINE | re.DOTALL,
)

_AGG_DECREMENT_RE = re.compile(
    r"(claimed_supply|total_claimed|total_allocated|total_staked|"
    r"total_supply|total_deposits|total_locked)\s*[-+*/]=\s*|"
    r"\.(decrement|decrease)\s*\(\s*(claimed_supply|total_claimed|total_allocated)",
    re.MULTILINE,
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

        if not _USER_DEBIT_RE.search(body_nc):
            continue
        if _AGG_DECREMENT_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` sets a user claim-flag / debits user state "
                f"but does not decrement the aggregate supply counter "
                f"(claimed_supply / total_claimed / …). Paired state-write "
                f"asymmetry — subsequent allocations read stale aggregates. "
                f"See Solodit #55454 (DesciLaunchpad)."
            ),
        })
    return hits
