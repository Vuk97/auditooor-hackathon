"""
r94_loop_zero_share_first_deposit.py

Flags deposit/mint/stake/withdraw fns that read a share_amount/amount
parameter, compute share-ratio math, but never guard against
`share_amount == 0` / `amount == 0`. The zero-value first-depositor
/ zero-share-withdraw flavor lets attackers manipulate the pool's
share-to-asset ratio.

Source: Solodit #53198 (OtterSec Walrus Contracts).
Class: zero-share-first-deposit (both).
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(
    r"(?i)^(deposit|mint|stake|withdraw|request_withdraw|redeem|"
    r"stake_\w+|unstake|request_withdraw_stake)$"
)

_SHARE_MATH_RE = re.compile(
    r"share_amount|total_shares|shares_to_(revert|mint|burn)|"
    r"\bshares\b.*?[*/]|[*/].*?\bshares\b|"
    r"\brate\s*=|ratio\s*="
)

_ZERO_GUARD_RE = re.compile(
    r"share_amount\s*(==|>|!=)\s*0|"
    r"require!?\s*\([^)]*\b(share_amount|shares|amount)\s*[>!]|"
    r"assert!?\s*\([^)]*\b(share_amount|shares|amount)\s*[>!]|"
    r"\b(amount|shares|share_amount)\s*(>|!=)\s*0|"
    r"if\s+\w*(share|amount)\w*\s*==\s*0\s*\{[^}]*?(return|panic|revert)"
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

        if not _SHARE_MATH_RE.search(body_nc):
            continue
        if _ZERO_GUARD_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` does share-ratio math on a caller-"
                f"supplied amount/share_amount without a zero-guard. "
                f"First-depositor / zero-share-withdraw manipulates the "
                f"share-to-asset ratio. See Solodit #53198 (Walrus)."
            ),
        })
    return hits
