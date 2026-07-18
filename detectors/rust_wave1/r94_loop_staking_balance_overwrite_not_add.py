"""
r94_loop_staking_balance_overwrite_not_add.py

Flags stake fns that write `staked_balance[user] = amount` (overwrite)
instead of `staked_balance[user] += amount` — second call erases
prior balance.

Source: Solodit #55486 (Pashov Coinflip).
Class: staking-balance-overwrite-not-add (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)^(stake|deposit_stake|add_stake|enter_stake)$")
_OVERWRITE_RE = re.compile(
    r"(staked_balance|stake_balance|\bstaked\b)\s*\[\s*\w+\s*\]\s*=\s*(amount|_amount|\w+)\s*;|"
    fr"self\.(staked_balance|staked)\s*=\s*{IDENT}amount\b"
)
_ADD_RE = re.compile(
    r"(staked_balance|stake_balance|\bstaked\b)\s*\[[^\]]*\]\s*\+=|"
    r"self\.(staked_balance|staked)\s*\+=|"
    r"existing_balance\s*\+\s*amount"
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
        if not _OVERWRITE_RE.search(body_nc):
            continue
        if _ADD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` writes stakedBalance = amount "
                f"(overwrite) instead of += — second call erases "
                f"prior balance (staking-balance-overwrite-not-add). "
                f"See Solodit #55486 (Coinflip)."
            ),
        })
    return hits
