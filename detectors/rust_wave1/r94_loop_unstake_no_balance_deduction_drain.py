"""
r94_loop_unstake_no_balance_deduction_drain.py

Flags unstake / withdraw_stake fns that call token.transfer(user, amt)
WITHOUT decrementing `staked_balance` — user calls repeatedly and
drains the contract.

Source: Solodit #62035 (Quantstamp Sapien).
Class: unstake-no-balance-deduction-drain (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(unstake|withdraw_stake|claim_stake|exit_stake|redeem_stake)")
_TRANSFER_OUT_RE = re.compile(
    r"(token\.transfer|safe_transfer|_transfer\s*\()"
)
_BALANCE_DECREMENT_RE = re.compile(
    r"(staked_balance|stake_balance|\bstaked\b|\bbalances\b)\s*\[[^\]]*\]\s*-=|"
    r"self\.(staked_balance|staked)\s*-=|"
    r"\.insert\s*\(\s*&?\w+\s*,\s*\w+\s*-\s*amount"
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
        if not _TRANSFER_OUT_RE.search(body_nc):
            continue
        if _BALANCE_DECREMENT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` transfers tokens out without "
                f"decrementing stakedBalance — user calls repeatedly "
                f"and drains the contract (unstake-no-balance-"
                f"deduction-drain). See Solodit #62035 (Sapien)."
            ),
        })
    return hits
