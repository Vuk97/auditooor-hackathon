"""
r94_loop_rebase_race_unstake.py

Flags unstake/withdraw fns that use `balance_of[user]` directly
without first calling the lazy-balance-refresh (`_calculate_values` /
`_apply_rebase` / `_settle_balance`).

Source: Solodit #63206 (Sherlock Yield Basis).
Class: rebase-race-unstake (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(unstake|withdraw|exit|redeem)")

_BALANCE_READ_RE = re.compile(
    r"balance_of\s*[\[\.\(]|balances?\s*[\[\.\(]|"
    r"balanceOf\s*\("
)

_SETTLE_RE = re.compile(
    r"_calculate_values|_apply_rebase|_settle_balance|_checkpoint_user|"
    r"apply_rebase|refresh_balance|_update_user"
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
        if not _BALANCE_READ_RE.search(body_nc):
            continue
        if _SETTLE_RE.search(body_nc):
            continue
        # Need rebase-style context (token with rebasing elsewhere in source)
        src_str = source.decode("utf8", errors="replace")
        if "rebase" not in src_str.lower() and "lt_contract" not in src_str.lower():
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads balance_of[user] for unstake/"
                f"withdraw in a rebase-enabled token context without "
                f"first calling the lazy-balance-refresh helper "
                f"(_calculate_values / _apply_rebase / _settle_balance). "
                f"User can escape negative rebase. See Solodit #63206 "
                f"(Yield Basis)."
            ),
        })
    return hits
