"""
r94_loop_liquidate_uses_stored_outdated_liabilities.py

Flags liquidate / warn / modify fns that read `borrow_balance_stored`
/ `borrowBalanceStored` (stored; no interest accrual) for the health
check instead of `borrow_balance_current` / accrue-then-read.

Source: Solodit #27661 (Sherlock Aloe Borrower).
Class: liquidate-uses-stored-outdated-liabilities (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(liquidate|warn|modify|health_check|check_health)")
_STORED_READ_RE = re.compile(
    r"(borrow_balance_stored|borrowBalanceStored|balance_stored|"
    r"get_stored_liabilities|stored_liabilities)\s*\("
)
_CURRENT_OR_ACCRUE_RE = re.compile(
    r"(borrow_balance_current|borrowBalanceCurrent|accrue_interest|"
    r"accrueInterest|update_interest|_update_interest)\s*\("
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
        if not _STORED_READ_RE.search(body_nc):
            continue
        if _CURRENT_OR_ACCRUE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads `borrowBalanceStored` for "
                f"the health check without calling accrueInterest "
                f"first — stored balance is stale, user creates "
                f"bad debt in one tx (liquidate-uses-stored-"
                f"outdated-liabilities). See Solodit #27661 (Aloe)."
            ),
        })
    return hits
