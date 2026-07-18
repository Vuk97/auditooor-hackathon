"""
r94_loop_token_deposit_no_balance_delta_fot_rebasing_drift.py

Flags deposit / stake / supply fns that credit the user the
amount passed in as a parameter rather than the actual
`balanceOf(this)` delta after `transferFrom`. Fee-on-transfer /
deflationary / rebasing tokens receive less than the parameter
amount, leaving protocol accounting drifted from real balance.

Source: Solodit #34506 (Codehawks Beedle Lender).
Class: token-deposit-no-balance-delta-fot-rebasing-drift (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(deposit|supply|stake|provide_liquidity|"
    r"add_collateral|fund|top_up|mint_shares_for)"
)
# Body does transferFrom then credits `amount` directly (no delta).
_NO_DELTA_RE = re.compile(
    fr"(?i)(transfer_from\s*\([\s\S]{{0,300}}?\)\s*;\s*[\s\S]{{0,300}}?(balances|total_deposits|shares|user\.\s*deposit)[\s\S]{{0,60}}?\+=\s*{IDENT}amount|"
    fr"safeTransferFrom\s*\([\s\S]{{0,300}}?\)\s*;\s*[\s\S]{{0,300}}?(balances|totalDeposits|shares)[\s\S]{{0,60}}?\+=\s*{IDENT}amount|"
    fr"token\.transferFrom\s*\([\s\S]{{0,200}}?\)[\s\S]{{0,200}}?_mint\s*\(\s*\w+\s*,\s*{IDENT}amount\s*\))"
)
# Safe: measures balance delta.
_BALANCE_DELTA_RE = re.compile(
    fr"(?i)(balance_before\s*=\s*{IDENT}balance_of\w*\s*\(|"
    fr"balanceBefore\s*=\s*{IDENT}balanceOf\w*\s*\(|"
    fr"pre_balance\s*=\s*{IDENT}balance_of\w*\s*\(|"
    fr"balance_after\s*-\s*balance_before|"
    fr"balanceAfter\s*-\s*balanceBefore|"
    fr"post_transfer_balance\s*-\s*pre_transfer_balance|"
    fr"actual_received\s*=|received\s*=\s*{IDENT}balance_after\s*-)"
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
        if not _NO_DELTA_RE.search(body_nc):
            continue
        if _BALANCE_DELTA_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` credits the user the parameter "
                f"`amount` after `transferFrom` instead of the actual "
                f"`balanceOf(this)` delta — fee-on-transfer / "
                f"deflationary / rebasing tokens cause internal "
                f"accounting to drift from real balance "
                f"(token-deposit-no-balance-delta-fot-rebasing-drift). "
                f"See Solodit #34506 (Codehawks Beedle Lender)."
            ),
        })
    return hits
