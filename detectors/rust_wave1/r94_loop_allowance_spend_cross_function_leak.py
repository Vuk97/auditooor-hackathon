"""
r94_loop_allowance_spend_cross_function_leak.py

Flags redeem/withdraw fns that take tokens from owner without
consulting / decrementing an allowance — while the standard transfer
path does enforce allowance. The sibling fn bypasses allowance.

Source: Solodit #30575 (Napier yield drained via 0-allowance redeemWithYT).
Class: allowance-spend-cross-function-leak (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(redeem|withdraw|claim|unwrap|burn_from)")
_USES_OWNER_FUNDS_RE = re.compile(
    r"(from|owner|user)\s*:\s*\w+|"
    r"\.burn\s*\(\s*(from|owner|user)|"
    r"_burn\s*\(\s*(from|owner|user)|"
    r"balance_of\s*\(\s*(from|owner|user)|"
    r"self\.balances?\s*\(\s*\&?(from|owner|user)"
)
_ALLOWANCE_CHECK_RE = re.compile(
    r"allowance\s*\(\s*(from|owner)|_spend_allowance|"
    r"spendAllowance|check_allowance|decrease_allowance|"
    r"self\.allowance|allowance_of\s*\("
)
_SELF_CALL_RE = re.compile(r"msg_sender\s*\(\s*\)|caller\s*\(\s*\)|env\.invoker\s*\(\s*\)")


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
        if not _USES_OWNER_FUNDS_RE.search(body_nc):
            continue
        if _ALLOWANCE_CHECK_RE.search(body_nc):
            continue
        if not _SELF_CALL_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` burns/moves funds from `owner/from` "
                f"param but never checks an allowance — attacker can "
                f"drain any holder who has tokens minted "
                f"(allowance-spend-cross-function-leak). See Solodit "
                f"#30575 (Napier)."
            ),
        })
    return hits
