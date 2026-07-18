"""
r94_loop_usdt_nonzero_to_nonzero_approve_dos_grief.py

Flags integration paths that call `token.approve(spender, amount)`
directly without first zeroing the allowance. USDT reverts
`approve(nonZero)` when an existing non-zero allowance still
exists — attacker front-runs a tiny `approve(..., 1)` through
an alternate code path and every subsequent protocol interaction
reverts on approve.

Source: Solodit #20423 (Pashov Audit Group Mugen).
Class: usdt-nonzero-to-nonzero-approve-dos-grief (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(swap|deposit|bridge|zap|provide_liquidity|"
    r"add_liquidity|execute_trade|router_call|"
    r"execute_swap|approve_and_call)"
)
# Body calls approve(spender, amount) with a non-trivial amount.
_APPROVE_RE = re.compile(
    fr"(?i)({IDENT}token\w*\s*\.\s*approve\s*\(\s*\w+\s*,\s*{IDENT}amount|"
    fr"{IDENT}token\w*\s*\.\s*approve\s*\(\s*\w+\s*,\s*{IDENT}value|"
    fr"IERC20\s*\(\s*\w+\s*\)\s*\.\s*approve\s*\(\s*\w+\s*,\s*{IDENT}amount|"
    fr"approve\s*\(\s*\w+\s*,\s*{IDENT}amount)"
)
# Safe: resets allowance to 0 first / forceApprove / safeApprove.
_RESET_RE = re.compile(
    r"(?i)(\.\s*approve\s*\(\s*\w+\s*,\s*0\s*\)|"
    r"safeApprove\s*\(|safe_approve\s*\(|"
    r"forceApprove\s*\(|force_approve\s*\(|"
    r"safeDecreaseAllowance|safe_decrease_allowance|"
    r"allowance\s*\(\s*\w+\s*,\s*\w+\s*\)\s*==\s*0|"
    r"safeIncreaseAllowance|"
    r"approve_from_zero_first)"
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
        if not _APPROVE_RE.search(body_nc):
            continue
        if _RESET_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` calls `token.approve(spender, "
                f"amount)` with a non-zero amount without first "
                f"resetting allowance to zero (safeApprove / "
                f"forceApprove) — USDT reverts non-zero→non-zero "
                f"approves, attacker front-runs a tiny approve to "
                f"permanently DOS the flow "
                f"(usdt-nonzero-to-nonzero-approve-dos-grief). "
                f"See Solodit #20423 (Pashov Audit Group Mugen)."
            ),
        })
    return hits
