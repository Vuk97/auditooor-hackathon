"""
r94_loop_erc20_approve_nonzero_to_nonzero_race_condition.py

Flags ERC20 `approve(spender, value)` implementations that
update the allowance to a non-zero value without first requiring
the prior allowance to be zero (or without exposing
`increase_allowance` / `decrease_allowance`). Classic race:
attacker front-runs the tx, spends the old allowance, then
accepts the new one — double-spend.

Source: Solodit #28942 (TrailOfBits Maple Labs).
Class: erc20-approve-nonzero-to-nonzero-race-condition (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(^approve$|^_approve$|\bapprove\b|approve_erc20|"
    r"approve_token|set_allowance)"
)
# Body writes allowance unconditionally.
_SET_ALLOWANCE_RE = re.compile(
    fr"(?i)(allowances\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*=\s*{IDENT}value|"
    fr"allowance\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*=\s*{IDENT}amount|"
    fr"{IDENT}allowances\s*\.\s*insert\s*\([\s\S]{{0,120}}?,\s*{IDENT}(value|amount)|"
    fr"self\s*\.\s*allowances\s*\.\s*set\s*\(|"
    fr"allowance\s*::\s*set\s*\(|"
    fr"set_allowance\s*\(\s*\w+\s*,\s*\w+\s*,\s*{IDENT}value\s*\))"
)
# Safe: current allowance must be zero first, OR increase/decrease only path.
_GUARD_RE = re.compile(
    fr"(?i)(require\s*\(\s*{IDENT}(amount|value)\s*==\s*0\s*\|\|\s*{IDENT}allowance\s*\[[\s\S]{{0,80}}?\]\s*==\s*0|"
    fr"require\s*\(\s*allowances\s*\[[\s\S]{{0,80}}?\]\s*==\s*0|"
    fr"current_allowance\s*==\s*0|"
    fr"increase_allowance\s*\(|increaseAllowance\s*\(|"
    fr"decrease_allowance\s*\(|decreaseAllowance\s*\(|"
    fr"approve_from_zero|forceApprove|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}(amount|value)\s*==\s*0\s*\|\|\s*{IDENT}allowance)"
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
        if not _SET_ALLOWANCE_RE.search(body_nc):
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
                f"pub fn `{name}` writes a new non-zero allowance "
                f"without requiring the prior allowance is zero or "
                f"exposing increase/decrease-only paths — attacker "
                f"front-runs the tx to spend the old allowance then "
                f"accepts the new one "
                f"(erc20-approve-nonzero-to-nonzero-race-condition). "
                f"See Solodit #28942 (TrailOfBits Maple Labs)."
            ),
        })
    return hits
