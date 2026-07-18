"""
r94_loop_restaking_operator_self_undelegate_lrt_rate_manipulation.py

Flags LRT / restaking undelegate fns that do NOT guard against the
staker being the operator themselves — when a malicious operator
calls `undelegate` with `staker == self`, the EL DelegationManager
forcibly unwinds all delegations to them and the LRT exchange rate
collapses.

Source: Solodit #30898 (Sherlock Rio Network).
Class: restaking-operator-self-undelegate-lrt-rate-manipulation (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(undelegate|undelegate_all|force_undelegate|"
    r"exit_operator|queue_undelegation)"
)
_CALLER_ACCESS_RE = re.compile(
    r"(?i)(msg\.sender|caller|env\.invoker|self\.caller|invoking_address)"
)
# Safe: guard that staker / caller != operator_addr.
_SELF_GUARD_RE = re.compile(
    fr"(?i)(caller\s*!=\s*{IDENT}operator|"
    fr"msg\.sender\s*!=\s*{IDENT}operator|"
    fr"staker\s*!=\s*{IDENT}operator|"
    fr"require\s*\(\s*!is_operator|"
    fr"require\s*\(\s*!\s*is_registered_operator|"
    fr"assert\w*\s*!?\s*\(\s*!\s*is_operator|"
    fr"is_operator\s*\(\s*staker\s*\)\s*==\s*false|"
    fr"panic_if_operator|check_not_operator)"
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
        if not _CALLER_ACCESS_RE.search(body_nc):
            continue
        if _SELF_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` handles undelegation against "
                f"msg.sender / caller without rejecting the case "
                f"where the caller IS the registered operator — "
                f"malicious operator triggers mass-undelegation to "
                f"themselves, collapsing the LRT exchange rate "
                f"(restaking-operator-self-undelegate-lrt-rate-manipulation). "
                f"See Solodit #30898 (Sherlock Rio Network)."
            ),
        })
    return hits
