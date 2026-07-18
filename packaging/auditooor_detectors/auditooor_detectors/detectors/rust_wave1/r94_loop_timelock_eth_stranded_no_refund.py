"""
r94_loop_timelock_eth_stranded_no_refund.py

Flags timelock execute-transaction fns that forward msg.value /
deposit_amount via invoke but have no refund branch for the leftover
(execution-failure, partial-consumption) path — ETH strands in the
timelock.

Source: Solodit #10698 (Tally SafeGuard Timelock).
Class: timelock-eth-stranded-no-refund (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(execute_transaction|execute_proposal|timelock_execute|dispatch_timelock)"
)
_FORWARDS_VALUE_RE = re.compile(
    r"(value|deposit_amount|payable_value|invoke_amount)\s*[:,)]|"
    r"env\.invoke_contract\s*\(\s*\w+\s*,\s*\w+\s*,\s*(value|amount)"
)
_REFUND_RE = re.compile(
    r"transfer\s*\(\s*(proposer|sender|caller)[^)]*,\s*\w*(leftover|remaining|refund|unused)|"
    r"send_to\s*\(\s*(proposer|sender|caller)|"
    r"refund_eth|refund_caller|send_refund|pay_back"
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
        if not _FORWARDS_VALUE_RE.search(body_nc):
            continue
        if _REFUND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` forwards msg.value / deposit "
                f"but has no refund branch — unused/leftover ETH "
                f"strands in the timelock (timelock-eth-stranded-"
                f"no-refund). See Solodit #10698 (Tally SafeGuard)."
            ),
        })
    return hits
