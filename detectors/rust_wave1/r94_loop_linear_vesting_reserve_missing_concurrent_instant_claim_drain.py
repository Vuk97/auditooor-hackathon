"""
r94_loop_linear_vesting_reserve_missing_concurrent_instant_claim_drain.py

Flags linear-vesting / linear-unlock scheduler fns that check the current
token balance against the scheduled amount at entry, but do NOT add the
scheduled output to a running reserve — concurrent instant-transmute
calls drain the pool before linear claimants arrive to claim their
unlocked share.

Source: Solodit #18832 (Trust Security Vagabond Token Transmuter).
Class: linear-vesting-reserve-missing-concurrent-instant-claim-drain (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(transmute_linear|transmuteLinear|"
    r"schedule_linear_unlock|scheduleLinearUnlock|"
    r"start_linear_vesting|startLinearVesting|"
    r"create_linear_claim|createLinearClaim)"
)
_BALANCE_CHECK_RE = re.compile(
    fr"(balance_of\s*{CALL}\s*>=\s*{IDENT}amount|"
    fr"balanceOf\s*{CALL}\s*>=\s*{IDENT}amount|"
    fr"require\s*\(\s*{IDENT}token\.balance_of\s*{CALL}\s*>=|"
    fr"assert\w*\s*!?\s*\(\s*balance_of\s*{CALL}\s*>=\s*{IDENT}amount)"
)
_RESERVE_RE = re.compile(
    r"(reserved_for_linear|reservedForLinear|"
    r"scheduled_output_reserve|scheduledOutputReserve|"
    r"total_reserved\s*\+=|totalReserved\s*\+=|"
    r"pending_unlock_reserve|pendingUnlockReserve|"
    r"locked_supply\s*\+=|lockedSupply\s*\+=|"
    r"reserved_output\[)"
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
        if not _BALANCE_CHECK_RE.search(body_nc):
            continue
        if _RESERVE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} checks balanceOf(this) >= amount at "
                f"entry to schedule a linear unlock, but does NOT add "
                f"to a running reserve — concurrent instant-transmute "
                f"calls drain the pool before linear claimants arrive "
                f"(linear-vesting-reserve-missing-concurrent-instant-"
                f"claim-drain). See Solodit #18832 (Trust Security "
                f"Vagabond Transmuter)."
            ),
        })
    return hits
