"""
r94_loop_withdraw_contribution_wrong_divisor.py

Flags withdraw_contribution / refund fns that divide contribution
by total_contributed while some portion has already been paid out
(fees, redeemed shares) — wrong base over/underpays contributors.

Source: Solodit #2986 (Fractional withdrawContribution).
Class: withdraw-contribution-wrong-divisor (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(withdraw_contribution|refund_contribution|claim_refund|"
    r"reclaim_contribution|withdraw_deposit)"
)
_DIV_RE = re.compile(
    r"\*\s*\w+\s*/\s*(total_contributed|totalContributed|total_deposited|"
    r"totalDeposited|total_raised|totalRaised)"
)
_TRACKS_REDUCTION_RE = re.compile(
    r"contributions_remaining|contributionsRemaining|remaining_raised|"
    r"remainingRaised|outstanding_contribution|outstandingContribution|"
    r"unredeemed_contribution"
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
        if not _DIV_RE.search(body_nc):
            continue
        if _TRACKS_REDUCTION_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` divides by `total_contributed` but "
                f"doesn't track already-withdrawn contributions — "
                f"late contributors get over/underpaid (withdraw-"
                f"contribution-wrong-divisor). See Solodit #2986 "
                f"(Fractional)."
            ),
        })
    return hits
