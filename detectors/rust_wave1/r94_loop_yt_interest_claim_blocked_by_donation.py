"""
r94_loop_yt_interest_claim_blocked_by_donation.py

Flags YT.claim_interest / accrue_interest fns that compute
`total_interest - already_claimed` using checked_sub or `-` without
first reconciling donated reserves — a malicious donation makes
the subtraction underflow and the claim reverts.

Source: Solodit #30576 (Sherlock Napier).
Class: yt-interest-claim-blocked-by-donation (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(claim_interest|claim_yield|collect_interest|collect_yield|accrue_interest_yt)")
_INTEREST_DIFF_RE = re.compile(
    r"(total_interest|pt_reserves|yt_reserves|total_yield|accrued_yield)\s*(-|\.checked_sub)|"
    r"let\s+\w+\s*=\s*(total_interest|total_yield|accrued_yield)\s*\([\s\S]{0,200}?\.checked_sub\s*\("
)
_DONATION_GUARD_RE = re.compile(
    r"(reconcile_reserves|absorb_donation|sync_reserves|snapshot_reserves_at_issue|"
    r"last_reserves\s*=)"
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
        if not _INTEREST_DIFF_RE.search(body_nc):
            continue
        if _DONATION_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` subtracts claimed-interest from "
                f"total-interest without reconciling donated reserves "
                f"— attacker donates tiny amount to trip underflow, "
                f"YT holders can't claim (yt-interest-claim-blocked-"
                f"by-donation). See Solodit #30576 (Napier)."
            ),
        })
    return hits
