"""
r94_loop_vote_uses_current_balance_not_snapshot.py

Flags castVote fns that compute voting weight as `balance_of(user)` /
`self.balances[user]` directly (LIVE balance) instead of
`balance_at(proposal.snapshot_block)`.

Source: Solodit #57249 (Codehawks Regnum RAAC Governor).
Class: vote-uses-current-balance-not-snapshot (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(cast_vote|vote|record_vote|submit_vote)")
_LIVE_BALANCE_RE = re.compile(
    fr"(balance_of\s*\(\s*{IDENT}user|self\.balances\s*\[\s*{IDENT}user|"
    fr"voting_power_of\s*\(\s*{IDENT}user|get_balance\s*\(\s*{IDENT}user)",
    re.IGNORECASE,
)
_SNAPSHOT_READ_RE = re.compile(
    r"(balance_at|balance_of_at|get_past_votes|get_votes_at|votes_at_block|"
    r"balanceOfAt|getPastVotes|getVotesAt|snapshot_weight)"
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
        if not _LIVE_BALANCE_RE.search(body_nc):
            continue
        if _SNAPSHOT_READ_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes voting weight from LIVE "
                f"balance instead of balance_at(proposal.snapshot) — "
                f"user can buy-vote-sell to double-spend voting power "
                f"(vote-uses-current-balance-not-snapshot). See "
                f"Solodit #57249 (Regnum RAAC)."
            ),
        })
    return hits
