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
from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    IDENT,
)

_FN_NAME_RE = re.compile(
    r"(?i)^(cast_vote|castVote|vote|record_vote|recordVote|submit_vote|submitVote)$"
)
_VOTER_ARG = r"(?:user|voter|who|account|holder|delegate|delegator|caller|sender)"
_LIVE_BALANCE_RE = re.compile(
    fr"(?:"
    fr"(?:balance_of|balanceOf|get_balance|getBalance|"
    fr"current_balance_of|get_current_balance|getCurrentBalance|"
    fr"current_votes|get_current_votes|getCurrentVotes|"
    fr"voting_power_of|get_voting_power|getVotingPower)"
    fr"\s*\(\s*(?:&\s*)?{_VOTER_ARG}\b|"
    fr"self\.(?:balances|current_balances|current_votes|votes|"
    fr"voting_power)\s*(?:\[\s*(?:&\s*)?{_VOTER_ARG}\b|"
    fr"\.\s*get\s*\(\s*(?:&\s*)?{_VOTER_ARG}\b)|"
    fr"(?:balances|current_balances|current_votes|votes|voting_power)"
    fr"\s*\.\s*get\s*\(\s*(?:&\s*)?{_VOTER_ARG}\b"
    fr")",
    re.IGNORECASE,
)
_SNAPSHOT_READ_RE = re.compile(
    r"(balance_at|balance_of_at|get_past_votes|get_votes_at|votes_at_block|"
    r"balanceOfAt|getPastVotes|getVotesAt|snapshot_weight)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
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
                f"balance instead of balance_at(proposal.snapshot) - "
                f"user can buy-vote-sell to double-spend voting power "
                f"(vote-uses-current-balance-not-snapshot). See "
                f"Solodit #57249 (Regnum RAAC)."
            ),
        })
    return hits
