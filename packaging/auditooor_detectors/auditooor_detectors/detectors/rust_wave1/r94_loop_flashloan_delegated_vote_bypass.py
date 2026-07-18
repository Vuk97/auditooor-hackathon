"""
r94_loop_flashloan_delegated_vote_bypass.py

Flags fns that accept delegated-vote action (vote_by_delegate /
vote_on_behalf / castVoteBySig) without snapshotting delegator's
balance at proposal-creation block.

Source: Solodit #27294 (Cyfrin Dexe).
Class: flashloan-delegated-vote-bypass (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(castVoteBySig|vote_by_delegate|vote_on_behalf|delegateVote|submitDelegatedVote)")
_SNAPSHOT_RE = re.compile(r"getPriorVotes|getPastVotes|votes_at_snapshot|balance_at_block|snapshot_block")


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
        if _SNAPSHOT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` accepts a delegated vote without "
                f"snapshotting balance at proposal-creation block. "
                f"Flash-loan + delegate in same tx decides proposal. "
                f"See Solodit #27294 (Dexe)."
            ),
        })
    return hits
