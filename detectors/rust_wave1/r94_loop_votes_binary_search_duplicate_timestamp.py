"""
r94_loop_votes_binary_search_duplicate_timestamp.py

Flags getPastVotes / balance_of_at fns that binary-search a sorted
checkpoint array on timestamp / block but don't disambiguate between
duplicate-timestamp entries — returns non-deterministic entry.

Source: Solodit #38112 (Immunefi Alchemix VotingEscrow).
Class: votes-binary-search-duplicate-timestamp (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(get_past_votes|get_votes_at|balance_of_at|binary_search_checkpoint|checkpoint_at)")
_BINARY_SEARCH_RE = re.compile(
    r"(while|loop)[\s\S]{0,200}?"
    r"(mid|mid_idx|lo|hi|low|high)\s*=[\s\S]{0,160}?"
    r"(timestamp|ts|block_number|\[\s*mid\s*\])\s*(<|<=|>)"
)
_DEDUP_RE = re.compile(
    r"(last_with_ts|last_at|last_index_for_ts|select_last_same_ts|"
    r"while\s+.*(ts|timestamp)\s*==\s*.*(ts|timestamp)|"
    r"dedup_timestamps|collapse_same_ts)"
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
        if not _BINARY_SEARCH_RE.search(body_nc):
            continue
        if _DEDUP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` binary-searches a checkpoint array "
                f"without disambiguating duplicate-timestamp entries "
                f"— returns non-deterministic entry, attacker times "
                f"writes so search returns stale value "
                f"(votes-binary-search-duplicate-timestamp). See "
                f"Solodit #38112 (Alchemix VotingEscrow)."
            ),
        })
    return hits
