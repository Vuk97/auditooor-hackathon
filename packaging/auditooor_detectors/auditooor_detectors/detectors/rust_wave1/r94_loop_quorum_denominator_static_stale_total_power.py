"""
r94_loop_quorum_denominator_static_stale_total_power.py

Flags quorum-check fns whose denominator reads a one-time-initialized
`total_power_in_tokens` / `initial_total_supply` instead of a live
`total_voting_power()` — denominator drifts from real state, quorum
becomes unreachable or trivially passable.

Source: Solodit #27304 (Dexe GovUserKeeper).
Class: quorum-denominator-static-stale-total-power (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(quorum|quorum_reached|has_reached_quorum|check_quorum|passed_quorum|proposal_succeeded)")
_STATIC_DENOM_RE = re.compile(
    r"/\s*(total_power_in_tokens|initial_total_supply|initial_voting_power|"
    r"total_power_at_start|static_total_supply)|"
    r"\*\s*\w+\s*/\s*(total_power_in_tokens|initial_total_supply|initial_voting_power)"
)
_LIVE_DENOM_RE = re.compile(
    r"total_voting_power\s*\(\s*\)|live_total_supply|current_total_supply|"
    r"total_supply\s*\(\s*\)|get_total_vote_weight\s*\(\s*\)"
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
        if not _STATIC_DENOM_RE.search(body_nc):
            continue
        if _LIVE_DENOM_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` uses a cached total_power_in_tokens "
                f"as quorum denominator — drifts from live total supply "
                f"when NFTs transfer/burn, making quorum unreachable "
                f"(quorum-denominator-static-stale-total-power). "
                f"See Solodit #27304 (Dexe)."
            ),
        })
    return hits
