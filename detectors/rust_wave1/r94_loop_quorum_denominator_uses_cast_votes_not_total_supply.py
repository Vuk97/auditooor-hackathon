"""
r94_loop_quorum_denominator_uses_cast_votes_not_total_supply.py

Flags `_quorumReached` / `is_quorum_reached` fns that divide `for`
votes by the sum of cast votes (for + against + abstain) instead
of by the token's total supply — proposals pass with a fraction
of intended supply participation.

Source: Solodit #50064 (Code4rena IQ AI TokenGovernor).
Class: quorum-denominator-uses-cast-votes-not-total-supply (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(_quorum_reached|quorum_reached|is_quorum_reached|"
    r"compute_quorum|check_quorum|has_quorum)"
)
# Body divides/compares against sum of cast votes.
_CAST_SUM_RE = re.compile(
    r"(?i)([\w\.]*for_votes\s*\+\s*[\w\.]*against_votes\s*\+\s*[\w\.]*abstain_votes|"
    r"[\w\.]*forVotes\s*\+\s*[\w\.]*againstVotes\s*\+\s*[\w\.]*abstainVotes|"
    r"[\w\.]*yes_votes\s*\+\s*[\w\.]*no_votes\s*\+\s*[\w\.]*abstain_votes|"
    r"total_votes_cast|totalVotesCast|votes_cast\s*\(|"
    r"total_cast\s*=\s*[\w\.]*for_votes\s*\+)"
)
# Safe: explicit totalSupply / getPastTotalSupply reference.
_TOTAL_SUPPLY_RE = re.compile(
    r"(?i)(total_supply\s*\(\s*\)|totalSupply\s*\(\s*\)|"
    r"past_total_supply|getPastTotalSupply|"
    fr"\.total\s*\(\s*\)\s*\*\s*{IDENT}quorum|"
    fr"{IDENT}quorum_numerator\s*\*\s*{IDENT}total)"
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
        if not _CAST_SUM_RE.search(body_nc):
            continue
        if _TOTAL_SUPPLY_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` computes quorum against the sum of "
                f"cast votes (for + against + abstain) instead of "
                f"total_supply — proposals pass with a fraction of "
                f"intended supply participation "
                f"(quorum-denominator-uses-cast-votes-not-total-supply). "
                f"See Solodit #50064 (Code4rena IQ AI TokenGovernor)."
            ),
        })
    return hits
