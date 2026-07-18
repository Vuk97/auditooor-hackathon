"""
r94_loop_quorum_counts_against_abstain_instead_of_for_abstain.py

Flags `_quorum_reached` / `is_quorum_reached` fns that sum
`against_votes + abstain_votes` as the numerator when comparing
against the quorum threshold — quorum only reaches when
against/abstain exceeds the threshold, inverting the intended
meaning. (OZ Governor counts forVotes + abstainVotes as
participation; for-only variants count forVotes.)

Source: Solodit #21145 (Code4rena Lybra Finance Governance).
Class: quorum-counts-against-abstain-instead-of-for-abstain (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(_quorum_reached|quorum_reached|is_quorum_reached|"
    r"compute_quorum|check_quorum|has_quorum)"
)
# Numerator sums against + abstain.
_BAD_SUM_RE = re.compile(
    r"(?i)([\w\.]*against_votes\s*\+\s*[\w\.]*abstain_votes|"
    r"[\w\.]*againstVotes\s*\+\s*[\w\.]*abstainVotes|"
    r"[\w\.]*no_votes\s*\+\s*[\w\.]*abstain_votes|"
    r"[\w\.]*noVotes\s*\+\s*[\w\.]*abstainVotes)"
)
# Safe: uses forVotes (+ optional abstain) in the numerator instead.
_GOOD_SUM_RE = re.compile(
    r"(?i)([\w\.]*for_votes\s*\+\s*[\w\.]*abstain_votes|"
    r"[\w\.]*forVotes\s*\+\s*[\w\.]*abstainVotes|"
    r"[\w\.]*yes_votes\s*\+\s*[\w\.]*abstain_votes|"
    r"return\s+[\w\.]*for_votes\s*>=|"
    r"return\s+[\w\.]*forVotes\s*>=|"
    r"return\s+[\w\.]*yes_votes\s*>=)"
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
        if not _BAD_SUM_RE.search(body_nc):
            continue
        if _GOOD_SUM_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` sums against_votes + abstain_votes "
                f"as the quorum numerator — quorum only reaches when "
                f"against/abstain exceeds the threshold, inverting "
                f"the intended meaning "
                f"(quorum-counts-against-abstain-instead-of-for-abstain). "
                f"See Solodit #21145 (Code4rena Lybra Finance)."
            ),
        })
    return hits
