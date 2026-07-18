"""
r94_loop_quorum_quadratic_vote_mismatch.py

Flags contracts that use QuadraticVoteStrategy / `sqrt`-weighted
vote counting AND GovernorVotesQuorumFractionUpgradeable-style
(linear) quorum — mismatch between vote units and quorum denominator.

Source: Solodit #52247 (Halborn Lucid Labs LucidGovernor).
Class: quorum-quadratic-vote-mismatch (both).
"""

from __future__ import annotations
import re
from _util import source_nocomment

_QUADRATIC_VOTE_RE = re.compile(
    r"QuadraticVoteStrategy|QuadraticGitcoin|sqrt_weighted|"
    r"(castVote|cast_vote)\s*\([^)]*\)[^{]*\{[\s\S]{0,300}?sqrt\s*\(|"
    r"vote[Ww]eight\s*=\s*sqrt\s*\("
)
_LINEAR_QUORUM_RE = re.compile(
    r"GovernorVotesQuorumFraction|quorumNumerator\s*\(\s*\)|"
    r"totalSupply\s*\(\s*\)\s*\*\s*quorum|quorum\s*=\s*\w+\s*\*\s*total_supply"
)
_QUADRATIC_QUORUM_RE = re.compile(
    r"quadratic_quorum|quorumSqrt|quorum_sqrt|sqrt_weighted_quorum"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src = source_nocomment(source)
    if not _QUADRATIC_VOTE_RE.search(src):
        return hits
    if not _LINEAR_QUORUM_RE.search(src):
        return hits
    if _QUADRATIC_QUORUM_RE.search(src):
        return hits
    hits.append({
        "severity": "high",
        "line": 1,
        "col": 0,
        "snippet": src[:200],
        "message": (
            "Contract uses quadratic (sqrt-weighted) vote counting "
            "but linear quorum (totalSupply * quorumNumerator) — "
            "quorum math is unit-mismatched, becomes unreachable or "
            "trivially met (quorum-quadratic-vote-mismatch). See "
            "Solodit #52247 (Lucid Labs LucidGovernor)."
        ),
    })
    return hits
