"""
r94_loop_quorum_denominator_total_supply_vs_quadratic_sqrt_mismatch.py

Flags Governor fns that integrate a quadratic / sqrt voting
strategy (cast_votes = sqrt(balance) or similar) but compute
quorum against `total_supply()` — cast votes are dwarfed by the
linear-scale denominator, quorum is never reachable.

Source: Solodit #52247 (Halborn Lucid Labs LucidGovernor).
Class: quorum-denominator-total-supply-vs-quadratic-sqrt-mismatch (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(_quorum_reached|quorum_reached|is_quorum_reached|"
    r"cast_vote|cast_vote_with_reason|get_votes|"
    r"check_quorum|has_quorum)"
)
# Body uses sqrt / quadratic scale for voting weight.
_QUADRATIC_RE = re.compile(
    fr"(?i)(sqrt\s*\(\s*{IDENT}balance|"
    fr"integer_sqrt\s*\(|"
    fr"isqrt\s*\(|"
    fr"\.\s*sqrt\s*\(\s*\)|"
    fr"quadratic_vote|"
    fr"weight\s*=\s*sqrt|"
    fr"pow\s*\(\s*{IDENT}balance\s*,\s*0\.5|"
    fr"passport_score)"
)
# Safe: quorum uses sqrt-denominator or separate sqrt-based supply.
_MATCHING_DENOM_RE = re.compile(
    fr"(?i)(sqrt_total_supply|"
    fr"sqrt_supply|"
    fr"quadratic_total_supply|"
    fr"sum_of_sqrt_balances|"
    fr"quorum_from_quadratic|"
    fr"quadratic_quorum|"
    fr"getPastTotalVotingPower\s*\(\s*\)\s*\*\s*{IDENT}sqrt)"
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
        if not _QUADRATIC_RE.search(body_nc):
            continue
        # Must reference total_supply() as the quorum denominator.
        if not re.search(r"(?i)(total_supply\s*\(|totalSupply\s*\(|getPastTotalSupply)", body_nc):
            continue
        if _MATCHING_DENOM_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` uses a quadratic / sqrt voting "
                f"weight but quorum is computed against linear-scale "
                f"`total_supply()` — cast votes are dwarfed by the "
                f"denominator, quorum is unreachable "
                f"(quorum-denominator-total-supply-vs-quadratic-sqrt-mismatch). "
                f"See Solodit #52247 (Halborn Lucid Labs LucidGovernor)."
            ),
        })
    return hits
