"""
r94_loop_ve_total_voting_power_equals_total_supply_inflation.py

Flags `get_total_voting_power` / `totalVotingPower` fns on
ve-token style contracts that return `total_supply()` directly
rather than the sum of locked-balance-weighted voting power —
any path that mints/inflates supply without increasing lock
weight dilutes active voters (and under-dilutes if supply
decreases).

Source: Solodit #57216 (Codehawks RAAC Core Contracts veRAACToken).
Class: ve-total-voting-power-equals-total-supply-inflation (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(get_total_voting_power|total_voting_power|"
    r"totalVotingPower|get_total_votes|total_votes|"
    r"global_voting_supply|voting_supply)"
)
# Returns total_supply() directly.
_RETURN_SUPPLY_RE = re.compile(
    fr"(?i)(return\s+{IDENT}total_supply\s*\(\s*\)|"
    fr"return\s+self\s*\.\s*total_supply\s*\(\s*\)|"
    fr"=\s*self\s*\.\s*total_supply\s*\(\s*\)\s*;|"
    fr"=\s*total_supply\s*\(\s*\)\s*;|"
    fr"return\s+totalSupply\s*\(\s*\))"
)
# Safe: returns summed / integrated locked-weight supply.
_WEIGHTED_RE = re.compile(
    fr"(?i)(sum_of_biases|sum_of_slopes|global_bias|"
    fr"global_slope|locked_voting_power_sum|"
    fr"integrate_supply|integrateSupply|"
    fr"sum_over_locks|sumOverLocks|"
    fr"for\s+\w+\s+in\s+{IDENT}locks|"
    fr"epoch_total_votes|epochTotalVotes)"
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
        if not _RETURN_SUPPLY_RE.search(body_nc):
            continue
        if _WEIGHTED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` returns `total_supply()` directly "
                f"instead of the sum of locked-weight voting power — "
                f"mint/inflate paths dilute active voters (or "
                f"under-dilute on burn) "
                f"(ve-total-voting-power-equals-total-supply-inflation). "
                f"See Solodit #57216 (Codehawks RAAC veRAACToken)."
            ),
        })
    return hits
