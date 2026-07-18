"""
r94_loop_funding_rate_derived_from_partial_skew_applied_globally.py

Flags perp-protocol fns that compute a funding rate from a single
maker's (oracle maker / partial) skew but then apply that rate to
every position market-wide — an attacker can skew the oracle maker
cheaply while every other trader pays funding.

Source: Solodit #32163 (Sherlock Perpetual Protocol).
Class: funding-rate-derived-from-partial-skew-applied-globally (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(compute_funding_rate|computeFundingRate|"
    r"update_funding|updateFunding|accrue_funding|"
    r"calc_funding_rate|get_funding_rate)"
)
_PARTIAL_SKEW_RE = re.compile(
    fr"(oracle_maker\s*\.\s*skew|oracleMaker\.skew|"
    fr"maker_skew|makerSkew|skew_of_oracle_maker|"
    fr"partialSkew|oracle_maker_imbalance|"
    fr"\.\s*net_position_size_of\s*\(\s*{IDENT}oracle_maker)"
)
_GLOBAL_APPLY_RE = re.compile(
    fr"(for\s+\w+\s+in\s+{IDENT}all_positions|"
    fr"for\s+\w+\s+in\s+{IDENT}traders|"
    fr"apply_rate_to_all|"
    fr"fundingRate\s*=\s*{IDENT}(maker|partial)|"
    fr"accumulated_funding\s*\+=|"
    fr"global_funding_index\s*=|"
    fr"update_all_funding_indexes|"
    fr"for\s+pos\s+in\s+{IDENT}positions)"
)
_SAFE_RE = re.compile(
    r"(total_market_skew|aggregate_skew|global_skew|"
    r"weighted_skew_all_makers|combined_skew)"
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
        if not _PARTIAL_SKEW_RE.search(body_nc):
            continue
        if not _GLOBAL_APPLY_RE.search(body_nc):
            continue
        if _SAFE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` derives funding rate from a single "
                f"maker's skew but applies it to every position "
                f"market-wide — attacker skews the oracle maker "
                f"cheaply, every other trader pays funding "
                f"(funding-rate-derived-from-partial-skew-applied-globally). "
                f"See Solodit #32163 (Sherlock Perpetual Protocol)."
            ),
        })
    return hits
