"""
r94_loop_max_liquidable_calc_inconsistent_scaling.py

Flags fns that compute both `max_liquidable_collateral` and
`max_liquidable_debt` but use DIFFERENT oracle sources / scaling
factors (one uses current_price, the other uses collateral_value with
a different denom) — inconsistency opens a profit window.

Source: Solodit #48037 (OtterSec Navi).
Class: max-liquidable-calc-inconsistent-scaling (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(calculate_max_liquidation|compute_max_liquidation|max_liquidable|liquidation_bounds)")
_BOTH_FIELDS_RE = re.compile(
    r"max_liquidable_collateral", re.IGNORECASE
)
_BOTH_FIELDS_RE_2 = re.compile(
    r"max_liquidable_debt|max_liquidable_repay", re.IGNORECASE
)
_DIFFERENT_SRC_RE = re.compile(
    r"(oracle_price|price_oracle|get_price|current_price|spot_price)\s*\(\s*\w+\s*\)[\s\S]{0,400}(collateral_value|stored_value|deposit_value)|"
    r"(collateral_value|deposit_value)[\s\S]{0,400}(oracle_price|price_oracle|get_price)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _BOTH_FIELDS_RE.search(body_nc):
            continue
        if not _BOTH_FIELDS_RE_2.search(body_nc):
            continue
        if not _DIFFERENT_SRC_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` sizes max_liquidable_collateral and "
                f"max_liquidable_debt from different oracle sources / "
                f"scaling paths — inconsistency opens a profit window "
                f"(max-liquidable-calc-inconsistent-scaling). See "
                f"Solodit #48037 (Navi)."
            ),
        })
    return hits
