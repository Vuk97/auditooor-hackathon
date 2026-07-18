"""
r94_loop_health_vs_slashable_collateral_discrepancy.py

Flags contracts that define BOTH a `compute_health` fn AND a
`slashable_collateral` / `compute_slashable` fn but they use
DIFFERENT collateral sources (e.g. one uses weighted collateral,
the other raw collateral) — liquidation flags unhealthy agents but
slashes insufficient amount, protocol absorbs bad debt.

Source: Solodit #61537 (TrailOfBits CAP Labs Covered Agent).
Class: health-vs-slashable-collateral-discrepancy (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of,
    is_pub, body_text_nocomment, source_nocomment,
)

_HEALTH_FN_RE = re.compile(r"(?i)^(compute_health|get_health|health_of|account_health)$")
_SLASH_FN_RE = re.compile(r"(?i)^(slashable_collateral|compute_slashable|get_slashable|slash_amount)$")

_COLLATERAL_KIND_RE = re.compile(
    r"(weighted_collateral|ltv_adjusted_collateral|collateral_weighted|"
    r"weighted_by_ltv|apply_liquidation_threshold)|"
    r"(raw_collateral|unweighted_collateral|full_collateral|gross_collateral|"
    r"balance_of\s*\(\s*collateral_token)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    health_kind = None
    health_fn = None
    slash_kind = None
    slash_fn = None
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        m_h = _HEALTH_FN_RE.search(name)
        m_s = _SLASH_FN_RE.search(name)
        if not (m_h or m_s):
            continue
        kind = None
        if re.search(r"weighted_collateral|ltv_adjusted|apply_liquidation_threshold", body_nc):
            kind = "weighted"
        elif re.search(r"raw_collateral|unweighted|gross_collateral|full_collateral", body_nc):
            kind = "raw"
        if m_h:
            health_kind = kind
            health_fn = fn
        if m_s:
            slash_kind = kind
            slash_fn = fn
    if health_fn is None or slash_fn is None:
        return hits
    if health_kind is None or slash_kind is None:
        return hits
    if health_kind != slash_kind:
        line, col = line_col(slash_fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(slash_fn, source)[:200],
            "message": (
                f"Health fn and slashable-collateral fn use DIFFERENT "
                f"collateral kinds ({health_kind} vs {slash_kind}) — "
                f"liquidation flags unhealthy but slash amount "
                f"mismatches, protocol absorbs bad debt "
                f"(health-vs-slashable-collateral-discrepancy). See "
                f"Solodit #61537 (CAP Labs Covered Agent)."
            ),
        })
    return hits
