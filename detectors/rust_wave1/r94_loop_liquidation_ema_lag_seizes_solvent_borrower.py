"""
r94_loop_liquidation_ema_lag_seizes_solvent_borrower.py

Flags liquidate / check_liquidatable fns that ONLY read an EMA /
smoothed / time-weighted price to decide liquidatability without
cross-checking the spot / current price — during EMA-lag windows
where price just recovered, still-solvent borrowers get liquidated.

Source: Solodit #65260 (CurrentSUI).
Class: liquidation-ema-lag-seizes-solvent-borrower (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(liquidate|check_liquidatable|is_liquidatable|can_liquidate)")
_EMA_READ_RE = re.compile(
    r"(ema_price|smoothed_price|twap|time_weighted|moving_average|"
    r"rolling_price|avg_price|average_price|weighted_price)"
)
_SPOT_CROSSCHECK_RE = re.compile(
    r"(spot_price|current_price|fresh_price|live_price|get_price_spot|"
    r"oracle\.get_price|oracle\.latest_price|price_feed\.get)"
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
        if not _EMA_READ_RE.search(body_nc):
            continue
        if _SPOT_CROSSCHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` decides liquidatability from EMA/"
                f"smoothed price with no spot/live cross-check — "
                f"during EMA-lag windows still-solvent borrowers get "
                f"liquidated (liquidation-ema-lag-seizes-solvent-"
                f"borrower). See Solodit #65260 (CurrentSUI)."
            ),
        })
    return hits
