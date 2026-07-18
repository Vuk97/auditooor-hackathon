"""
r94_loop_single_dex_spot_reserves_flashloan_manipulable_oracle.py

Flags price-provider fns that compute a token price from the
*instantaneous* reserves of a single Uniswap-V2 / Balancer pool
(e.g., `getReserves()`, `balanceOf(pool)`, `price0Cumulative`
snapshots with no time delta). Attacker flashloans, swaps to
skew reserves, reads manipulated price, restores.

Source: Solodit #56440 (Zokyo Radiant Capital PriceProvider).
Class: single-dex-spot-reserves-flashloan-manipulable-oracle (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(get_token_price|get_lp_token_price|"
    r"get_price_from_pool|price_from_reserves|"
    r"compute_price|fetch_price|usd_price|get_asset_price)"
)
# Reads spot reserves / balanceOf / getReserves.
_SPOT_RE = re.compile(
    r"(?i)(get_reserves\s*\(|getReserves\s*\(|"
    r"balance_of\s*\(\s*\w*(pool|pair)|"
    r"balanceOf\s*\(\s*\w*(pool|pair)|"
    r"pool\.\s*balance\s*\(|pair\.\s*reserves|"
    fr"{IDENT}pair\s*\.\s*reserve0|{IDENT}pair\s*\.\s*reserve1)"
)
# Safe: TWAP / cumulative average over Δt / time-weighted.
_TWAP_RE = re.compile(
    r"(?i)(twap|time_weighted|timeWeighted|"
    r"price_cumulative|priceCumulative|"
    r"observe\s*\(|observations\s*\[|"
    r"last_update_timestamp|lastUpdateTimestamp|"
    r"oracle_period|TWAP_PERIOD|"
    r"consult\s*\(|quoteAtTick\s*\()"
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
        if not _SPOT_RE.search(body_nc):
            continue
        if _TWAP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` derives price from *instantaneous* "
                f"single-DEX reserves (getReserves / pool balance) "
                f"with no TWAP / time-weighted window — attacker "
                f"flashloans, swaps to skew reserves, reads the "
                f"manipulated price, restores "
                f"(single-dex-spot-reserves-flashloan-manipulable-oracle). "
                f"See Solodit #56440 (Zokyo Radiant Capital)."
            ),
        })
    return hits
