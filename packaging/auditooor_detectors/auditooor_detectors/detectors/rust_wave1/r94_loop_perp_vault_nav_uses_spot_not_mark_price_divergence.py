"""
r94_loop_perp_vault_nav_uses_spot_not_mark_price_divergence.py

Flags perp-vault NAV computation fns that pull a SPOT oracle price
(Chainlink latestAnswer/latestRoundData, spot_price getter, etc.) to
value perpetual positions — but never reference the perp MARK price
(or index TWAP). NAV diverges from actual settlement during funding
windows; redemptions execute at a stale/biased NAV.

Source: Solodit #64772 (Quantstamp Dipcoin Vault).
Class: perp-vault-nav-uses-spot-not-mark-price-divergence (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(compute_nav|computeNav|get_nav|getNav|"
    r"calculate_nav|vault_nav|total_nav|"
    r"pricing_nav|share_nav|nav_per_share)"
)
_SPOT_PRICE_CALL_RE = re.compile(
    r"(oracle_spot_price|oracleSpotPrice|"
    r"spot_price\s*\(|spotPrice\s*\(|"
    r"chainlink_feed\s*\.\s*latest|"
    r"get_spot_from_chainlink|"
    r"oracle\s*\.\s*latest_answer|oracle\.latestAnswer|"
    r"latestRoundData|latest_round_data)"
)
_MARK_PRICE_RE = re.compile(
    r"(mark_price|markPrice|perp_mark_price|perpetual_mark|"
    r"twap_mark|get_mark_price|compute_mark_price|"
    r"index_price_twap)"
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
        if not _SPOT_PRICE_CALL_RE.search(body_nc):
            continue
        if _MARK_PRICE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} computes perp-vault NAV using oracle "
                f"SPOT price instead of perp MARK price — NAV diverges "
                f"from actual settlement during funding windows, "
                f"redemption at stale NAV "
                f"(perp-vault-nav-uses-spot-not-mark-price-divergence). "
                f"See Solodit #64772 (Quantstamp Dipcoin Vault)."
            ),
        })
    return hits
