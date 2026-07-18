"""
r94_loop_liquidation_atoken_burn_reserve_illiquidity_dos.py

Flags liquidation fns that burn / redeem aTokens directly against
the collateral reserve (transfer underlying out) without a
fall-through path when the reserve is illiquid. If the reserve
lacks available liquidity, the burn reverts and unhealthy
positions cannot be liquidated — insolvency compounds.

Source: Solodit #41813 (Sherlock ZeroLend One).
Class: liquidation-atoken-burn-reserve-illiquidity-dos (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(liquidate|liquidate_call|execute_liquidation|"
    r"liquidation_call|liquidate_position|process_liquidation)"
)
_ATOKEN_BURN_RE = re.compile(
    fr"(?i)(a_token\s*\.\s*burn\s*\(|aToken\.burn\s*\(|"
    fr"{IDENT}aToken\s*\.\s*transfer_underlying_to\s*\(|"
    fr"a_token\s*\.\s*transfer_underlying_to\s*\(|"
    fr"IScaledBalanceToken\s*\(|"
    fr"reserve\s*\.\s*withdraw\s*\(|"
    fr"pool\.\s*transfer_collateral_to_liquidator)"
)
_FALLTHROUGH_RE = re.compile(
    fr"(?i)(if\s+{IDENT}reserve\.available_liquidity\s*<|"
    fr"require\s*\(\s*{IDENT}reserveAvailable\s*>=\s*{IDENT}toBurn|"
    fr"else\s*\{{\s*{IDENT}transfer_atoken_instead|"
    fr"receive_as_atoken|transferAToken|"
    fr"fallback_transfer_scaled|"
    fr"liquidate_in_atokens|"
    fr"fallback_to_atokens)"
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
        if not _ATOKEN_BURN_RE.search(body_nc):
            continue
        if _FALLTHROUGH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` burns / redeems aTokens against "
                f"the collateral reserve without a fall-through path "
                f"when the reserve is illiquid — the burn reverts "
                f"and unhealthy positions cannot be liquidated, "
                f"insolvency compounds "
                f"(liquidation-atoken-burn-reserve-illiquidity-dos). "
                f"See Solodit #41813 (Sherlock ZeroLend One)."
            ),
        })
    return hits
