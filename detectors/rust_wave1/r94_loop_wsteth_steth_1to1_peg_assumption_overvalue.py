"""
r94_loop_wsteth_steth_1to1_peg_assumption_overvalue.py

Flags fns that price wstETH as its stETH accounting value
(stEthPerToken / getStETHByWstETH) without querying a
stETH/ETH oracle — assumes stETH pegs 1:1 to ETH; during
depegs the derivative overvalues the LSD.

Source: Solodit #19921 (Code4rena Asymmetry Finance WstEth).
Class: wsteth-steth-1to1-peg-assumption-overvalue (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(eth_per_derivative|ethPerDerivative|"
    r"eth_value_of|ethValueOf|price_of_lsd|priceOfLsd|"
    r"compute_collateral_value|fetch_lsd_price|wsteth_to_eth)"
)
_PEG_ASSUMPTION_RE = re.compile(
    r"(?i)(stEthPerToken\s*\(|st_eth_per_token\s*\(|"
    r"getStETHByWstETH|get_steth_by_wsteth|"
    r"sharesToSteth|tokensPerShare)"
)
_ORACLE_PRICE_RE = re.compile(
    r"(?i)(steth_eth_oracle|stEthEthOracle|"
    r"curve_pool_get_dy|getDy\s*\(|chainlink_feed|"
    fr"oracle\s*\.\s*latest|get_price\s*\(\s*{IDENT}steth|"
    r"stethPrice|lsd_price_feed|depegging_price_check)"
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
        if not _PEG_ASSUMPTION_RE.search(body_nc):
            continue
        if _ORACLE_PRICE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` prices wstETH as its stETH accounting "
                f"value without querying a stETH/ETH oracle — assumes "
                f"stETH pegs 1:1 to ETH; during depegs the derivative "
                f"overvalues the LSD "
                f"(wsteth-steth-1to1-peg-assumption-overvalue). "
                f"See Solodit #19921 (Code4rena Asymmetry Finance)."
            ),
        })
    return hits
