"""
r94_loop_lp_value_sum_of_balances_priced_flashloan_manipulable.py

Flags LP-pricing helpers that return
`price(tokenA) * balanceA + price(tokenB) * balanceB`
using the pool's instantaneous token balances. Attacker
flashloans, skews the pool's balance ratio, intra-tx LP price
is tampered, exits — Alpha Homora class vuln.

Source: Solodit #6798 (Spearbit Sense LP.sol).
Class: lp-value-sum-of-balances-priced-flashloan-manipulable (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(lp_price|get_lp_price|lp_value|"
    r"price_of_lp|compute_lp_value|fair_lp_price|"
    r"value_of_pool|oracle_lp_price)"
)
# Sums price * balance for both tokens (spot).
_SUM_BALANCE_RE = re.compile(
    fr"(?i)(price\s*\(\s*{IDENT}tokenA\s*\)[\s\S]{{0,80}}?balanceA|"
    fr"price\s*\(\s*{IDENT}token0\s*\)[\s\S]{{0,80}}?balance0|"
    fr"price_of\s*\(\s*{IDENT}token_a\s*\)[\s\S]{{0,80}}?balance_a|"
    fr"priceA\s*\*\s*balanceA\s*\+\s*priceB\s*\*\s*balanceB|"
    fr"price0\s*\*\s*reserve0\s*\+\s*price1\s*\*\s*reserve1)"
)
# Safe: Fair-LP formula (Alpha Homora) using k / sqrt / reserves with invariant.
_FAIR_LP_RE = re.compile(
    fr"(?i)(fair_lp|fairLp|"
    fr"sqrt\s*\(\s*{IDENT}(p0\s*\*\s*p1|pA\s*\*\s*pB)|"
    fr"2\s*\*\s*sqrt\s*\(\s*{IDENT}reserve|"
    fr"fairReserves|"
    fr"alpha_homora_lp|AlphaHomoraLp|"
    fr"compute_fair_value\s*\()"
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
        if not _SUM_BALANCE_RE.search(body_nc):
            continue
        if _FAIR_LP_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` prices an LP token as "
                f"`priceA*balanceA + priceB*balanceB` using the "
                f"pool's instantaneous balances — attacker "
                f"flashloans and skews balances intra-tx to tamper "
                f"LP price (Alpha Homora class vuln) "
                f"(lp-value-sum-of-balances-priced-flashloan-manipulable). "
                f"See Solodit #6798 (Spearbit Sense)."
            ),
        })
    return hits
