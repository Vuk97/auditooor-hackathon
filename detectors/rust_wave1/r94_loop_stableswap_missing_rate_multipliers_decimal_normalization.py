"""
r94_loop_stableswap_missing_rate_multipliers_decimal_normalization.py

Flags Curve-style stableswap `compute_d` / `get_y` / `swap`
helpers that iterate raw token balances without first applying
rate multipliers / decimal normalization. Pools with mixed-
decimal assets compute a skewed D, LPs receive wrong shares,
swaps trade at unfair price.

Source: Solodit #54982 (Code4rena MANTRA pool-manager).
Class: stableswap-missing-rate-multipliers-decimal-normalization (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(compute_d|get_d|get_y|stable_swap|"
    r"calc_d_invariant|stableswap_swap|"
    r"stable_pool_deposit|stable_pool_withdraw)"
)
# Touches raw balances for summation.
_RAW_SUM_RE = re.compile(
    r"(?i)(balances\s*\.\s*iter|balances\s*\[\s*\w+\s*\]|"
    r"pool\.\s*balances|xp\s*\[|"
    r"reserves\s*\.\s*iter|reserves\s*\[)"
)
# Safe: applies rate_multipliers / decimals normalization / PRECISION_MUL.
_RATE_MULTI_RE = re.compile(
    r"(?i)(rate_multipliers|rateMultipliers|"
    r"precision_multiplier|PRECISION_MUL|"
    r"normalize_balance|normalize_decimals|"
    r"rate_multiplier|to_18_decimals|"
    r"scale_to_precision|scaleToPrecision|"
    r"decimals\s*\[\s*\w+\s*\]|"
    fr"10\s*\*\*\s*\(\s*18\s*-\s*{IDENT}decimals)"
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
        if not _RAW_SUM_RE.search(body_nc):
            continue
        if _RATE_MULTI_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` iterates raw stableswap balances "
                f"without applying rate_multipliers / decimal "
                f"normalization — pools with mixed-decimal tokens "
                f"compute a skewed D, LPs get wrong shares, swaps "
                f"trade at unfair price "
                f"(stableswap-missing-rate-multipliers-decimal-normalization). "
                f"See Solodit #54982 (Code4rena MANTRA pool-manager)."
            ),
        })
    return hits
