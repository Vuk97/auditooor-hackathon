"""
lp_join_asymmetric_pair_sandwich_overpays_one_side.py

Flags Rust LP join paths that mint LP shares from the minimum of two
asset-to-reserve ratios without a min-out or proportionality guard.

Shape:
  1. Public join/add-liquidity style function.
  2. Computes both `token0 * supply / reserve0` and
     `token1 * supply / reserve1`, either directly or through checked math.
  3. Uses `min(...)` over those ratio values.
  4. Lacks min LP output, max token input, proportionality, oracle, or
     explicit ratio guard.

This is a rounding-direction and asymmetric-ratio value loss detector, not a
generic string marker. A sandwich can skew one reserve before the victim joins;
the minimum ratio mints LP from the depleted side while the other side is
overpaid.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    is_pub,
    line_col,
    snippet_of,
)


_FN_NAME_RE = re.compile(
    r"(?i)(on_join_pool|join_pool|joinpool|add_liquidity|addliquidity|"
    r"mint_lp|mintlp|deposit_to_pool|depositpool|pool_join)"
)

_MIN_RE = re.compile(r"(?i)(?:std\s*::\s*cmp\s*::|cmp\s*::)?min\s*\(")

_SIDE0 = (
    r"(?:[a-z_][a-z0-9_]*\.)*"
    r"(?:token0_in|token0in|amount0_in|amount0in|asset0_in|asset0in|"
    r"coin0_in|coin0in|max_token0_in|maxtoken0in)"
)
_SIDE1 = (
    r"(?:[a-z_][a-z0-9_]*\.)*"
    r"(?:token1_in|token1in|amount1_in|amount1in|asset1_in|asset1in|"
    r"coin1_in|coin1in|max_token1_in|maxtoken1in)"
)
_SUPPLY = (
    r"(?:[a-z_][a-z0-9_]*\.)*"
    r"(?:supply|total_supply|totalsupply|lp_supply|lpsupply|supply_lp|"
    r"supplylp|total_lp|totallp)"
)
_RESERVE0 = (
    r"(?:[a-z_][a-z0-9_]*\.)*"
    r"(?:reserve0|reserve_0|reserves0|balance0|balance_0|token0_reserve|"
    r"token0reserve)"
)
_RESERVE1 = (
    r"(?:[a-z_][a-z0-9_]*\.)*"
    r"(?:reserve1|reserve_1|reserves1|balance1|balance_1|token1_reserve|"
    r"token1reserve)"
)

_SIDE0_RATIO = (
    rf"(?:{_SIDE0}\s*(?:\.checked_mul\s*\(\s*{_SUPPLY}\s*\)"
    rf"\??\s*\.checked_div\s*\(\s*{_RESERVE0}\s*\)|"
    rf"\*\s*{_SUPPLY}\s*/\s*{_RESERVE0}))"
)
_SIDE1_RATIO = (
    rf"(?:{_SIDE1}\s*(?:\.checked_mul\s*\(\s*{_SUPPLY}\s*\)"
    rf"\??\s*\.checked_div\s*\(\s*{_RESERVE1}\s*\)|"
    rf"\*\s*{_SUPPLY}\s*/\s*{_RESERVE1}))"
)

_SIDE0_RATIO_RE = re.compile(_SIDE0_RATIO)
_SIDE1_RATIO_RE = re.compile(_SIDE1_RATIO)

_RATIO_VAR0_RE = re.compile(
    rf"(?i)let\s+(?:mut\s+)?(?P<var>[a-z_][a-z0-9_]*(?:0|_0))"
    rf"(?:\s*:\s*[^=;]+)?\s*=\s*[^;\n]*(?:{_SIDE0_RATIO})"
)
_RATIO_VAR1_RE = re.compile(
    rf"(?i)let\s+(?:mut\s+)?(?P<var>[a-z_][a-z0-9_]*(?:1|_1))"
    rf"(?:\s*:\s*[^=;]+)?\s*=\s*[^;\n]*(?:{_SIDE1_RATIO})"
)

_SAFE_GUARD_RE = re.compile(
    r"(?i)(min_lp|min_amount_lp_out|minamountlpout|min_lp_out|"
    r"min_shares|min_amount_out|minamountout|slippage|"
    r"max_token0|max_token1|max_amount0|max_amount1|max_asset0|max_asset1|"
    r"pre_join_price|prejoinprice|oracle_price|price_check|"
    r"weighted_price_check|check_join_ratio|proportional|"
    r"ratio_check|same_ratio|invariant_check|"
    r"assert!\s*\([^;]*(?:>=|<=|>|<)|"
    r"ensure!\s*\([^;]*(?:>=|<=|>|<)|"
    r"require!\s*\([^;]*(?:>=|<=|>|<)|"
    r"if\s+[^{};]*(?:token0|amount0|asset0|lp|share)[^{};]*"
    r"(?:>=|<=|>|<)[^{};]*(?:return\s+none|return\s+err|return\s+false))"
)


def _has_ratio_pair(body: str) -> bool:
    if _SIDE0_RATIO_RE.search(body) and _SIDE1_RATIO_RE.search(body):
        return True

    var0 = _RATIO_VAR0_RE.search(body)
    var1 = _RATIO_VAR1_RE.search(body)
    if not (var0 and var1):
        return False

    min_window = body[min(var0.end(), var1.end()) :]
    return bool(
        re.search(
            rf"(?i)(?:std\s*::\s*cmp\s*::|cmp\s*::)?min\s*\(\s*"
            rf"(?:{re.escape(var0.group('var'))}\s*,\s*"
            rf"{re.escape(var1.group('var'))}|"
            rf"{re.escape(var1.group('var'))}\s*,\s*"
            rf"{re.escape(var0.group('var'))})",
            min_window,
        )
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source).lower()
        if not _MIN_RE.search(body_nc):
            continue
        if not _has_ratio_pair(body_nc):
            continue
        if _SAFE_GUARD_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` mints LP from min(token0*supply/reserve0, "
                    "token1*supply/reserve1) without min-out or proportionality "
                    "guards. Reserve skew can make the victim overpay one side "
                    "for too few LP shares."
                ),
            }
        )
    return hits
