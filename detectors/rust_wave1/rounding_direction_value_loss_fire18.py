"""
rounding_direction_value_loss_fire18.py

Rust same-class lift for rounding-direction-attack recall gaps.

Flags public value-moving accounting functions when they:
  1. divide before multiplying a share, collateral, debt, fee, LP, reward,
     or payout amount and then apply the rounded result to accounting,
  2. mint LP from asymmetric min-ratio math without min-out or proportional
     guards, or
  3. use unchecked, wrapping, saturating, or unwrap-default arithmetic that
     silently clamps an economic invariant before a value movement.

The detector intentionally ignores generic arithmetic. A raw `a / b * c`
expression, or wrapping math in a helper, is not enough without a value-bearing
context and sink.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


_VALUE_CONTEXT_RE = re.compile(
    r"(?i)(shares?|share_ratio|collateral|assets?|tokens?|balances?|"
    r"reserves?|debt|borrow|repay|liquidat|liquidity|lp_|lp\b|"
    r"fee|fees|reward|payout|withdraw|redeem|deposit|mint|burn|"
    r"principal|interest|vault|position|supply|settle|seize)"
)

_VALUE_SINK_RE = re.compile(
    r"(?i)(transfer|mint|burn|credit|debit|withdraw|redeem|repay|borrow|"
    r"seize|payout|release|settle|push\s*\(|insert\s*\(|entry\s*\(|"
    r"balances?\.|rewards?\.|positions?\.|collateral_balances|"
    r"self\.[A-Za-z0-9_]*(?:share|debt|collateral|liquidity|lp|asset|"
    r"reserve|balance|supply|fee|reward|payout)[A-Za-z0-9_]*\s*"
    r"(?:\+=|-=|=)|\+=|-=|return\s+|Ok\s*\(|Some\s*\()"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?i)(mul_div|muldiv|mul_div_floor_checked|fixedu?128|fixedi?128|"
    r"fixed_point|decimal|perbill|permill|ratio::|checked_ratio|"
    r"roundingmode\s*::|rounding\s*::|round_up|ceil_div|div_ceil)"
)

_DIRECT_DIV_FIRST_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,220}/[^;\n]{1,220}\)?\s*\*\s*[^;\n]{1,220})\s*;",
    re.MULTILINE,
)

_METHOD_DIV_FIRST_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>[^;]{0,220}\.checked_div\s*\([^;]{1,160}\)"
    r"\??[^;]{0,120}\.checked_mul\s*\([^;]{1,160}\)\??)\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,180}/[^;\n]{1,180}\)?)\s*;",
    re.MULTILINE,
)

_MUL_WITH_QUOTIENT_RE_TEMPLATE = (
    r"let\s+(?:mut\s+)?(?P<out>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*[^;\n]{0,180}\b%s\b[^;\n]{0,180}\*"
    r"[^;\n]{0,180};"
)

_CLAMP_ARITH_RE = re.compile(
    r"(?i)("
    r"\.\s*wrapping_(?:add|sub|mul|div|shl|shr)\s*\("
    r"|unchecked\s*\{"
    r"|checked_(?:add|sub|mul|div)\s*\([^;]{1,180}\)\s*"
    r"\.\s*unwrap_or(?:_default)?\s*\(\s*"
    r"(?:0|[ui](?:8|16|32|64|128|size)::MAX|u256::MAX|i256::MAX|"
    r"[A-Z][A-Z0-9_]*_MAX|MAX_[A-Z0-9_]+)?\s*\)"
    r"|"
    r"\.\s*saturating_(?:add|sub|mul)\s*\("
    r")"
)

_SAFE_DISPOSITION_RE = re.compile(
    r"(?i)(ok_or|ok_or_else|return\s+Err|Err\s*\(|map_err|try_from|"
    r"refund|refund_unused|residual|remainder|dust|carry_forward|"
    r"excess|unused_amount|checked_(?:add|sub|mul|div)\s*\([^;]{1,220}\)"
    r"\s*\?)"
)

_LP_JOIN_NAME_RE = re.compile(
    r"(?i)(join_pool|joinpool|on_join_pool|add_liquidity|addliquidity|"
    r"mint_lp|mintlp|deposit_to_pool|pool_join)"
)

_MIN_RE = re.compile(r"(?i)(?:std\s*::\s*cmp\s*::|cmp\s*::)?min\s*\(")

_LP_SIDE0_RATIO_RE = re.compile(
    r"(?i)(?:token0|amount0|asset0|coin0)[A-Za-z0-9_\.]*"
    r"[\s\S]{0,180}(?:checked_mul\s*\([^)]*(?:supply|lp_supply|total_lp)"
    r"|\*\s*(?:self\.)?(?:supply|lp_supply|total_lp))"
    r"[\s\S]{0,180}(?:checked_div\s*\([^)]*(?:reserve0|reserve_0|balance0)"
    r"|/\s*(?:self\.)?(?:reserve0|reserve_0|balance0))"
)

_LP_SIDE1_RATIO_RE = re.compile(
    r"(?i)(?:token1|amount1|asset1|coin1)[A-Za-z0-9_\.]*"
    r"[\s\S]{0,180}(?:checked_mul\s*\([^)]*(?:supply|lp_supply|total_lp)"
    r"|\*\s*(?:self\.)?(?:supply|lp_supply|total_lp))"
    r"[\s\S]{0,180}(?:checked_div\s*\([^)]*(?:reserve1|reserve_1|balance1)"
    r"|/\s*(?:self\.)?(?:reserve1|reserve_1|balance1))"
)

_LP_SAFE_GUARD_RE = re.compile(
    r"(?i)(min_lp|min_amount_lp_out|minamountlpout|min_lp_out|"
    r"min_shares|min_amount_out|minamountout|slippage|"
    r"max_token0|max_token1|max_amount0|max_amount1|max_asset0|max_asset1|"
    r"pre_join_price|oracle_price|price_check|weighted_price_check|"
    r"check_join_ratio|proportional|ratio_check|same_ratio|invariant_check|"
    r"assert!\s*\([^;]*(?:>=|<=|>|<)|ensure!\s*\([^;]*(?:>=|<=|>|<)|"
    r"require!\s*\([^;]*(?:>=|<=|>|<))"
)


def _has_value_context(name: str, body: str) -> bool:
    return bool(_VALUE_CONTEXT_RE.search(name) or _VALUE_CONTEXT_RE.search(body))


def _has_value_sink(body: str, var: str, start: int) -> bool:
    tail = body[start : start + 1000]
    if not re.search(rf"\b{re.escape(var)}\b", tail):
        return False
    return bool(_VALUE_SINK_RE.search(tail))


def _division_before_multiplication_hit(body: str) -> tuple[str, str] | None:
    if _SAFE_ROUNDING_RE.search(body):
        return None

    for regex in (_DIRECT_DIV_FIRST_RE, _METHOD_DIV_FIRST_RE):
        for match in regex.finditer(body):
            var = match.group("var")
            expr = match.group("expr")
            if not (_VALUE_CONTEXT_RE.search(var) or _VALUE_CONTEXT_RE.search(expr)):
                continue
            if _has_value_sink(body, var, match.end()):
                return "division before multiplication reaches accounting", var

    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        q = match.group("q")
        expr = match.group("expr")
        if not (_VALUE_CONTEXT_RE.search(q) or _VALUE_CONTEXT_RE.search(expr)):
            continue
        tail = body[match.end() : match.end() + 800]
        mul_re = re.compile(_MUL_WITH_QUOTIENT_RE_TEMPLATE % re.escape(q), re.MULTILINE)
        result = mul_re.search(tail)
        if not result:
            continue
        out = result.group("out")
        if not (_VALUE_CONTEXT_RE.search(out) or _VALUE_CONTEXT_RE.search(result.group(0))):
            continue
        if _has_value_sink(body, out, match.end() + result.end()):
            return "division before multiplication quotient reaches accounting", out

    return None


def _unchecked_or_clamp_hit(body: str) -> tuple[str, str] | None:
    if not _CLAMP_ARITH_RE.search(body):
        return None
    if _SAFE_DISPOSITION_RE.search(body):
        return None
    if not _VALUE_SINK_RE.search(body):
        return None

    for match in _CLAMP_ARITH_RE.finditer(body):
        window = body[max(0, match.start() - 160) : match.end() + 240]
        if _VALUE_CONTEXT_RE.search(window):
            return "unchecked or clamping arithmetic reaches accounting", "clamped_value"
    return None


def _lp_join_hit(name: str, body: str) -> tuple[str, str] | None:
    if not _LP_JOIN_NAME_RE.search(name):
        return None
    if not _MIN_RE.search(body):
        return None
    if _LP_SAFE_GUARD_RE.search(body):
        return None
    if not (_LP_SIDE0_RATIO_RE.search(body) and _LP_SIDE1_RATIO_RE.search(body)):
        return None
    return "asymmetric LP min-ratio join lacks value protection", "lp_amount"


def _first_hit(name: str, body: str) -> tuple[str, str] | None:
    return (
        _lp_join_hit(name, body)
        or _division_before_multiplication_hit(body)
        or _unchecked_or_clamp_hit(body)
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source) or not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _has_value_context(name, body_nc):
            continue

        hit = _first_hit(name, body_nc)
        if hit is None:
            continue

        reason, value = hit
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` has rounding-direction-attack value loss: "
                    f"{reason} via `{value}`. Require multiply-before-divide, "
                    "explicit safe rounding, checked error handling, or min-out "
                    "and proportionality guards before moving value."
                ),
            }
        )
    return hits
