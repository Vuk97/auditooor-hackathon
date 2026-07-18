"""
rounding_direction_div_before_mul_fire24.py

Rust recall lift for rounding-direction-attack gaps in value distribution math.

Flags public Rust functions that calculate fee, reward, share, liquidation, or
debt accounting values by dividing before multiplying and then apply the
rounded result to value-moving state. This intentionally ignores generic
arithmetic and helper-only math unless the rounded value reaches an accounting
sink.

Safe controls include multiply-before-divide ordering, fixed-point helpers,
checked mul-div APIs, explicit ceil/protocol-favorable rounding, and rejected
zero-fee or zero-share outcomes.
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
    r"(?i)(fees?|protocol_fee|reward|rewards?|shares?|assets?|amount|"
    r"collateral|liquidat|liquidator|debt|borrow|repay|interest|"
    r"payout|bonus|seize|mint|redeem|withdraw|deposit|vault|position|"
    r"balance|balances?|supply|liquidity|lp_|lp\b|distribution)"
)

_VALUE_SINK_RE = re.compile(
    r"(?i)(transfer|mint|burn|credit|debit|withdraw|redeem|repay|borrow|"
    r"seize|payout|pay_|release|settle|distribute|insert\s*\(|push\s*\(|"
    r"entry\s*\(|self\.[A-Za-z0-9_]*(?:fee|reward|share|debt|collateral|"
    r"asset|balance|supply|liquidity|reserve|payout|bonus)[A-Za-z0-9_]*"
    r"\s*(?:\+=|-=|=)|balances?\.|rewards?\.|positions?\.|"
    r"collateral_out\.|debt_shares\.|\+=|-=|return\s+|Ok\s*\()"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?i)(mul_div|muldiv|mul_div_(?:floor|ceil|down|up)?_?checked|"
    r"checked_mul\s*\([^;]{0,260}\)\s*\?[^;]{0,260}"
    r"checked_div\s*\([^;]{0,260}\)\s*\?|"
    r"fixedu?128|fixedi?128|fixed_point|decimal|ratio::|"
    r"perbill|permill|rounding\s*::|roundingmode|"
    r"round_up|round_down_protocol|protocol_favorable|ceil_div|div_ceil|"
    r"checked_ceil_div|full_precision)"
)

_ZERO_VALUE_REJECT_RE = re.compile(
    r"(?i)(if\s+[A-Za-z_][A-Za-z0-9_]*\s*==\s*0\s*\{\s*return\s+Err|"
    r"ensure!\s*\([^;]*(?:fee|share|reward|payout|collateral)[^;]*>\s*0|"
    r"require!\s*\([^;]*(?:fee|share|reward|payout|collateral)[^;]*>\s*0|"
    r"assert!\s*\([^;]*(?:fee|share|reward|payout|collateral)[^;]*>\s*0)"
)

_DIRECT_DIV_FIRST_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,220}/[^;\n]{1,220}\)?"
    r"\s*\*\s*[^;\n]{1,220})\s*;",
    re.MULTILINE,
)

_METHOD_DIV_FIRST_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>[^;]{0,240}\.checked_div\s*\([^;]{1,180}\)"
    r"\??[^;]{0,160}\.checked_mul\s*\([^;]{1,180}\)\??)"
    r"\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,200}/[^;\n]{1,200}\)?)\s*;",
    re.MULTILINE,
)

_MUL_WITH_QUOTIENT_RE_TEMPLATE = (
    r"let\s+(?:mut\s+)?(?P<out>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?:[^;\n]{{0,180}}\b{q}\b[^;\n]{{0,180}}\*"
    r"|[^;\n]{{0,180}}\*\s*[^;\n]{{0,180}}\b{q}\b)"
    r"[^;\n]{{0,180}};"
)


def _has_value_context(name: str, body: str) -> bool:
    return bool(_VALUE_CONTEXT_RE.search(name) or _VALUE_CONTEXT_RE.search(body))


def _has_value_sink(body: str, var: str, start: int) -> bool:
    tail = body[start : start + 1000]
    if not re.search(rf"\b{re.escape(var)}\b", tail):
        return False
    return bool(_VALUE_SINK_RE.search(tail))


def _direct_hit(body: str) -> tuple[str, str] | None:
    for regex, reason in (
        (_DIRECT_DIV_FIRST_RE, "operator division before multiplication"),
        (_METHOD_DIV_FIRST_RE, "checked_div before checked_mul"),
    ):
        for match in regex.finditer(body):
            var = match.group("var")
            expr = match.group("expr")
            if not (_VALUE_CONTEXT_RE.search(var) or _VALUE_CONTEXT_RE.search(expr)):
                continue
            if _has_value_sink(body, var, match.end()):
                return reason, var
    return None


def _split_quotient_hit(body: str) -> tuple[str, str] | None:
    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        quotient = match.group("q")
        expr = match.group("expr")
        if not (
            _VALUE_CONTEXT_RE.search(quotient)
            or _VALUE_CONTEXT_RE.search(expr)
        ):
            continue
        tail = body[match.end() : match.end() + 850]
        mul_re = re.compile(
            _MUL_WITH_QUOTIENT_RE_TEMPLATE.format(q=re.escape(quotient)),
            re.MULTILINE,
        )
        multiplied = mul_re.search(tail)
        if multiplied is None:
            continue
        out = multiplied.group("out")
        if not (
            _VALUE_CONTEXT_RE.search(out)
            or _VALUE_CONTEXT_RE.search(multiplied.group(0))
        ):
            continue
        if _has_value_sink(body, out, match.end() + multiplied.end()):
            return "split quotient multiplied after floor rounding", out
    return None


def _first_hit(name: str, body: str) -> tuple[str, str] | None:
    if not _has_value_context(name, body):
        return None
    if _SAFE_ROUNDING_RE.search(body) or _ZERO_VALUE_REJECT_RE.search(body):
        return None
    return _direct_hit(body) or _split_quotient_hit(body)


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
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` computes value-moving `{value}` with "
                    f"{reason}. Divide-first integer math can round fees, "
                    "rewards, shares, debt, or liquidation payouts in the "
                    "user-favored direction before accounting is updated."
                ),
            }
        )
    return hits
