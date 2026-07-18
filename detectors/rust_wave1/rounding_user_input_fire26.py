"""
rounding_user_input_fire26.py

Source-backed Rust lift for rounding-direction-attack recall gaps.

Sources:
- Halborn division-before-multiplication precision loss sections cited by
  detectors/rust_wave1/division_before_multiplication.py.
- Solodit #55256, SEDA Protocol division by a user-controlled denominator,
  cited by r94_loop_division_by_zero_on_user_input.py.
- Solodit #6322, Tigris Trade fee-config intermediate overflow, cited by
  r94_loop_fee_config_intermediate_overflow_vault_drain.py.

Flags public Rust functions where user-controlled amount, fee, reward, share,
or denominator math is rounded, divided by an unchecked user denominator, or
multiplied through an overflow-prone fee expression before the result reaches
vault, reward, fee, share, or balance accounting.

This is detector-fixture evidence only. It does not claim submission readiness.
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
    text_of,
)


_NUMERIC_TY_RE = re.compile(
    r"(?i)\b(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|"
    r"u256|uint128|uint256|u512|i256|decimal|fixedu?128)\b"
)

_PARAM_RE = re.compile(
    r"^\s*(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?:&\s*(?:mut\s+)?)?(?P<ty>[A-Za-z_][A-Za-z0-9_:<>]*)"
)

_VALUE_CONTEXT_RE = re.compile(
    r"(?i)(amount|assets?|tokens?|balances?|shares?|collateral|debt|borrow|"
    r"repay|liquidat|liquidity|lp_|lp\b|fee|fees|bps|reward|rewards|"
    r"payout|withdraw|redeem|deposit|mint|burn|principal|interest|vault|"
    r"reserve|position|supply|settle|seize|cost|price|pnl|profit)"
)

_VALUE_PARAM_RE = re.compile(
    r"(?i)^(amount|asset|assets|token|tokens|balance|shares?|collateral|debt|"
    r"borrow|repay|liquidity|lp|fee|fees|fee_bps|bps|reward|rewards|"
    r"payout|deposit|withdraw|principal|interest|position|size|price|pnl|"
    r"emission|supply|reserve|cost)"
)

_DENOM_PARAM_RE = re.compile(
    r"(?i)(denom|denominator|divisor|period|epoch|slot|count|num_|total|"
    r"supply|shares?|gas_price|scale|rate|window|parts|length|len)"
)

_STATE_SINK_RE = re.compile(
    r"(?i)(transfer|mint|burn|credit|debit|withdraw|redeem|repay|borrow|"
    r"seize|payout|pay_|release|settle|distribute|collect|harvest|"
    r"entry\s*\(|insert\s*\(|push\s*\(|"
    r"(?:self|state|vault|pool|market|ledger|config|account)\."
    r"[A-Za-z0-9_]*(?:vault|fee|reward|share|asset|balance|debt|"
    r"collateral|supply|reserve|payout|liquidity|position)[A-Za-z0-9_]*"
    r"\s*(?:\+=|-=|=)|\+=|-=|return\s+|Ok\s*\(|Some\s*\()"
)

_SAFE_MATH_RE = re.compile(
    r"(?i)(mul_div|muldiv|full_math|fullmath|safe_mul_div|"
    r"checked_mul\s*\([^;]{0,260}\)\s*\?[^;]{0,260}"
    r"checked_div\s*\([^;]{0,260}\)\s*\?|"
    r"checked_div\s*\([^;]{0,260}\)\s*\?[^;]{0,260}"
    r"checked_mul\s*\([^;]{0,260}\)\s*\?|"
    r"fixedu?128|fixedi?128|fixed_point|decimal|ratio::|perbill|permill|"
    r"rounding\s*::|roundingmode|round_up|ceil_div|div_ceil)"
)

_ZERO_GUARD_TEMPLATE = (
    r"(?i)(?:"
    r"\b{p}\s*!=\s*0|"
    r"\b{p}\s*>\s*0|"
    r"0\s*<\s*\b{p}\b|"
    r"if\s+\b{p}\b\s*==\s*0|"
    r"if\s+\b{p}\b\s*<=\s*0|"
    r"ensure!\s*\([^;]*\b{p}\b\s*(?:>|!=)\s*0|"
    r"require!\s*\([^;]*\b{p}\b\s*(?:>|!=)\s*0|"
    r"assert!\s*\([^;]*\b{p}\b\s*(?:>|!=)\s*0|"
    r"NonZero(?:U|I)(?:8|16|32|64|128|size)::new\s*\(\s*\b{p}\b\s*\)"
    r")"
)

_DIV_FIRST_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,240}/[^;\n]{1,240}\)?"
    r"\s*\*\s*[^;\n]{1,240})\s*;",
    re.MULTILINE,
)

_METHOD_DIV_FIRST_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>[^;]{0,260}\.checked_div\s*\([^;]{1,180}\)"
    r"\??[^;]{0,180}\.checked_mul\s*\([^;]{1,180}\)\??)"
    r"\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,220}/[^;\n]{1,220}\)?)\s*;",
    re.MULTILINE,
)

_DIV_BY_PARAM_ASSIGN_TEMPLATE = (
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>[^;\n]{{1,240}}(?:/|%)\s*\b{p}\b[^;\n]{{0,160}})\s*;"
)

_DIRECT_DIV_BY_PARAM_TEMPLATE = r"(?P<expr>[^;\n{{}}]{{1,220}}(?:/|%)\s*\b{p}\b)"

_TRIPLE_MUL_RE = re.compile(
    r"(?i)("
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\s*\*\s*"
    r"[A-Za-z_][A-Za-z0-9_\.]*\s*\*\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_\.]*fee[A-Za-z0-9_]*|fee[A-Za-z0-9_]*|bps)"
    r"\s*/\s*[A-Za-z0-9_:\.]+|"
    r"\.wrapping_mul\s*\([^;]{1,120}\)[^;]{0,220}"
    r"\.wrapping_mul\s*\([^;]{1,120}\)[^;]{0,220}/|"
    r"\.checked_mul\s*\([^;]{1,160}\)\s*\.\s*unwrap\s*\(\s*\)"
    r"[^;]{0,220}\.checked_mul\s*\([^;]{1,160}\)"
    r")"
)

_CHECKED_PROPAGATES_RE = re.compile(
    r"checked_mul\s*\([^;]{1,180}\)\s*\?[^;]{0,260}"
    r"checked_(?:mul|div)\s*\([^;]{1,180}\)\s*\?"
)


def _numeric_params(fn, source: bytes) -> set[str]:
    names: set[str] = set()
    for child in fn.children:
        if child.type != "parameters":
            continue
        for param in child.children:
            if param.type != "parameter":
                continue
            raw = text_of(param, source)
            match = _PARAM_RE.search(raw)
            if not match:
                continue
            if _NUMERIC_TY_RE.search(match.group("ty")):
                names.add(match.group("name"))
    return names


def _mentions_any(text: str, names: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _value_params(names: set[str]) -> set[str]:
    return {name for name in names if _VALUE_PARAM_RE.search(name)}


def _has_value_context(name: str, body: str, params: set[str]) -> bool:
    if _VALUE_CONTEXT_RE.search(name) or _VALUE_CONTEXT_RE.search(body):
        return True
    return bool(_value_params(params))


def _has_state_sink(body: str, var: str, start: int) -> bool:
    tail = body[start : start + 1200]
    if not re.search(rf"\b{re.escape(var)}\b", tail):
        return False
    return bool(_STATE_SINK_RE.search(tail))


def _has_zero_guard(prefix: str, param: str) -> bool:
    regex = re.compile(_ZERO_GUARD_TEMPLATE.format(p=re.escape(param)))
    return bool(regex.search(prefix))


def _division_before_multiply_hit(body: str, params: set[str]) -> tuple[str, str] | None:
    if _SAFE_MATH_RE.search(body):
        return None
    value_params = _value_params(params)
    for regex in (_DIV_FIRST_ASSIGN_RE, _METHOD_DIV_FIRST_ASSIGN_RE):
        for match in regex.finditer(body):
            var = match.group("var")
            expr = match.group("expr")
            if not _mentions_any(expr, params):
                continue
            if not (
                _VALUE_CONTEXT_RE.search(var)
                or _VALUE_CONTEXT_RE.search(expr)
                or _mentions_any(expr, value_params)
            ):
                continue
            if _has_state_sink(body, var, match.end()):
                return "division before multiplication", var

    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        quotient = match.group("q")
        expr = match.group("expr")
        if not _mentions_any(expr, params):
            continue
        if not (
            _VALUE_CONTEXT_RE.search(quotient)
            or _VALUE_CONTEXT_RE.search(expr)
            or _mentions_any(expr, value_params)
        ):
            continue
        tail = body[match.end() : match.end() + 900]
        multiply_re = re.compile(
            rf"let\s+(?:mut\s+)?(?P<out>[A-Za-z_][A-Za-z0-9_]*)"
            rf"(?:\s*:\s*[^=;]+)?\s*=\s*[^;\n]{{0,200}}"
            rf"(?:\b{re.escape(quotient)}\b[^;\n]{{0,200}}\*|"
            rf"\*[^;\n]{{0,200}}\b{re.escape(quotient)}\b)"
            rf"[^;\n]{{0,200}};",
            re.MULTILINE,
        )
        multiplied = multiply_re.search(tail)
        if multiplied is None:
            continue
        out = multiplied.group("out")
        if _has_state_sink(body, out, match.end() + multiplied.end()):
            return "split quotient multiplied after floor rounding", out
    return None


def _division_by_user_denominator_hit(body: str, params: set[str]) -> tuple[str, str] | None:
    value_params = _value_params(params)
    for param in sorted(params):
        if not (_DENOM_PARAM_RE.search(param) or value_params):
            continue
        assign_re = re.compile(
            _DIV_BY_PARAM_ASSIGN_TEMPLATE.format(p=re.escape(param)),
            re.MULTILINE,
        )
        for match in assign_re.finditer(body):
            prefix = body[: match.start()]
            if _has_zero_guard(prefix, param):
                continue
            var = match.group("var")
            expr = match.group("expr")
            if not (
                _VALUE_CONTEXT_RE.search(var)
                or _VALUE_CONTEXT_RE.search(expr)
                or _mentions_any(expr, value_params)
            ):
                continue
            if _has_state_sink(body, var, match.end()):
                return "user-controlled denominator without non-zero guard", param

        direct_re = re.compile(
            _DIRECT_DIV_BY_PARAM_TEMPLATE.format(p=re.escape(param)),
            re.MULTILINE,
        )
        for match in direct_re.finditer(body):
            prefix = body[: match.start()]
            if _has_zero_guard(prefix, param):
                continue
            expr = match.group("expr")
            if not (
                _VALUE_CONTEXT_RE.search(expr)
                or _mentions_any(expr, value_params)
            ):
                continue
            after = body[match.end() : match.end() + 220]
            before = body[max(0, match.start() - 80) : match.start()]
            if "return" in before or re.search(r"^\s*[;\n\r}]+", after):
                return "user-controlled denominator without non-zero guard", param
    return None


def _intermediate_overflow_hit(body: str, params: set[str]) -> tuple[str, str] | None:
    if _SAFE_MATH_RE.search(body) or _CHECKED_PROPAGATES_RE.search(body):
        return None
    value_params = _value_params(params)
    for match in _TRIPLE_MUL_RE.finditer(body):
        expr = match.group(0)
        if not (_mentions_any(expr, params) or _VALUE_CONTEXT_RE.search(expr)):
            continue
        window = body[max(0, match.start() - 180) : match.end() + 280]
        if not (
            _VALUE_CONTEXT_RE.search(window)
            or _mentions_any(window, value_params)
        ):
            continue
        if _STATE_SINK_RE.search(body[match.end() : match.end() + 1200]):
            return "intermediate overflow-prone fee math", "fee_math"
        # Public helper return is still useful because callers often apply the
        # fee or PnL result to vault accounting.
        if re.search(r"(?i)\b(pnl|fee|price|position|vault)\b", window):
            return "intermediate overflow-prone fee math", "fee_math"
    return None


def _first_hit(name: str, body: str, params: set[str]) -> tuple[str, str] | None:
    if not params or not _has_value_context(name, body, params):
        return None
    return (
        _division_before_multiply_hit(body, params)
        or _division_by_user_denominator_hit(body, params)
        or _intermediate_overflow_hit(body, params)
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source) or not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        params = _numeric_params(fn, source)
        body_nc = body_text_nocomment(body, source)
        name = fn_name(fn, source)
        hit = _first_hit(name, body_nc, params)
        if hit is None:
            continue
        reason, subject = hit
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` performs user-controlled value math with "
                    f"{reason} around `{subject}` before vault, reward, fee, "
                    "share, or balance accounting. Use checked non-zero "
                    "denominators, multiply-before-divide, safe mul_div, and "
                    "explicit protocol-favorable rounding."
                ),
            }
        )
    return hits
