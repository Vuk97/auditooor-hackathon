"""
rounding_div_before_mul_fire34.py

Rust Fire34 lift for rounding-direction-attack.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:bfadc3c938400bc6
- context_pack_hash: bfadc3c938400bc6618f7f3ae8d500bbc8e5dce19f7f4e6c043195ffc6742129
- source ref: reports/detector_lift_fire33_20260605/post_priorities_rust.md
- source ref: reference/patterns.dsl/rounding-direction-attack.yaml
- source ref: detectors/rust_wave1/rust_share_math_division_before_multiplication_value_loss.py
- source ref: detectors/go_wave1/go-rounding-direction-fee-fire32.py
- attack_class: rounding-direction-attack

Flags public Rust value math where an attacker-controlled numeric operand is
floored by division before a multiplier, or floored directly in fee, share,
reward, or liquidation math, before the result reaches a transfer, state
write, solvency check, or return path.

This is detector-fixture evidence only. NOT_SUBMIT_READY.
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


DETECTOR_ID = "rust_wave1.rounding_div_before_mul_fire34"

_NUMERIC_TY_RE = re.compile(
    r"(?i)\b(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|"
    r"u256|u512|i256|i512|uint128|uint256|balance|amount)\b"
)

_PARAM_RE = re.compile(
    r"^\s*(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?:&\s*(?:mut\s+)?)?(?P<ty>[A-Za-z_][A-Za-z0-9_:<>]*)"
)

_VALUE_CONTEXT_RE = re.compile(
    r"(?i)(fee|fees|share|shares|reward|rewards|liquidat|penalty|haircut|"
    r"debt|borrow|repay|repayment|collateral|margin|health|solv|vault|"
    r"fund|reserve|payout|claim|withdraw|redeem|deposit|mint|burn|"
    r"notional|amount|assets|tokens|balance|position|liquidity|lp_|bps)"
)

_STRONG_FN_RE = re.compile(
    r"(?i)(fee|claim|reward|withdraw|redeem|deposit|mint|burn|borrow|repay|"
    r"liquidat|settle|payout|preview|convert|health|solv|margin)"
)

_ATTACKER_PARAM_RE = re.compile(
    r"(?i)(user|caller|sender|payer|borrower|trader|liquidator|withdrawer|"
    r"recipient|delegator|operator|owner|account|position|pos|amount|"
    r"notional|shares?|assets?|tokens?|debt|collateral|liquidity|reward|"
    r"claim|denom|denominator|divisor|parts|count|weight|bps|rate|factor)"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?i)(mul_div|muldiv|checked_mul_div|safe_mul_div|multiply_ratio|"
    r"checked_multiply_ratio|full_?precision|fixedu?128|fixedi?128|"
    r"fixed_point|decimal|perbill|permill|ratio::|round_up|rounding\s*::|"
    r"ceil_div|div_ceil|mul_ceil|roundingmode)"
)

_MUL_BEFORE_DIV_RE = re.compile(
    r"(?is)checked_mul\s*\([^;]{0,260}\)\s*\??[^;]{0,260}"
    r"\.checked_div\s*\(|\([^;\n]{1,180}\*[^;\n]{1,180}\)\s*/"
)

_SINK_CALLS = (
    r"transfer|mint|burn|credit|debit|charge|collect|withdraw|redeem|repay|"
    r"borrow|seize|payout|release|settle|distribute|claim|liquidate|"
    r"health|solv|margin|insert|entry|set"
)

_TERM = (
    r"(?:[A-Za-z_][A-Za-z0-9_:\.]*|\d[\d_]*)"
    r"(?:\s+as\s+[A-Za-z_][A-Za-z0-9_:<>]*)?"
)

_DIRECT_DIV_FIRST_RE = re.compile(
    rf"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    rf"(?:\s*:\s*[^=;]+)?\s*=\s*"
    rf"(?P<expr>\(?\s*{_TERM}\s*/\s*{_TERM}\s*\)?\s*\*\s*{_TERM})"
    rf"\s*;",
    re.MULTILINE,
)

_METHOD_DIV_FIRST_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>[^;]{0,280}\.checked_div\s*\([^;]{1,180}\)\s*\??"
    r"[^;]{0,240}\.checked_mul\s*\([^;]{1,180}\)\s*\??)"
    r"\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    rf"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    rf"(?:\s*:\s*[^=;]+)?\s*=\s*"
    rf"(?P<expr>\(?\s*{_TERM}\s*/\s*{_TERM}\s*\)?)\s*;",
    re.MULTILINE,
)

_CHECKED_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>[^;]{0,220}\.checked_div\s*\([^;]{1,180}\)\s*\??)"
    r"\s*;",
    re.MULTILINE,
)

_MUL_WITH_QUOTIENT_TEMPLATE = (
    r"let\s+(?:mut\s+)?(?P<out>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>(?:[^;\n]{{0,220}}\b{q}\b[^;\n]{{0,220}}\*|"
    r"[^;\n]{{0,220}}\*[^;\n]{{0,220}}\b{q}\b)"
    r"[^;\n]{{0,220}})\s*;"
)

_FLOOR_ONLY_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>(?:[^;\n]{1,220}/[^;\n]{1,220}|"
    r"[^;]{0,220}\.checked_div\s*\([^;]{1,180}\)\s*\??))\s*;",
    re.MULTILINE,
)

_REMAINDER_REJECT_RE = re.compile(
    r"(?is)(?:if|ensure!|require!|assert!)\s*[^{;]{0,360}%[^{;]{0,360}"
    r"(?:!=\s*0|>\s*0|<\s*0)[^{;]{0,260}"
    r"(?:return\s+Err|Err\s*\(|panic!|false)"
)


def _numeric_params(fn, source: bytes) -> set[str]:
    names: set[str] = set()
    for child in fn.children:
        if child.type != "parameters":
            continue
        for param in child.children:
            if param.type != "parameter":
                continue
            match = _PARAM_RE.search(text_of(param, source))
            if match and _NUMERIC_TY_RE.search(match.group("ty")):
                names.add(match.group("name"))
    return names


def _mentions_name(text: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\b", text))


def _has_attacker_operand(expr: str, params: set[str], fn_text: str) -> bool:
    for param in params:
        if not _mentions_name(expr, param):
            continue
        if _ATTACKER_PARAM_RE.search(param):
            return True
        if re.search(r"(?i)(user|caller|sender|borrower|liquidator|withdrawer)", fn_text):
            return True
    return False


def _has_value_context(name: str, body: str, expr: str = "") -> bool:
    return bool(
        _VALUE_CONTEXT_RE.search(name)
        or _VALUE_CONTEXT_RE.search(body)
        or _VALUE_CONTEXT_RE.search(expr)
    )


def _safe_near(body: str, start: int, end: int) -> bool:
    window = body[max(0, start - 300) : min(len(body), end + 360)]
    return bool(
        _SAFE_ROUNDING_RE.search(window)
        or _MUL_BEFORE_DIV_RE.search(window)
        or _REMAINDER_REJECT_RE.search(window)
    )


def _floor_numerator_var(expr: str) -> str | None:
    method_match = re.search(
        r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\.checked_div\s*\(",
        expr,
    )
    if method_match:
        return method_match.group("var")
    operator_match = re.search(
        r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\b\s*/",
        expr,
    )
    if operator_match:
        return operator_match.group("var")
    return None


def _local_var_derived_from_mul(prefix: str, var: str) -> bool:
    return bool(
        re.search(
            rf"let\s+(?:mut\s+)?{re.escape(var)}"
            rf"(?:\s*:\s*[^=;]+)?\s*=\s*[^;]{{0,260}}"
            rf"(?:checked_mul\s*\(|\*)[^;]{{0,260}};",
            prefix[-1200:],
            re.IGNORECASE | re.DOTALL,
        )
    )


def _has_value_sink(body: str, var: str, start: int) -> bool:
    tail = body[start : start + 1300]
    escaped = re.escape(var)
    sink_patterns = (
        rf"(?is)\b(?:{_SINK_CALLS})[A-Za-z0-9_]*\s*\([^;{{}}]*\b{escaped}\b",
        rf"(?is)\b(?:Ok|Some)\s*\([^;{{}}]*\b{escaped}\b",
        rf"(?is)\breturn\s+[^;{{}}]*\b{escaped}\b",
        rf"(?is)(?:self|state|vault|pool|market|ledger|account|position)\."
        rf"[A-Za-z0-9_]*(?:fee|reward|share|asset|balance|debt|collateral|"
        rf"reserve|fund|liquidity|payout|margin|health|solv|position)"
        rf"[A-Za-z0-9_]*\s*(?:\+=|-=|=)\s*[^;\n{{}}]*\b{escaped}\b",
        rf"(?is)(?:\+=|-=)\s*[^;\n{{}}]*\b{escaped}\b",
    )
    return any(re.search(pattern, tail) for pattern in sink_patterns)


def _direct_hit(body: str, params: set[str], fn_text: str) -> tuple[str, str] | None:
    for regex, reason in (
        (_DIRECT_DIV_FIRST_RE, "operator division before multiplication"),
        (_METHOD_DIV_FIRST_RE, "checked_div before checked_mul"),
    ):
        for match in regex.finditer(body):
            if _safe_near(body, match.start(), match.end()):
                continue
            var = match.group("var")
            expr = match.group("expr")
            if not _has_attacker_operand(expr, params, fn_text):
                continue
            if not (_VALUE_CONTEXT_RE.search(var) or _VALUE_CONTEXT_RE.search(expr)):
                continue
            if _has_value_sink(body, var, match.end()):
                return reason, var
    return None


def _split_hit(body: str, params: set[str], fn_text: str) -> tuple[str, str] | None:
    for regex in (_QUOTIENT_ASSIGN_RE, _CHECKED_QUOTIENT_ASSIGN_RE):
        for match in regex.finditer(body):
            if _safe_near(body, match.start(), match.end()):
                continue
            quotient = match.group("q")
            quotient_expr = match.group("expr")
            if not _has_attacker_operand(quotient_expr, params, fn_text):
                continue
            if not (
                _VALUE_CONTEXT_RE.search(quotient)
                or _VALUE_CONTEXT_RE.search(quotient_expr)
            ):
                continue

            tail = body[match.end() : match.end() + 900]
            mul_re = re.compile(
                _MUL_WITH_QUOTIENT_TEMPLATE.format(q=re.escape(quotient)),
                re.MULTILINE,
            )
            multiplied = mul_re.search(tail)
            if multiplied is None:
                continue
            out = multiplied.group("out")
            expr = multiplied.group("expr")
            if not (_VALUE_CONTEXT_RE.search(out) or _VALUE_CONTEXT_RE.search(expr)):
                continue
            if _has_value_sink(body, out, match.end() + multiplied.end()):
                return "split quotient multiplied after floor division", out
    return None


def _floor_only_hit(body: str, params: set[str], fn_text: str) -> tuple[str, str] | None:
    for match in _FLOOR_ONLY_RE.finditer(body):
        if _safe_near(body, match.start(), match.end()):
            continue
        var = match.group("var")
        expr = match.group("expr")
        numerator = _floor_numerator_var(expr)
        if numerator and _local_var_derived_from_mul(body[: match.start()], numerator):
            continue
        if not _has_attacker_operand(expr, params, fn_text):
            continue
        if not (_VALUE_CONTEXT_RE.search(var) or _VALUE_CONTEXT_RE.search(expr)):
            continue
        if _has_value_sink(body, var, match.end()):
            return "floor division reaches value math sink", var
    return None


def _first_hit(name: str, body: str, params: set[str], fn_text: str) -> tuple[str, str] | None:
    if not params:
        return None
    if not _has_value_context(name, body):
        return None
    return (
        _direct_hit(body, params, fn_text)
        or _split_hit(body, params, fn_text)
        or _floor_only_hit(body, params, fn_text)
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
        fn_text = text_of(fn, source)
        params = _numeric_params(fn, source)
        hit = _first_hit(name, body_nc, params, fn_text)
        if hit is None:
            continue

        reason, value = hit
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source, max_len=220),
                "message": (
                    f"`{name}` computes attacker-influenced `{value}` with "
                    f"{reason} before a fee, share, reward, liquidation, or "
                    "accounting sink. Floor rounding can favor the caller; "
                    "use explicit mul-div or a documented rounding mode. "
                    "(class: rounding-direction-attack)"
                ),
            }
        )
    return hits
