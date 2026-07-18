"""
rust_division_before_multiplication_fire28.py

Rust Fire28 recall lift for rounding-direction-attack.

Flags fixed-point, share, AMM, vault, reward, payout, or accounting math that
divides an integer numerator before multiplying by a scale, share, rate, or
precision factor. The detector is intentionally narrower than generic
division-before-multiplication: a candidate must have value context and the
rounded value must reach a payout, return value, or accounting sink.

Source refs:
  - reference/patterns.dsl.r76_glider/glider-division-before-multiplication-in-math-operations-py.yaml
  - reference/patterns.dsl.r94_solodit_rust/insufficient-intermediate-value-precision-in-stableswap-calculations.yaml
  - reference/patterns.dsl.r75_mined/c4_novel/withdrawable-per-share-division-before-multiplication.yaml
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
    r"(?i)(shares?|assets?|amount|tokens?|balances?|vault|accounting|"
    r"withdraw|withdrawable|redeem|preview|convert|payout|pay_|claim|"
    r"reward|rewards?|fee|fees?|protocol_fee|treasury|deposit|mint|burn|"
    r"supply|liquidity|lp_|lp\b|reserve|pool|amm|swap|stableswap|curve|"
    r"invariant|price|quote|"
    r"collateral|debt|borrow|repay|settle|seize)"
)

_STRONG_FN_RE = re.compile(
    r"(?i)(get_?withdrawable|withdrawable|preview_?(redeem|withdraw)|"
    r"convert_?to_?(assets|shares)|shares_?to_?assets|assets_?to_?shares|"
    r"calculate_?stableswap|calc_?stableswap|claim_?reward|settle_?fee|"
    r"redeem|withdraw|payout|distribute|accrue|mint|burn)"
)

_FACTOR_CONTEXT_RE = re.compile(
    r"(?i)(shares?|user_?shares|share_?amount|assets?|amount|scale|"
    r"precision|rate|bps|basis|wad|ray|price|quote|liquidity|lp_|lp\b|"
    r"reserve|pool|amp|coefficient|reward|fee|payout|collateral|debt)"
)

_VALUE_SINK_RE = re.compile(
    r"(?i)(transfer|mint|burn|credit|debit|withdraw|redeem|repay|borrow|"
    r"seize|payout|pay_|release|settle|distribute|claim|insert\s*\(|"
    r"push\s*\(|entry\s*\(|set\s*\(|Ok\s*\(|return\s+|"
    r"self\.[A-Za-z0-9_]*(?:fee|reward|share|asset|balance|supply|"
    r"liquidity|reserve|payout|collateral|debt|amount|pool)[A-Za-z0-9_]*"
    r"\s*(?:\+=|-=|=)|balances?\.|rewards?\.|positions?\.|reserves?\.|"
    r"collateral_out\.|debt_shares\.|\+=|-=)"
)

_FULL_PRECISION_RE = re.compile(
    r"(?i)(mul_div|muldiv|full_?precision|multiply_ratio|"
    r"checked_multiply_ratio|checked_mul_div|mul_floor|mul_ceil|"
    r"Uint512|U512|I512|u512|i512|Uint256|U256|I256|u256|i256|"
    r"BigUint|BigInt|FixedU128|FixedI128|fixed_point|Decimal|"
    r"Perbill|Permill|Ratio::|checked_fixed)"
)

_CHECKED_MUL_BEFORE_DIV_RE = re.compile(
    r"(?is)checked_mul\s*\([^;]{0,260}\)\s*\??[^;]{0,260}"
    r"\.checked_div\s*\("
)

_ZERO_VALUE_REJECT_RE = re.compile(
    r"(?is)(ensure!\s*\([^;]*(?:payout|share|asset|reward|fee|amount)"
    r"[^;]*>\s*0|require!\s*\([^;]*(?:payout|share|asset|reward|fee|amount)"
    r"[^;]*>\s*0|if\s+[A-Za-z_][A-Za-z0-9_]*\s*==\s*0\s*\{"
    r"\s*return\s+Err)"
)

_IDENT_EXPR = r"[A-Za-z_][A-Za-z0-9_:\.]*"
_TERM = rf"(?:{_IDENT_EXPR}|\d[\d_]*)(?:\s+as\s+{_IDENT_EXPR})?"

_DIRECT_OPERATOR_RE = re.compile(
    rf"(?P<prefix>let\s+(?:mut\s+)?|self\.)"
    rf"(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    rf"(?:\s*:\s*[^=;]+)?\s*=\s*"
    rf"(?P<expr>\(?\s*{_TERM}\s*/\s*{_TERM}\s*\)?\s*\*\s*{_TERM})"
    rf"\s*;",
    re.MULTILINE,
)

_METHOD_DIV_FIRST_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>[^;]{0,260}\.checked_div\s*\([^;]{1,180}\)\s*\??"
    r"[^;]{0,220}\.checked_mul\s*\([^;]{1,180}\)\??)"
    r"\s*;",
    re.MULTILINE,
)

_QUOTIENT_ASSIGN_RE = re.compile(
    rf"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    rf"(?:\s*:\s*[^=;]+)?\s*=\s*"
    rf"(?P<expr>\(?\s*{_TERM}\s*/\s*{_TERM}\s*\)?)\s*;",
    re.MULTILINE,
)

_MUL_WITH_QUOTIENT_RE_TEMPLATE = (
    r"let\s+(?:mut\s+)?(?P<out>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>(?:[^;\n]{{0,200}}\b{q}\b[^;\n]{{0,200}}\*"
    r"|[^;\n]{{0,200}}\*[^;\n]{{0,200}}\b{q}\b)"
    r"[^;\n]{{0,200}})\s*;"
)


def _has_value_context(name: str, body: str) -> bool:
    return bool(_VALUE_CONTEXT_RE.search(name) or _VALUE_CONTEXT_RE.search(body))


def _is_candidate_function(fn_node, name: str, body: str, source: bytes) -> bool:
    if is_pub(fn_node, source):
        return True
    return bool(_STRONG_FN_RE.search(name) or _STRONG_FN_RE.search(body))


def _safe_near(body: str, start: int, end: int) -> bool:
    window = body[max(0, start - 220) : min(len(body), end + 300)]
    return bool(
        _FULL_PRECISION_RE.search(window)
        or _CHECKED_MUL_BEFORE_DIV_RE.search(window)
        or _ZERO_VALUE_REJECT_RE.search(window)
    )


def _has_value_sink(body: str, var: str, start: int) -> bool:
    window = body[start : start + 1100]
    if not re.search(rf"\b{re.escape(var)}\b", window):
        return False
    if _VALUE_SINK_RE.search(window):
        return True
    return bool(
        re.search(rf"(?m)\b(?:return\s+)?{re.escape(var)}\s*;?\s*\}}", window)
    )


def _direct_hit(body: str) -> tuple[str, str] | None:
    for regex, reason in (
        (_DIRECT_OPERATOR_RE, "operator division before multiplying by a factor"),
        (_METHOD_DIV_FIRST_RE, "checked_div before checked_mul factor math"),
    ):
        for match in regex.finditer(body):
            if _safe_near(body, match.start(), match.end()):
                continue
            var = match.group("var")
            expr = match.group("expr")
            if not (
                _VALUE_CONTEXT_RE.search(var)
                or _VALUE_CONTEXT_RE.search(expr)
                or _FACTOR_CONTEXT_RE.search(expr)
            ):
                continue
            if _has_value_sink(body, var, match.end()):
                return reason, var
    return None


def _split_quotient_hit(body: str) -> tuple[str, str] | None:
    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        if _safe_near(body, match.start(), match.end()):
            continue
        quotient = match.group("q")
        quotient_expr = match.group("expr")
        if not (
            _VALUE_CONTEXT_RE.search(quotient)
            or _VALUE_CONTEXT_RE.search(quotient_expr)
            or _FACTOR_CONTEXT_RE.search(quotient)
            or _FACTOR_CONTEXT_RE.search(quotient_expr)
        ):
            continue

        tail = body[match.end() : match.end() + 900]
        mul_re = re.compile(
            _MUL_WITH_QUOTIENT_RE_TEMPLATE.format(q=re.escape(quotient)),
            re.MULTILINE,
        )
        multiplied = mul_re.search(tail)
        if multiplied is None:
            continue

        absolute_start = match.end() + multiplied.start()
        absolute_end = match.end() + multiplied.end()
        if _safe_near(body, absolute_start, absolute_end):
            continue

        out = multiplied.group("out")
        mul_expr = multiplied.group("expr")
        if not (
            _VALUE_CONTEXT_RE.search(out)
            or _VALUE_CONTEXT_RE.search(mul_expr)
            or _FACTOR_CONTEXT_RE.search(mul_expr)
        ):
            continue
        if _has_value_sink(body, out, match.end() + multiplied.end()):
            return "split quotient multiplied after floor rounding", out
    return None


def _first_hit(name: str, body: str) -> tuple[str, str] | None:
    if not _has_value_context(name, body):
        return None
    return _direct_hit(body) or _split_quotient_hit(body)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _is_candidate_function(fn, name, body_nc, source):
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
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub/accounting fn `{name}` computes `{value}` with "
                    f"{reason}. Divide-first integer math can truncate the "
                    "intermediate before applying scale, share, rate, or "
                    "precision factors in value-moving Rust math."
                ),
            }
        )
    return hits
