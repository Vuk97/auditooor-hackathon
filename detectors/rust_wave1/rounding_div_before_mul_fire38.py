"""
rounding_div_before_mul_fire38.py

Rust Fire38 lift for rounding-direction-attack and precision-loss value math.

Rule 37 provenance:
- verification_tier: tier-3-synthetic-taxonomy-anchored
- context_pack_id: auditooor.vault_context_pack.v1:resume:d13bd9d230bee9a9
- context_pack_hash: d13bd9d230bee9a9be7b0163da353a019de15118dc6e4d3986c543a54d28abff
- source ref: reports/detector_lift_fire37_20260605/post_priorities_rust.md
- source ref: detectors/rust_wave1/rounding_redeem_fee_direction_fire37.py
- source ref: detectors/rust_wave1/rounding_div_before_mul_fire34.py
- source ref: detectors/rust_wave1/r94_loop_field_modulus_timestamp_overflow.py
- source ref: reference/patterns.dsl/precision_loss_rounding_error.yaml
  (requested source ref absent in this worktree)
- source ref: reference/patterns.dsl/mul-after-div-precision-loss.yaml
- attack_class: rounding-direction-attack

Flags public Rust financial math that divides before multiplying, floors fee
or share math in a caller-favorable direction before a value-moving sink, or
clamps field and timestamp arithmetic only after unchecked overflow-sensitive
operations.

Detector hits are source-review candidates only. R40 and R80 proof still
require a real in-scope PoC before any finding can cite the result.
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


DETECTOR_ID = "rust_wave1.rounding_div_before_mul_fire38"

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

_REMAINDER_REJECT_RE = re.compile(
    r"(?is)(?:if|ensure!|require!|assert!)\s*(?=[^{;]{0,520}"
    r"(?:%|checked_rem|rem_euclid))(?=[^{;]{0,520}"
    r"(?:!=\s*0|>\s*0|<\s*0|non_exact|exact|remainder))"
    r"[^{;]{0,520}(?:return\s+Err|Err\s*\(|panic!|None|false)"
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

_FLOOR_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>(?:[^;\n]{1,220}/[^;\n]{1,220}|"
    r"[^;]{0,220}\.checked_div\s*\([^;]{1,180}\)\s*\??))\s*;",
    re.MULTILINE,
)

_SINK_CALLS = (
    r"transfer|mint|burn|credit|debit|charge|collect|withdraw|redeem|repay|"
    r"borrow|seize|payout|release|settle|distribute|claim|liquidate|"
    r"health|solv|margin|insert|entry|set"
)

_OUTGOING_CALL_TEMPLATE = (
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:transfer|send|credit|pay|payout|withdraw|redeem|release|settle|"
    r"distribute|claim)[A-Za-z0-9_:\.]*\s*\("
    r"(?=[^;{}]{0,620}\b{alias}\b)[^;{}]{0,620}\)"
)

_BURN_OR_DEBIT_TEMPLATE = (
    r"(?is)\b[A-Za-z_][A-Za-z0-9_:\.]*"
    r"(?:burn|debit|deduct|take|pull|sub|remove|charge)"
    r"[A-Za-z0-9_:\.]*\s*\("
    r"(?=[^;{}]{0,620}\b{alias}\b)[^;{}]{0,620}\)"
)

_NET_SUB_TEMPLATE = (
    r"(?is)\blet\s+(?:mut\s+)?(?P<net>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*[^;{}]{0,260}"
    r"(?:checked_sub\s*\(\s*{fee}\s*\)|-\s*{fee}\b)[^;{}]{0,260};"
)

_FEE_ALIAS_RE = re.compile(r"(?i)(fee|fees|commission|surcharge)")
_SHARE_ALIAS_RE = re.compile(r"(?i)(share|shares|burn)")

_FIELD_CONTEXT_RE = re.compile(
    r"(?i)(BabyBear|Goldilocks|Pallas|Mersenne|field::|Fp::|F::|MODULUS|"
    r"FIELD_ORDER|field_modulus|to_canonical|wrap_into_field)"
)

_FIELD_COUNTER_RE = re.compile(
    r"(?i)(timestamp|clock|counter|step_counter|slot|epoch|nonce|height)"
)

_FIELD_UNCHECKED_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*(?P<expr>[^;]{0,220}"
    r"(?:timestamp|clock|counter|step_counter|slot|epoch|nonce|height)"
    r"[^;]{0,220}(?:\+|\*|-)[^;]{0,220});",
    re.IGNORECASE | re.MULTILINE,
)

_FIELD_DIRECT_MUTATION_RE = re.compile(
    r"(?i)\b(?:timestamp|clock|counter|step_counter|slot|epoch|nonce|height)"
    r"\s*(?:\+=|\*=|-=)"
)

_CHECKED_ARITH_RE = re.compile(
    r"(?i)(checked_add|checked_mul|checked_sub|saturating_add|"
    r"saturating_mul|saturating_sub|overflowing_add|overflowing_mul)"
)

_FIELD_BOUND_RE = re.compile(
    r"(?is)(?:assert!|ensure!|require!|if)\s*\([^;{}]{0,520}"
    r"(?:MODULUS|FIELD_ORDER|field_modulus)[^;{}]{0,520}"
    r"(?:return\s+Err|Err\s*\(|panic!|None|false)?"
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
    window = body[max(0, start - 420) : min(len(body), end + 420)]
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


def _compile_alias(template: str, **aliases: str) -> re.Pattern[str]:
    text = template
    for key, value in aliases.items():
        text = text.replace("{" + key + "}", re.escape(value))
    return re.compile(text)


def _has_value_sink(body: str, var: str, start: int) -> bool:
    tail = body[start : start + 1500]
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


def _has_outgoing_sink(tail: str, alias: str) -> bool:
    return bool(_compile_alias(_OUTGOING_CALL_TEMPLATE, alias=alias).search(tail[:1700]))


def _has_burn_or_debit_sink(tail: str, alias: str) -> bool:
    return bool(_compile_alias(_BURN_OR_DEBIT_TEMPLATE, alias=alias).search(tail[:1400]))


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

            tail = body[match.end() : match.end() + 1000]
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


def _fee_or_share_floor_hit(
    body: str,
    params: set[str],
    fn_text: str,
) -> tuple[str, str] | None:
    for match in _FLOOR_ASSIGN_RE.finditer(body):
        if _safe_near(body, match.start(), match.end()):
            continue
        alias = match.group("var")
        expr = match.group("expr")
        numerator = _floor_numerator_var(expr)
        if numerator and _local_var_derived_from_mul(body[: match.start()], numerator):
            continue
        if not _has_attacker_operand(expr, params, fn_text):
            continue

        tail = body[match.end() :]
        if _FEE_ALIAS_RE.search(alias):
            net_match = _compile_alias(_NET_SUB_TEMPLATE, fee=alias).search(tail[:1200])
            if net_match is not None:
                net_alias = net_match.group("net")
                after_net = tail[net_match.end() :]
                if _has_outgoing_sink(after_net, net_alias):
                    return "floor-rounded fee is subtracted before caller payout", alias

        if _SHARE_ALIAS_RE.search(alias):
            if _has_burn_or_debit_sink(tail, alias) and _has_outgoing_sink(tail, "requested_assets"):
                return "floor-rounded shares are burned before requested assets leave", alias
            if _has_burn_or_debit_sink(tail, alias) and re.search(
                r"(?is)\b(?:transfer|send|withdraw|redeem|release|payout)"
                r"[A-Za-z0-9_:\.]*\s*\([^;{}]{0,620}"
                r"(?:asset|assets|amount|payout|out|requested)",
                tail[:1700],
            ):
                return "floor-rounded shares are burned before assets leave", alias
    return None


def _field_clamp_after_unchecked_hit(
    body: str,
    source_head: str,
) -> tuple[str, str] | None:
    if not _FIELD_CONTEXT_RE.search(source_head + "\n" + body):
        return None

    for match in _FIELD_UNCHECKED_ASSIGN_RE.finditer(body):
        var = match.group("var")
        expr = match.group("expr")
        window = body[max(0, match.start() - 420) : min(len(body), match.end() + 900)]
        if _CHECKED_ARITH_RE.search(window):
            continue
        if _FIELD_BOUND_RE.search(window):
            continue
        tail = body[match.end() : match.end() + 900]
        escaped = re.escape(var)
        if re.search(rf"(?is)\b{escaped}\b\s*\.\s*(?:min|max|clamp)\s*\(", tail):
            return "unchecked field or timestamp arithmetic is clamped only after overflow risk", var
        if re.search(rf"(?is)\b{escaped}\b\s*%\s*(?:MODULUS|FIELD_ORDER|field_modulus)", tail):
            return "unchecked field or timestamp arithmetic is reduced only after overflow risk", var
        if re.search(rf"(?is)(?:Ok|Some|return)\s*\(?[^;{{}}]*\b{escaped}\b", tail):
            return "unchecked field or timestamp arithmetic reaches a return path", var

    if _FIELD_DIRECT_MUTATION_RE.search(body):
        if not _CHECKED_ARITH_RE.search(body) and not _FIELD_BOUND_RE.search(body):
            return "direct field or timestamp counter mutation lacks checked arithmetic", "counter"
    return None


def _first_hit(
    name: str,
    body: str,
    params: set[str],
    fn_text: str,
    source_head: str,
) -> tuple[str, str] | None:
    field_hit = _field_clamp_after_unchecked_hit(body, source_head)
    if field_hit is not None:
        return field_hit
    if not params:
        return None
    if not _has_value_context(name, body):
        return None
    return (
        _direct_hit(body, params, fn_text)
        or _split_hit(body, params, fn_text)
        or _fee_or_share_floor_hit(body, params, fn_text)
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    source_head = source[:8000].decode("utf8", errors="replace")
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
        hit = _first_hit(name, body_nc, params, fn_text, source_head)
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
                    f"`{name}` computes caller-influenced `{value}` with "
                    f"{reason}. This can favor the caller through truncated "
                    "fee, share, reward, or field arithmetic. Use explicit "
                    "mul-div, a documented rounding mode, remainder rejection, "
                    "or checked arithmetic before any value sink. (class: "
                    "rounding-direction-attack; posture: NOT_SUBMIT_READY)"
                ),
            }
        )
    return hits
