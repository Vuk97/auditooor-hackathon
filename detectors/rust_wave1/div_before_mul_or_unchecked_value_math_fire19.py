"""
div_before_mul_or_unchecked_value_math_fire19.py

Rust recall lift for rounding-direction-attack value math.

Flags public value-moving Rust functions when they use one of three shapes:
  1. division before multiplication in swap, vault, reward, or accounting math,
  2. unchecked, wrapping, saturating, or unwrap-default arithmetic in value math,
  3. swap/exchange calls without explicit minimum-output protection.

Detector hits are candidate evidence only. Generic arithmetic without value
context is intentionally ignored.
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
    walk_no_nested_fn,
)


_VALUE_CONTEXT_RE = re.compile(
    r"(?i)(amount|amount_in|amount_out|min_out|min_return|slippage|swap|"
    r"exchange|shares?|assets?|tokens?|balances?|vault|account|accounting|"
    r"reserves?|liquidity|lp_|lp\b|collateral|debt|borrow|repay|reward|"
    r"payout|fee|fees|withdraw|redeem|deposit|mint|burn|position|supply|"
    r"settle|seize|price|quote)"
)

_CONTRACT_CONTEXT_RE = re.compile(
    r"(?i)(soroban_sdk|contractimpl|anchor_lang|cosmwasm_std|near_sdk|"
    r"frame_support|pallet::|#\s*\[\s*program\s*\])"
)

_SAFE_MATH_RE = re.compile(
    r"(?i)(mul_div|muldiv|checked_mul\s*\([^;]{0,220}\)\s*\?"
    r"[^;]{0,220}checked_div\s*\([^;]{0,220}\)\s*\?|"
    r"fixedu?128|fixedi?128|fixed_point|decimal|perbill|permill|"
    r"ratio::|rounding\s*::|roundingmode|ceil_div|div_ceil|round_up)"
)

_DIV_BEFORE_MUL_RE = re.compile(
    r"(?P<expr>\(?\b[A-Za-z_][A-Za-z0-9_\.]*\b\s*/\s*"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\b\)?\s*\*\s*"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\b)",
    re.MULTILINE,
)

_CHECKED_DIV_THEN_MUL_RE = re.compile(
    r"(?i)\.checked_div\s*\([^;]{1,180}\)\s*\??[^;]{0,120}"
    r"\.checked_mul\s*\([^;]{1,180}\)"
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,180}/[^;\n]{1,180}\)?)\s*;",
    re.MULTILINE,
)

_MUL_WITH_QUOTIENT_RE_TEMPLATE = (
    r"let\s+(?:mut\s+)?(?P<out>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*[^;\n]{0,180}\b%s\b"
    r"[^;\n]{0,180}\*\s*[^;\n]{0,180};"
)

_UNSAFE_ARITH_RE = re.compile(
    r"(?i)("
    r"\.\s*wrapping_(?:add|sub|mul|div|shl|shr)\s*\("
    r"|unchecked\s*\{"
    r"|\.\s*saturating_(?:add|sub|mul)\s*\("
    r"|checked_(?:add|sub|mul|div)\s*\([^;]{1,180}\)\s*"
    r"\.\s*unwrap_or(?:_default)?\s*\("
    r")"
)

_SAFE_DISPOSITION_RE = re.compile(
    r"(?i)(ok_or|ok_or_else|return\s+Err|Err\s*\(|map_err|try_from|"
    r"checked_(?:add|sub|mul|div)\s*\([^;]{1,220}\)\s*\?|"
    r"require!\s*\(|ensure!\s*\(|assert!\s*\([^;]{0,220}"
    r"(?:min_out|min_return|slippage)[^;]{0,220}(?:>|>=))"
)

_SWAP_METHOD_RE = re.compile(
    r"(?i)^(swap|swap_exact_in|swap_exact_out|swap_exact_tokens|exact_input|"
    r"exact_output|path_swap|exchange|exchange_exact_in|execute_swap)$"
)

_LOOSE_SWAP_METHOD_RE = re.compile(r"(?i)^(swap_|exchange_)")

_REJECT_METHOD_PREFIXES = (
    "get_",
    "set_",
    "is_",
    "validate_",
    "check_",
    "read_",
    "load_",
    "store_",
    "update_",
    "quote_",
)

_REJECT_METHOD_CONTAINS = (
    "config",
    "factory",
    "reserve",
    "whitelist",
    "handler",
    "health",
)

_MIN_OUT_RE = re.compile(
    r"(?i)\b(min_amount_out|min_out|min_return|min_swap_output|"
    r"minimum_out|min_received|slippage|price_limit|sqrt_price_limit)\b"
)

_ZERO_OR_UNBOUNDED_RE = re.compile(
    r"(?i)(?:^|[&\s:=,(])(0(?:u128|i128|_u128|_i128)?|i128::MIN|"
    r"u128::MIN|U256::ZERO|None)\b"
)


def _has_value_context(name: str, body: str, source_text: str) -> bool:
    if _VALUE_CONTEXT_RE.search(name) or _VALUE_CONTEXT_RE.search(body):
        return True
    return bool(_CONTRACT_CONTEXT_RE.search(source_text))


def _division_before_mul_reason(body: str) -> str | None:
    if _SAFE_MATH_RE.search(body):
        return None
    div_hit = _DIV_BEFORE_MUL_RE.search(body) or _CHECKED_DIV_THEN_MUL_RE.search(body)
    if div_hit:
        if _VALUE_CONTEXT_RE.search(div_hit.group(0)) or _VALUE_CONTEXT_RE.search(body):
            return "division before multiplication in value math"

    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        quotient = match.group("q")
        if not (_VALUE_CONTEXT_RE.search(quotient) or _VALUE_CONTEXT_RE.search(match.group("expr"))):
            continue
        tail = body[match.end() : match.end() + 700]
        mul_re = re.compile(
            _MUL_WITH_QUOTIENT_RE_TEMPLATE % re.escape(quotient),
            re.MULTILINE,
        )
        multiplied = mul_re.search(tail)
        if multiplied is not None and _VALUE_CONTEXT_RE.search(multiplied.group(0)):
            return "division before multiplication in value math"
    return None


def _unchecked_arith_reason(body: str, source_text: str) -> str | None:
    if not _UNSAFE_ARITH_RE.search(body):
        return None
    if _SAFE_DISPOSITION_RE.search(body):
        return None
    if not (_VALUE_CONTEXT_RE.search(body) or _CONTRACT_CONTEXT_RE.search(source_text)):
        return None
    return "unchecked arithmetic in value math"


def _method_name(call_node, source: bytes) -> str | None:
    callee = None
    for child in call_node.children:
        if child.type == "field_expression":
            callee = child
            break
    if callee is not None:
        method = None
        for child in callee.children:
            if child.type == "field_identifier":
                method = text_of(child, source)
        return method

    for child in call_node.children:
        if child.type in ("identifier", "scoped_identifier"):
            return text_of(child, source).split("::")[-1]
    return None


def _arguments_text(call_node, source: bytes) -> str:
    for child in call_node.children:
        if child.type == "arguments":
            return text_of(child, source)
    return ""


def _is_swap_method(method: str) -> bool:
    lowered = method.lower()
    if any(lowered.startswith(prefix) for prefix in _REJECT_METHOD_PREFIXES):
        return False
    if any(piece in lowered for piece in _REJECT_METHOD_CONTAINS):
        return False
    return bool(_SWAP_METHOD_RE.match(method) or _LOOSE_SWAP_METHOD_RE.match(method))


def _missing_min_output_reason(body_node, source: bytes) -> str | None:
    for node in walk_no_nested_fn(body_node):
        if node.type != "call_expression":
            continue
        method = _method_name(node, source)
        if method is None or not _is_swap_method(method):
            continue

        args = _arguments_text(node, source)
        min_match = _MIN_OUT_RE.search(args)
        if min_match is None:
            return "missing minimum-output protection on swap call"

        tail = args[min_match.end() : min_match.end() + 80]
        if _ZERO_OR_UNBOUNDED_RE.search(tail):
            return "zero or unbounded minimum-output protection on swap call"
    return None


def _first_reason(name: str, body_text: str, body_node, source: bytes) -> str | None:
    source_text = source.decode("utf-8", errors="replace")
    if not _has_value_context(name, body_text, source_text):
        return None
    return (
        _missing_min_output_reason(body_node, source)
        or _division_before_mul_reason(body_text)
        or _unchecked_arith_reason(body_text, source_text)
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
        body_text = body_text_nocomment(body, source)
        reason = _first_reason(name, body_text, body, source)
        if reason is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` has rounding-direction-attack value risk: "
                    f"{reason}. Require multiply-before-divide, checked error "
                    "handling, or explicit min-out/slippage protection before "
                    "moving user value."
                ),
            }
        )
    return hits
