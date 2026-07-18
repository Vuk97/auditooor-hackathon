"""
value_math_rounding_or_minout_zero_fire20.py

Rust recall lift for rounding-direction-attack.

Flags public value-moving Rust functions when swap or vault math can move
value through one of three same-class shapes:
  1. division happens before multiplication in vault, share, payout, or amount
     math,
  2. DEX amount or quote math uses floor division where the pool-favorable
     side needs a round-up path, or
  3. a swap path has no minimum output or passes zero/None as the minimum.

Detector hits are candidate evidence only. Raw arithmetic without swap, vault,
asset, or accounting context is intentionally ignored.
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
    r"(?i)(amount|amount_in|amount_out|min_out|min_return|minimum_out|"
    r"min_received|slippage|swap|exchange|router|quote|shares?|assets?|"
    r"tokens?|balances?|vault|accounting|reserves?|liquidity|lp_|lp\b|"
    r"collateral|debt|borrow|repay|reward|payout|fee|fees|withdraw|"
    r"redeem|deposit|mint|burn|position|supply|settle|seize|price)"
)

_CONTRACT_CONTEXT_RE = re.compile(
    r"(?i)(soroban_sdk|contractimpl|anchor_lang|cosmwasm_std|near_sdk|"
    r"frame_support|pallet::|#\s*\[\s*program\s*\])"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?i)(mul_div_up|muldiv_up|ceil_div|div_ceil|round_up|"
    r"roundingmode\s*::\s*up|rounding\s*::\s*up|rounding::up|"
    r"checked_mul\s*\([^;]{0,220}\)\s*\?[^;]{0,220}"
    r"checked_div\s*\([^;]{0,220}\)\s*\?)"
)

_DIRECT_DIV_FIRST_RE = re.compile(
    r"(?P<expr>\(?\b[A-Za-z_][A-Za-z0-9_\.]*\b\s*/\s*"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\b\)?\s*\*\s*"
    r"\b[A-Za-z_][A-Za-z0-9_\.]*\b)",
    re.MULTILINE,
)

_CHECKED_DIV_THEN_MUL_RE = re.compile(
    r"(?i)(?P<expr>\.checked_div\s*\([^;]{1,180}\)\s*\??"
    r"[^;]{0,140}\.checked_mul\s*\([^;]{1,180}\))"
)

_QUOTIENT_ASSIGN_RE = re.compile(
    r"let\s+(?:mut\s+)?(?P<q>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*"
    r"(?P<expr>\(?[^;\n]{1,180}/[^;\n]{1,180}\)?)\s*;",
    re.MULTILINE,
)

_MUL_WITH_QUOTIENT_RE_TEMPLATE = (
    r"(?P<stmt>[^;\n]{0,200}\b%s\b[^;\n]{0,200}\*[^;\n]{0,200};|"
    r"[^;\n]{0,200}\*[^;\n]{0,200}\b%s\b[^;\n]{0,200};)"
)

_DEX_AMOUNT_FN_RE = re.compile(
    r"(?i)(ask|bid|get|preview)_?(exact_)?amount_?(in|out)|"
    r"calc_amount_?(in|out)|get_amount_?(in|out)|quote_?(in|out)|"
    r"preview_redeem|preview_withdraw|preview_mint|swap_?(out|in)|"
    r"amount_?(out|in)_?for"
)

_FLOOR_DIV_RE = re.compile(
    r"(?i)(\.checked_div\s*\(|/\s*[A-Za-z_(]|mul_div\s*\(|"
    r"mul_div_down|mul_div_floor|floor_div)"
)

_AMOUNT_CONTEXT_RE = re.compile(
    r"(?i)(amount_in|amount_out|shares?|assets?|reserves?|liquidity|"
    r"numerator|denominator|fee|price|quote)"
)

_SWAP_METHOD_RE = re.compile(
    r"(?i)^(swap|swap_exact_in|swap_exact_out|swap_exact_tokens|"
    r"swap_exact_tokens_for_tokens|exact_input|exact_input_single|"
    r"exact_output|path_swap|exchange|exchange_exact_in|execute_swap|"
    r"route_swap|router_swap)$"
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

_MIN_OUT_RE = re.compile(
    r"(?i)\b(min_amount_out|min_out|min_return|min_swap_output|"
    r"minimum_out|min_received|amount_out_min|amountOutMin|"
    r"amountOutMinimum|sqrt_price_limit|price_limit|slippage)\b"
)

_ZERO_OR_UNBOUNDED_RE = re.compile(
    r"(?i)(?:^|[&\s:=,(])(0(?:u128|i128|_u128|_i128)?|i128::MIN|"
    r"u128::MIN|U256::ZERO|None)\b"
)

_USER_MIN_RE = re.compile(
    r"(?i)(user_min_out|caller_min_out|caller_supplied_min|min_out|"
    r"min_amount_out|min_return|minimum_out|min_received|slippage)"
)

_BODY_MIN_GUARD_RE = re.compile(
    r"(?is)\b(user_min_out|caller_min_out|min_out|min_amount_out|"
    r"min_return|minimum_out|min_received)\b.{0,220}"
    r"(?:<=\s*0|<\s*1|ensure!\s*\(|require!\s*\(|return\s+Err|Err\s*\()"
)


def _has_value_context(name: str, body: str, source_text: str) -> bool:
    return bool(
        _VALUE_CONTEXT_RE.search(name)
        or _VALUE_CONTEXT_RE.search(body)
        or _CONTRACT_CONTEXT_RE.search(source_text)
    )


def _safe_near(body: str, start: int, end: int) -> bool:
    window = body[max(0, start - 180) : min(len(body), end + 240)]
    return bool(_SAFE_ROUNDING_RE.search(window))


def _division_before_multiplication_reason(body: str) -> str | None:
    for match in _DIRECT_DIV_FIRST_RE.finditer(body):
        if _safe_near(body, match.start(), match.end()):
            continue
        expr = match.group("expr")
        if _VALUE_CONTEXT_RE.search(expr) or _VALUE_CONTEXT_RE.search(body):
            return "division before multiplication in value-moving math"

    for match in _CHECKED_DIV_THEN_MUL_RE.finditer(body):
        if _safe_near(body, match.start(), match.end()):
            continue
        expr = match.group("expr")
        if _VALUE_CONTEXT_RE.search(expr) or _VALUE_CONTEXT_RE.search(body):
            return "checked division before checked multiplication in value-moving math"

    for match in _QUOTIENT_ASSIGN_RE.finditer(body):
        quotient = match.group("q")
        expr = match.group("expr")
        if not (_VALUE_CONTEXT_RE.search(quotient) or _VALUE_CONTEXT_RE.search(expr)):
            continue
        tail = body[match.end() : match.end() + 800]
        mul_re = re.compile(
            _MUL_WITH_QUOTIENT_RE_TEMPLATE
            % (re.escape(quotient), re.escape(quotient)),
            re.MULTILINE,
        )
        multiplied = mul_re.search(tail)
        if multiplied is None:
            continue
        absolute_start = match.end() + multiplied.start()
        absolute_end = match.end() + multiplied.end()
        if _safe_near(body, absolute_start, absolute_end):
            continue
        if _VALUE_CONTEXT_RE.search(multiplied.group("stmt")):
            return "division before multiplication quotient reaches value-moving math"

    return None


def _dex_floor_rounding_reason(name: str, body: str) -> str | None:
    if not _DEX_AMOUNT_FN_RE.search(name):
        return None
    if not _FLOOR_DIV_RE.search(body):
        return None
    if not _AMOUNT_CONTEXT_RE.search(body):
        return None
    if _SAFE_ROUNDING_RE.search(body):
        return None
    return "DEX amount or quote math uses floor rounding without round-up protection"


def _method_name(call_node, source: bytes) -> str | None:
    for child in call_node.children:
        if child.type == "field_expression":
            for field_child in child.children:
                if field_child.type == "field_identifier":
                    return text_of(field_child, source)

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
    if "swap" in lowered and any(
        marker in lowered
        for marker in ("router", "uniswap", "dex", "exact", "token", "execute")
    ):
        return True
    return bool(_SWAP_METHOD_RE.match(method) or _LOOSE_SWAP_METHOD_RE.match(method))


def _missing_min_output_reason(body_node, source: bytes) -> str | None:
    body_text = text_of(body_node, source)
    body_has_guarded_min = bool(_BODY_MIN_GUARD_RE.search(body_text))
    for node in walk_no_nested_fn(body_node):
        if node.type != "call_expression":
            continue
        method = _method_name(node, source)
        if method is None or not _is_swap_method(method):
            continue

        args = _arguments_text(node, source)
        call_text = text_of(node, source)
        probe_text = args or call_text
        if _USER_MIN_RE.search(probe_text) or body_has_guarded_min:
            continue
        if _MIN_OUT_RE.search(probe_text) is None:
            if _ZERO_OR_UNBOUNDED_RE.search(probe_text):
                return "swap call passes zero or unbounded minimum output"
            return "swap call has no explicit minimum-output argument"

        if _ZERO_OR_UNBOUNDED_RE.search(probe_text):
            return "swap call passes zero or unbounded minimum output"

        if _USER_MIN_RE.search(probe_text):
            continue
    return None


def _first_reason(name: str, body_text: str, body_node, source: bytes) -> str | None:
    source_text = source.decode("utf-8", errors="replace")
    if not _has_value_context(name, body_text, source_text):
        return None
    return (
        _missing_min_output_reason(body_node, source)
        or _dex_floor_rounding_reason(name, body_text)
        or _division_before_multiplication_reason(body_text)
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
                    f"{reason}. Require checked multiply-before-divide, "
                    "pool-favorable rounding, or caller supplied min-output "
                    "protection before moving user value."
                ),
            }
        )
    return hits
