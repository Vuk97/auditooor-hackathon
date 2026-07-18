"""
stale_source_or_value_feeds_critical_math.py

Flags public Rust functions where either:

1. A stale-prone oracle/source value is consumed inside a price/value/
   collateral/debt/payout path without any freshness or circuit-breaker
   guard, or
2. A cached/snapshot/initial value feeds critical arithmetic for score,
   debt, collateral, payout, mint, burn, transfer, or liquidation math
   without any live/current refresh, or
3. The function mutates state before reading a `get_prior_*` value that is
   later used in score/debt/collateral math.

This is the sibling shape between:
  - circuit_breaker_staleness_bypass
  - convictionscore_updateconvictionscore_uses_stale_score_for_delta

The detector is intentionally scoped to public functions whose names or
function bodies indicate critical valuation / settlement math, not generic
helpers.
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


_NAME_CONTEXT_RE = re.compile(
    r"(?i)(price|value|score|collateral|debt|health|ltv|liquidat|"
    r"payout|reward|refund|claim|transfer|mint|burn|redeem|withdraw|"
    r"settle|quote)"
)

_SINK_WORD_RE = re.compile(
    r"(?i)(asset|price|value|score|conviction|collateral|debt|owed|"
    r"liquidat|payout|reward|refund|claim|shares?|amount|repay|"
    r"seize|bonus|health|ltv|mint|burn|transfer)"
)

_SOURCE_CALL_RE = re.compile(
    r"(?i)(\.lastprice\s*\(|"
    r"\.twap\s*\(|"
    r"get_price_with_protection|"
    r"query_custom_oracle|"
    r"query_batch_adapter_direct|"
    r"manual_override_price|"
    r"Reflector\s*::\s*new|"
    r"get_last_price_data|"
    r"get_last_price\b|"
    r"get_cached_price)"
)

_SOURCE_GUARD_RE = re.compile(
    r"(?i)(validate_price_staleness|"
    r"validate_price_freshness|"
    r"validate_price_change|"
    r"is_circuit_breaker_active|"
    r"get_circuit_breaker_state|"
    r"circuit_breaker_check|"
    r"check_staleness|"
    r"check_freshness|"
    r"heartbeat|"
    r"max_staleness|"
    r"max_age)"
)

_STALE_VALUE_TOKEN_RE = re.compile(
    r"(?i)\b("
    r"(cached|stored|snapshot|saved|initial|last|old|stale)_"
    r"(price|value|debt|collateral|supply|shares|balance|amount|"
    r"power|liquidity|reserve|index|payout|reward)|"
    r"(price|value|debt|collateral|supply|shares|balance|amount|"
    r"power|liquidity|reserve|index|payout|reward)_at_"
    r"(deposit|start|epoch|round|issue|mint)|"
    r"liquidity_at_deposit|"
    r"position_liquidity|"
    r"stored_liquidity|"
    r"cached_liquidity|"
    r"total_power_in_tokens|"
    r"initial_total_supply"
    r")\b"
)

_FRESH_VALUE_RE = re.compile(
    r"(?i)(current_(price|value|score|debt|collateral|balance|power|"
    r"supply|liquidity)|"
    r"live_(price|value|score|debt|collateral|balance|power|supply|"
    r"liquidity)|"
    r"refresh_(price|value|score|debt|collateral|balance|position)|"
    r"recompute_(price|value|score|debt|collateral|balance)|"
    r"settle_(debt|position|reward)|"
    r"accrue_(interest|debt|reward)|"
    r"total_voting_power\s*\(|"
    r"current_total_supply|"
    r"get_position_info\s*\(|"
    r"position_manager\s*\.\s*positions\s*\(|"
    r"nft_position_manager\s*\.\s*positions\s*\()"
)

_MUTATION_BEFORE_PRIOR_READ_RE = re.compile(
    r"(?is)(?:"
    r"\.(insert|set|remove|update)\s*\(|"
    r"\b(set_|update_|clear_|remove_)\w*\s*\("
    r")"
    r"[\s\S]{0,240}?"
    r"(get_prior\w*_(score|debt|balance|collateral|power)|"
    r"get_prior\w*score)"
)

_MATH_CONTEXT_RE = re.compile(
    r"(?i)(saturating_(sub|add|mul|div)\s*\(|"
    r"[+\-*/])"
)


def _uses_token_in_math(body_text: str, token: str) -> bool:
    esc = re.escape(token)
    patterns = [
        rf"\b{esc}\b\s*[+\-*/]",
        rf"[+\-*/]\s*\b{esc}\b",
        rf"=\s*[^;\n]*\b{esc}\b[^;\n]*[+\-*/]",
        rf"=\s*[^;\n]*[+\-*/][^;\n]*\b{esc}\b",
        rf"saturating_(sub|add|mul|div)\s*\(\s*\b{esc}\b",
        rf"saturating_(sub|add|mul|div)\s*\([^)]*\b{esc}\b[^)]*\)",
    ]
    return any(re.search(p, body_text) for p in patterns)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        name_or_sink_context = (
            _NAME_CONTEXT_RE.search(name) or _SINK_WORD_RE.search(body_nc)
        )
        if not name_or_sink_context:
            continue

        source_without_guard = (
            _SOURCE_CALL_RE.search(body_nc)
            and not _SOURCE_GUARD_RE.search(body_nc)
        )
        if source_without_guard:
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` consumes a stale-prone oracle/source "
                    f"value in a critical price/value/settlement path without "
                    f"any freshness or circuit-breaker guard "
                    f"(stale-source-or-value-feeds-critical-math)."
                ),
            })
            continue

        if (
            _MUTATION_BEFORE_PRIOR_READ_RE.search(body_nc)
            and _MATH_CONTEXT_RE.search(body_nc)
            and _SINK_WORD_RE.search(body_nc)
        ):
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` mutates state before reading a "
                    f"`get_prior_*` value that later feeds score/debt/"
                    f"collateral math - delta or payout can be computed from "
                    f"a stale view (stale-source-or-value-feeds-critical-math)."
                ),
            })
            continue

        if _FRESH_VALUE_RE.search(body_nc):
            continue

        for match in _STALE_VALUE_TOKEN_RE.finditer(body_nc):
            token = match.group(0)
            if not _uses_token_in_math(body_nc, token):
                continue
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` uses stale token `{token}` inside "
                    f"critical arithmetic without any live/current refresh "
                    f"(stale-source-or-value-feeds-critical-math)."
                ),
            })
            break
    return hits
