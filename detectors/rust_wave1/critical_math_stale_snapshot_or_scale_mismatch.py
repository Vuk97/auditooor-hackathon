"""
critical_math_stale_snapshot_or_scale_mismatch.py

Class-invariant detector for Rust fund-loss-via-arithmetic shapes where
critical value math uses a stale snapshot, stale score, cached price, cached
liquidity, pre-update prior value, or mismatched decimal scale.

The detector is deliberately narrower than generic arithmetic scans. It only
fires in public functions with value, debt, collateral, share, price, reward,
liquidation, settlement, or score context, and requires a stale-value or scale
hazard to be present.
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


_CRITICAL_CONTEXT_RE = re.compile(
    r"(?i)(price|value|score|conviction|collateral|debt|borrow|repay|"
    r"health|ltv|liquidat|payout|reward|refund|claim|transfer|mint|"
    r"burn|redeem|withdraw|deposit|settle|quote|shares?|assets?|"
    r"supply|liquidity|reserve)"
)

_MATH_RE = re.compile(
    r"(?i)(saturating_(sub|add|mul|div)\s*\(|checked_(sub|add|mul|div)\s*\(|"
    r"\b(wrapping_(sub|add|mul|div))\s*\(|[+\-*/])"
)

_SOURCE_CALL_RE = re.compile(
    r"(?i)(Reflector\s*::\s*new|\.lastprice\s*\(|\.twap\s*\(|"
    r"\.get_price\s*\(|get_price_with_protection|query_custom_oracle|"
    r"query_batch_adapter_direct|manual_override_price|get_last_price_data|"
    r"get_last_price\b|get_cached_price|cached_price|last_price)"
)

_FRESHNESS_GUARD_RE = re.compile(
    r"(?i)(validate_price_staleness|validate_price_freshness|"
    r"validate_price_change|is_circuit_breaker_active|"
    r"get_circuit_breaker_state|circuit_breaker_check|check_staleness|"
    r"check_freshness|heartbeat|max_staleness|max_age|stale_after)"
)

_STALE_TOKEN_RE = re.compile(
    r"(?i)\b("
    r"(cached|stored|snapshot|saved|initial|last|old|stale|prior|previous|pre)_"
    r"(price|value|debt|collateral|supply|shares|share|balance|amount|"
    r"power|liquidity|reserve|index|payout|reward|score|rate)|"
    r"(price|value|debt|collateral|supply|shares|share|balance|amount|"
    r"power|liquidity|reserve|index|payout|reward|score|rate)_at_"
    r"(deposit|start|epoch|round|issue|mint|snapshot)|"
    r"position_liquidity|stored_liquidity|cached_liquidity|"
    r"liquidity_at_deposit|total_power_in_tokens|initial_total_supply"
    r")\b"
)

_FRESH_VALUE_RE = re.compile(
    r"(?i)(current_(price|value|score|debt|collateral|balance|power|"
    r"supply|liquidity|shares|amount)|live_(price|value|score|debt|"
    r"collateral|balance|power|supply|liquidity|shares|amount)|"
    r"refresh_(price|value|score|debt|collateral|balance|position|"
    r"liquidity)|recompute_(price|value|score|debt|collateral|balance|"
    r"shares|assets)|settle_(debt|position|reward)|"
    r"accrue_(interest|debt|reward)|get_position_info\s*\(|"
    r"position_manager\s*\.\s*positions\s*\(|"
    r"nft_position_manager\s*\.\s*positions\s*\()"
)

_MUTATION_BEFORE_PRIOR_RE = re.compile(
    r"(?is)(?:"
    r"\.(insert|set|remove|update)\s*\(|"
    r"\b(set_|update_|clear_|remove_)\w*\s*\("
    r")"
    r"[\s\S]{0,280}?"
    r"(get_prior\w*_(score|debt|balance|collateral|power|value)|"
    r"get_prior\w*score|get_past\w*\s*\(|get_prev\w*\s*\(|"
    r"read_previous\w*\s*\()"
)

_DECIMAL_WORD_RE = re.compile(
    r"(?i)\b(vault_decimals|strategy_decimals|asset_decimals|"
    r"share_decimals|price_decimals|oracle_decimals|collateral_decimals|"
    r"debt_decimals|token_decimals|underlying_decimals|decimals_diff|"
    r"scale_factor|scale|precision)\b"
)

_MISMATCH_WORD_RE = re.compile(
    r"(?i)(vault|strategy|asset|share|price|oracle|collateral|debt|"
    r"underlying|token)"
)

_NORMALIZE_RE = re.compile(
    r"(?i)(normalize|rescale|scale_to|scale_from|adjust_decimals|"
    r"convert_decimals|checked_pow|pow\s*\(|10u?(8|16|32|64|128)\s*\.pow|"
    r"decimals_diff)"
)


def _uses_token_in_math(body_text: str, token: str) -> bool:
    esc = re.escape(token)
    patterns = [
        rf"\b{esc}\b\s*[+\-*/]",
        rf"[+\-*/]\s*\b{esc}\b",
        rf"=\s*[^;\n]*\b{esc}\b[^;\n]*[+\-*/]",
        rf"=\s*[^;\n]*[+\-*/][^;\n]*\b{esc}\b",
        rf"(saturating|checked|wrapping)_(sub|add|mul|div)\s*\([^)]*\b{esc}\b",
    ]
    return any(re.search(p, body_text) for p in patterns)


def _stale_assignment_used_in_math(body_text: str) -> str | None:
    for stmt in re.finditer(r"(?is)\blet\s+([A-Za-z_]\w*)\s*=\s*([^;]+);", body_text):
        var_name = stmt.group(1)
        rhs = stmt.group(2)
        if not _STALE_TOKEN_RE.search(rhs):
            continue
        if _uses_token_in_math(body_text[stmt.end():], var_name):
            return var_name
    return None


def _has_critical_context(name: str, body_text: str) -> bool:
    return bool(_CRITICAL_CONTEXT_RE.search(name) or _CRITICAL_CONTEXT_RE.search(body_text))


def _decimal_scale_mismatch(body_text: str) -> bool:
    if not _DECIMAL_WORD_RE.search(body_text):
        return False
    if not _MISMATCH_WORD_RE.search(body_text):
        return False
    if not _MATH_RE.search(body_text):
        return False
    if _NORMALIZE_RE.search(body_text):
        return False
    return True


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

        if not _has_critical_context(name, body_nc):
            continue

        if _SOURCE_CALL_RE.search(body_nc) and not _FRESHNESS_GUARD_RE.search(body_nc):
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` consumes a stale-prone price/source in "
                    f"critical value math without a freshness or circuit "
                    f"breaker guard (critical-math-stale-snapshot-or-scale-"
                    f"mismatch, fund-loss-via-arithmetic)."
                ),
            })
            continue

        if (
            _MUTATION_BEFORE_PRIOR_RE.search(body_nc)
            and _MATH_RE.search(body_nc)
            and _CRITICAL_CONTEXT_RE.search(body_nc)
        ):
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` mutates state before reading a prior "
                    f"value that later feeds delta/value math "
                    f"(critical-math-stale-snapshot-or-scale-mismatch, "
                    f"fund-loss-via-arithmetic)."
                ),
            })
            continue

        matched_stale_token = False
        if not _FRESH_VALUE_RE.search(body_nc):
            stale_alias = _stale_assignment_used_in_math(body_nc)
            if stale_alias is not None:
                line, col = line_col(fn)
                hits.append({
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:220],
                    "message": (
                        f"pub fn `{name}` assigns a stale snapshot/cache "
                        f"value to `{stale_alias}` and later uses it in "
                        f"critical arithmetic without a live/current refresh "
                        f"(critical-math-stale-snapshot-or-scale-mismatch, "
                        f"fund-loss-via-arithmetic)."
                    ),
                })
                continue

            for match in _STALE_TOKEN_RE.finditer(body_nc):
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
                        f"critical arithmetic without a live/current refresh "
                        f"(critical-math-stale-snapshot-or-scale-mismatch, "
                        f"fund-loss-via-arithmetic)."
                    ),
                })
                matched_stale_token = True
                break
            if matched_stale_token:
                continue

        if _decimal_scale_mismatch(body_nc):
            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` mixes decimal or scale domains in "
                    f"asset/share/debt math without normalization "
                    f"(critical-math-stale-snapshot-or-scale-mismatch, "
                    f"fund-loss-via-arithmetic)."
                ),
            })
    return hits
