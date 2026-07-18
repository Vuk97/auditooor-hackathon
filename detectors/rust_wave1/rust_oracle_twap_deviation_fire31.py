"""
rust_oracle_twap_deviation_fire31.py

Rust Fire31 lift for oracle-price-manipulation.

Flags public Rust oracle consumers that accept a spot price or cached price
without any TWAP or deviation guard, heartbeat or freshness guard, or safe
shutdown branch before returning the price or using it in value-moving math.

Rule 37 provenance:
- local miss class: Rust oracle spot or cached price accepted without TWAP
  deviation, heartbeat, or shutdown protection.
- source refs:
  - reports/detector_lift_fire30_20260605/post_priorities_rust.md
  - detectors/rust_wave1/rust_oracle_heartbeat_no_fallback_fire30.py
  - reference/patterns.dsl.zellic_k2_mined/cached-oracle-prices-ignore-per-asset-freshness-limits.yaml
- attack_class: oracle-price-manipulation

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
)


DETECTOR_ID = "rust_wave1.rust_oracle_twap_deviation_fire31"

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_ORACLE_CONTEXT_RE = re.compile(
    r"(?i)(oracle|price|feed|round|answer|pyth|chainlink|reflector|"
    r"spot|twap|lastpricedata|last_price|cached_price|stored_price|"
    r"collateral|debt|health|ltv|liquidat|borrow|margin|notional)"
)

_VALUE_MOVEMENT_NAME_RE = re.compile(
    r"(?i)(borrow|liquidat|mint|redeem|deposit|withdraw|settle|"
    r"collateral|health|ltv|margin|position|share|vault|loan|debt|nav)"
)

_VALUE_MOVEMENT_BODY_RE = re.compile(
    r"(?i)("
    r"\.(?:borrow|liquidat|mint|redeem|deposit|withdraw|settle)\s*\(|"
    r"(?:debt|collateral|shares|minted|borrow_limit|liquidation_bonus|"
    r"seize|payout|settlement|notional|margin|health_factor|ltv|nav)"
    r"\s*(?:[+\-*/%]?=|:)|"
    r"(?:transfer|transfer_from|safe_transfer|send_tokens)\s*\(|"
    r"(?:borrower|account|position|vault|market)\.\w+\s*[+\-]?="
    r")"
)

_PUBLIC_PRICE_GETTER_RE = re.compile(
    r"(?i)(get_|read_|fetch_|load_|return_)?(?:asset_)?(?:oracle_)?"
    r"(?:price|prices|spot|quote|rate|last_price)"
)

_SPOT_SOURCE_RE = re.compile(
    r"(?is)("
    r"(?:oracle|feed|price_feed|aggregator|pyth|chainlink|reflector|"
    r"adapter|source|pool|pair|amm|dex)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*){0,3}"
    r"\s*\.\s*"
    r"(?:latest_price|latest_answer|latest_round_data|latestRoundData|"
    r"lastprice|last_price|price|spot_price|get_spot_price|"
    r"current_price|get_price|read_price|fetch_price|quote_price|"
    r"get_reserves|getReserves|reserves)"
    r"\s*\(|"
    r"\b(?:spot_price|current_price|latest_price|oracle_spot_price)\b"
    r")"
)

_CACHED_SOURCE_RE = re.compile(
    r"(?is)("
    r"\b(?:cached_price|cached_oracle_price|last_price|stored_price|"
    r"saved_price|manual_price|override_price)\b|"
    r"\b(?:cached|cache|last|stored|saved|price_data|last_price_data)"
    r"\s*\.\s*(?:price|answer|rate|value)\b|"
    r"\bLastPriceData\b|"
    r"\bget_asset_price_data_with_config\s*\(|"
    r"\bget_asset_prices_(?:vec|batch)\s*\("
    r")"
)

_PRICE_ACCEPT_SINK_RE = re.compile(
    r"(?is)("
    r"return\s+(?:Ok\s*\()?[^;{}]{0,260}"
    r"(?:spot_price|current_price|latest_price|oracle_spot_price|"
    r"cached_price|last_price|stored_price|saved_price|"
    r"price_data\s*\.\s*price|last_price_data\s*\.\s*price|"
    r"cached\s*\.\s*price)|"
    r"Ok\s*\([^)]{0,260}"
    r"(?:spot_price|current_price|latest_price|oracle_spot_price|"
    r"cached_price|last_price|stored_price|saved_price|"
    r"price_data\s*\.\s*price|last_price_data\s*\.\s*price|"
    r"cached\s*\.\s*price)|"
    r"(?:spot_price|current_price|latest_price|oracle_spot_price|"
    r"cached_price|last_price|stored_price|saved_price)"
    r"\s*(?:[*/+\-]|\.saturating_|\.checked_)"
    r")"
)

_TWAP_OR_DEVIATION_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:ensure|require|assert|debug_assert)!?\s*\([^;{}]{0,900}"
    r"(?:twap|time_weighted|moving_average|ema|vwap|median|"
    r"deviation|max_deviation|deviation_bps|abs_diff|within_tolerance|"
    r"bounds?|min_price|max_price|sanity|price_band|max_change)|"
    r"\b(?:ensure|require)\s*\([^;{}]{0,900}"
    r"(?:twap|time_weighted|moving_average|deviation|max_deviation|"
    r"abs_diff|within_tolerance|bounds?|sanity)\s*\)\s*\?|"
    r"\b(?:ensure|check|validate|assert)_[A-Za-z0-9_]*"
    r"(?:twap|deviation|bounds?|sanity|price)|"
    r"\b(?:safe_twap|twap_price|time_weighted_price|median_price|"
    r"moving_average_price|within_tolerance|max_deviation_bps)\b"
    r")"
)

_HEARTBEAT_GUARD_RE = re.compile(
    r"(?is)("
    r"\b(?:ensure|require|assert|debug_assert)!?\s*\([^;{}]{0,900}"
    r"(?:fresh|freshness|stale|staleness|heartbeat|max_age|"
    r"max_staleness|max_delay|ttl|updated_at|publish_time|last_update)|"
    r"\b(?:ensure|require)\s*\([^;{}]{0,900}"
    r"(?:fresh|stale|heartbeat|max_age|ttl|updated_at|publish_time)"
    r"\s*\)\s*\?|"
    r"\b(?:ensure|check|validate)_[A-Za-z0-9_]*"
    r"(?:fresh|stale|heartbeat|age)|"
    r"\b(?:no_older_than|get_price_no_older_than|cache_age)\b"
    r"[^;{}]{0,260}(?:<=|<|>=|>)"
    r"[^;{}]{0,260}(?:heartbeat|max_age|max_staleness|max_delay|ttl)|"
    r"\bif\s+[^{}]{0,760}"
    r"(?:age|cache_age|updated_at|publish_time|last_update|timestamp)"
    r"[^{}]{0,320}(?:<=|<|>=|>)"
    r"[^{}]{0,320}"
    r"(?:heartbeat|max_age|max_staleness|max_delay|ttl)"
    r"[^{}]{0,160}\{[^{}]{0,520}"
    r"(?:return\s+(?:Err|None)|Err\s*\(|bail!\s*\(|panic!\s*\()"
    r")"
)

_SAFE_SHUTDOWN_RE = re.compile(
    r"(?is)("
    r"(?:shutdown|safe_shutdown|paused|pause|halt|freeze|disable|"
    r"emergency_stop|fail_closed|circuit_breaker|reject|mark_stale|"
    r"mark_invalid)"
    r"[^{};]{0,320}"
    r"(?:return\s+(?:Err|None)|Err\s*\(|bail!\s*\(|panic!\s*\(|false)|"
    r"(?:return\s+(?:Err|None)|Err\s*\(|bail!\s*\(|panic!\s*\()"
    r"[^{};]{0,220}"
    r"(?:Shutdown|Paused|Halted|StalePrice|InvalidPrice|CircuitBreaker)"
    r")"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _has_oracle_context(name: str, body: str) -> bool:
    return bool(_ORACLE_CONTEXT_RE.search(name) or _ORACLE_CONTEXT_RE.search(body))


def _has_acceptance_context(name: str, body: str) -> bool:
    return bool(
        _VALUE_MOVEMENT_NAME_RE.search(name)
        or _VALUE_MOVEMENT_BODY_RE.search(body)
        or _PUBLIC_PRICE_GETTER_RE.search(name)
        or _PRICE_ACCEPT_SINK_RE.search(body)
    )


def _has_safe_guard(body: str) -> bool:
    return bool(
        _TWAP_OR_DEVIATION_GUARD_RE.search(body)
        or _HEARTBEAT_GUARD_RE.search(body)
        or _SAFE_SHUTDOWN_RE.search(body)
    )


def _candidate_reason(name: str, body: str) -> str | None:
    if not _has_oracle_context(name, body):
        return None
    if not _has_acceptance_context(name, body):
        return None
    if _has_safe_guard(body):
        return None

    spot = _SPOT_SOURCE_RE.search(body) is not None
    cached = _CACHED_SOURCE_RE.search(body) is not None
    if not (spot or cached):
        return None

    if not (
        _VALUE_MOVEMENT_BODY_RE.search(body)
        or _PRICE_ACCEPT_SINK_RE.search(body)
        or _PUBLIC_PRICE_GETTER_RE.search(name)
    ):
        return None

    if spot and cached:
        return "spot and cached oracle prices are accepted"
    if spot:
        return "spot oracle price is accepted"
    return "cached oracle price is accepted"


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        body = _strip_strings(body_text_nocomment(body_node, source))
        reason = _candidate_reason(name, body)
        if reason is None:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "file": filepath,
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"Rust oracle TWAP deviation candidate in `{name}`: "
                    f"{reason} before any TWAP or deviation guard, heartbeat "
                    "or freshness guard, or safe shutdown branch. Add "
                    "fail-closed freshness validation plus TWAP, deviation, "
                    "secondary oracle, or market shutdown before accepting "
                    "the price. attack_class=oracle-price-manipulation."
                ),
            }
        )

    return hits
