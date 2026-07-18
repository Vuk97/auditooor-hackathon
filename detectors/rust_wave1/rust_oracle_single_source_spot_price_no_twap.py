"""
rust_oracle_single_source_spot_price_no_twap.py

Flags public Rust value-movement functions that consume a single-source
spot oracle or instantaneous pool reserve price with no TWAP, median,
freshness, confidence, or deviation guard.

Confirmed lift: Compound-style single oracle pricing and spot reserve
pricing become reportable only when the raw price directly controls mint,
redeem, borrow, liquidation, settlement, collateral, or share movement.
This detector rejects standalone price getters and safe guarded consumers.

Fire14 lift: also catches same-class oracle manipulation shapes where the
oracle value is a manipulable AMM quote, a one-sided pool branch prices at a
flat oracle value without spread or size impact, or a `lookback` parameter is
accepted while the body reads only the latest round.
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


_VALUE_MOVEMENT_NAME_RE = re.compile(
    r"(?i)(mint|redeem|borrow|repay|liquidat|settle|withdraw|deposit|"
    r"collateral|health|ltv|margin|position|share|vault|loan)"
)

_VALUE_MOVEMENT_BODY_RE = re.compile(
    r"(?i)("
    r"\.(mint|redeem|borrow|repay|liquidat|settle|withdraw|deposit)"
    r"\s*\(|"
    r"(minted|shares|debt|collateral|liability|liquidation_bonus|"
    r"seize|payout|settlement|notional|margin|health_factor|ltv)"
    r"\s*(?:[+\-*/%]?=|:)|"
    r"(transfer|transfer_from|safe_transfer|send_tokens)\s*\(|"
    r"borrower\.\w+\s*[+\-]?=|"
    r"position\.\w+\s*[+\-]?=|"
    r"vault\.\w+\s*[+\-]?="
    r")"
)

_SPOT_PRICE_RE = re.compile(
    r"(?i)("
    r"(oracle|feed|price_feed|aggregator|pyth|reflector)"
    r"\s*\.\s*"
    r"(latest_price|latest_answer|latest_round_data|latestRoundData|"
    r"get_price|price|last_price|lastprice|current_price|spot_price)"
    r"\s*\(|"
    r"(pool|pair|amm|dex)"
    r"\s*\.\s*"
    r"(get_reserves|getReserves|reserves|spot_price|current_price)"
    r"\s*\(|"
    r"\bspot_price\b|"
    r"\bcurrent_price\b|"
    r"\blast_px\b"
    r")"
)

_AMM_QUOTE_RE = re.compile(
    r"(?i)(get_amounts_in|getAmountsIn|quote_exact_output|"
    r"get_amounts_out|getAmountsOut)\s*\("
)

_AMM_QUOTE_SAFE_RE = re.compile(
    r"(?i)(twap|time_weighted|moving_average|ema|vwap|chainlink|"
    r"oracle_price|price_oracle|mark_price|fresh|freshness|stale|"
    r"staleness|deviation|max_deviation|validate_price|checked_price)"
)

_DISCARDED_AMM_QUOTE_RE = re.compile(
    r"(?is)\blet\s+_\s*=\s*[^;]*(get_amounts_in|getAmountsIn|"
    r"quote_exact_output|get_amounts_out|getAmountsOut)\s*\([^;]*;"
)

_AMM_QUOTE_USED_RE = re.compile(
    r"(?is)("
    r"\blet\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*"
    r"(?:get_amounts_in|getAmountsIn|quote_exact_output|"
    r"get_amounts_out|getAmountsOut)\s*\([^;]*;"
    r"[\s\S]*?(?:return\s+(?P=var)\b|(?P=var)\s*[*/+\-]|"
    r"[*/+\-]\s*(?P=var)\b|(?P=var)\s*[};])|"
    r"return\s+[^;]*(?:get_amounts_in|getAmountsIn|quote_exact_output|"
    r"get_amounts_out|getAmountsOut)\s*\("
    r")"
)

_ONE_SIDED_BRANCH_RE = re.compile(
    r"(?i)(reserve[0-9]?_?(a|b|x|y|in|out)|balance[0-9]?|liquidity)"
    r"\s*==\s*0|is_empty\s*\(\)|len\s*\(\)\s*==\s*0"
)

_ORACLE_VALUE_RE = re.compile(
    r"(?i)(oracle_price|get_oracle|oracle\.|get_price_from_oracle|"
    r"price_feed|pyth|chainlink|reflector|latest_round_data|"
    r"latestRoundData)"
)

_SIZE_SCALING_RE = re.compile(
    r"(?i)(dynamic_spread|price_impact|apply_slippage|spread_bps|"
    r"slippage_bps|scale_by_size|impact\s*=|amount\s*\*\s*fee_bps)"
)

_LOOKBACK_ARG_RE = re.compile(
    r"(?i)fn\s+\w+\s*\([^)]*\b(lookback|twap_window|window_seconds|"
    r"lookback_secs)\s*:"
)

_LATEST_ROUND_RE = re.compile(
    r"(?i)(latest_round_data|latestRoundData|latest_answer|latestAnswer)\s*\("
)

_LOOKBACK_DISCARD_RE = re.compile(
    r"(?i)\blet\s+_\s*=\s*(lookback|twap_window|window_seconds|lookback_secs)\b"
)

_LOOKBACK_USED_FOR_HISTORY_RE = re.compile(
    r"(?i)(saturating_sub\s*\(\s*(lookback|twap_window|window_seconds|"
    r"lookback_secs)\s*\)|-\s*(lookback|twap_window|window_seconds|"
    r"lookback_secs)\b|historical_round|get_round|round_at|for\s+\w+\s+in|"
    r"twap|time_weighted|moving_average|ema)"
)

_SAFE_ORACLE_GUARD_RE = re.compile(
    r"(?i)("
    r"twap|time_weighted|timeWeighted|moving_average|ema|vwap|"
    r"price_cumulative|priceCumulative|observe\s*\(|observations\s*\[|"
    r"consult\s*\(|quote_at_tick|quoteAtTick|oracle_period|"
    r"median|median_price|sort_by|prices\.sort|"
    r"multi_source|multi_feed|secondary_feed|fallback_feed|"
    r"feeds\.iter|sources\.iter|oracles\.iter|quorum|majority|"
    r"confidence|max_confidence|conf_interval|price_conf|"
    r"deviation|max_deviation|deviation_bps|within_tolerance|"
    r"bounds?|min_price|max_price|sanity|"
    r"fresh|freshness|stale|staleness|max_age|heartbeat|"
    r"publish_time|last_update|updated_at|no_older_than|"
    r"validate_price|check_price|checked_price"
    r")"
)


def _sig_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _amm_quote_used_as_oracle(body_nc: str) -> bool:
    if not _AMM_QUOTE_RE.search(body_nc):
        return False
    if _AMM_QUOTE_SAFE_RE.search(body_nc):
        return False
    if _DISCARDED_AMM_QUOTE_RE.search(body_nc):
        return False
    return bool(_AMM_QUOTE_USED_RE.search(body_nc))


def _asymmetric_liquidity_flat_oracle(body_nc: str) -> bool:
    if not _ONE_SIDED_BRANCH_RE.search(body_nc):
        return False
    if not _ORACLE_VALUE_RE.search(body_nc):
        return False
    return not _SIZE_SCALING_RE.search(body_nc)


def _lookback_latest_round_only(fn, source: bytes, body_nc: str) -> bool:
    sig = _sig_text(fn, source)
    if not _LOOKBACK_ARG_RE.search(sig):
        return False
    if not _LATEST_ROUND_RE.search(body_nc):
        return False
    body_without_discards = _LOOKBACK_DISCARD_RE.sub("", body_nc)
    return not _LOOKBACK_USED_FOR_HISTORY_RE.search(body_without_discards)


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

        amm_quote = _amm_quote_used_as_oracle(body_nc)
        asymmetric_flat = _asymmetric_liquidity_flat_oracle(body_nc)
        lookback_ignored = _lookback_latest_round_only(fn, source, body_nc)
        value_movement = (
            _VALUE_MOVEMENT_NAME_RE.search(name)
            or _VALUE_MOVEMENT_BODY_RE.search(body_nc)
        )
        single_source_spot = (
            value_movement
            and _SPOT_PRICE_RE.search(body_nc)
            and not _SAFE_ORACLE_GUARD_RE.search(body_nc)
        )
        if not (single_source_spot or amm_quote or asymmetric_flat or lookback_ignored):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:220],
            "message": (
                f"pub fn `{name}` uses a single-source spot oracle or "
                f"instantaneous pool reserve price to control value movement "
                f"with no TWAP, median, confidence, deviation, freshness, or "
                f"multi-source guard "
                f"(rust-oracle-single-source-spot-price-no-twap)."
            ),
        })
    return hits
