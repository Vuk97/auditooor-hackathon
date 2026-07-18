"""
matching_engine_misprice_fire22.py

Flags Rust matching and perpetual valuation paths that compute margin,
fill, or liquidation value from a stale orderbook last price, a wrong-side
book price, or a caller-supplied underlying price without an oracle or
current-book validation path.

Source: Fire22 detector lift AA, seeded by Fire21 miss
r94-loop-perp-underlying-px-from-orderbook-last-px-positive.
Class: matching-engine-misprice.
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


_SURFACE_NAME_RE = re.compile(
    r"(?i)(match|fill|execute|settle|liquidat|margin|maintenance|"
    r"mark_to_market|position_value|notional|health|collateral|risk|pnl)"
)

_SURFACE_BODY_RE = re.compile(
    r"(?i)(margin|maintenance_margin|liquidation_value|fill_price|"
    r"fill_value|notional|position_value|health|collateral|pnl|"
    r"match_order|execute_fill|settlement)"
)

_STALE_LAST_PRICE_RE = re.compile(
    r"\b(last_px|last_price|last_trade_price|last_fill_price|"
    r"orderbook_last_px|spot_last_px)\b|"
    r"\b(book|orderbook|market|pair)\s*\.\s*"
    r"(last_px|last_price|last_trade_price)\b",
    re.IGNORECASE,
)

_WRONG_BUY_SIDE_RE = re.compile(
    r"(?is)(Side::Buy|side\s*==\s*(?:Side::)?Buy|\.is_buy\s*\(\s*\)|"
    r"is_buy\s*\(\s*\))[\s\S]{0,240}"
    r"(best_bid|bid_price|bid_px|book\s*\.\s*bid|book\s*\.\s*best_bid)"
)

_WRONG_SELL_SIDE_RE = re.compile(
    r"(?is)(Side::Sell|side\s*==\s*(?:Side::)?Sell|\.is_sell\s*\(\s*\)|"
    r"is_sell\s*\(\s*\))[\s\S]{0,240}"
    r"(best_ask|ask_price|ask_px|book\s*\.\s*ask|book\s*\.\s*best_ask)"
)

_UNBOUND_UNDERLYING_RE = re.compile(
    r"\b(underlying_price|underlying_px|input_price|submitted_price|"
    r"claimed_price)\b|"
    r"\b(order|request|params|quote|payload|input)\s*\.\s*"
    r"(underlying_)?(price|px|mark_price)\b",
    re.IGNORECASE,
)

_SAFE_PRICE_CONTEXT_RE = re.compile(
    r"(?i)(oracle|price_feed|pyth|chainlink|twap|time_weighted|vwap|ema|"
    r"median|fresh|freshness|stale|staleness|max_age|confidence|"
    r"deviation|max_deviation|validate_price|assert_price|checked_price|"
    r"checked_mark|mark_price_oracle|current_book|current_mid|mid_price|"
    r"price_for_side|best_ask|best_bid|quote_at_tick|book_snapshot|"
    r"from_orderbook_snapshot)"
)

_MATH_OR_STATE_RE = re.compile(
    r"(?i)(\*|/|\+|-|margin\s*=|notional\s*=|liquidation_value\s*=|"
    r"fill_value\s*=|position_value\s*=|health\s*=|collateral\s*=|"
    r"\.margin\s*=|\.notional\s*=|\.liquidation)"
)


def _sig_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _is_matching_surface(name: str, body_nc: str) -> bool:
    return bool(_SURFACE_NAME_RE.search(name) or _SURFACE_BODY_RE.search(body_nc))


def _stale_last_price_without_guard(body_nc: str) -> bool:
    if not _STALE_LAST_PRICE_RE.search(body_nc):
        return False
    return not _SAFE_PRICE_CONTEXT_RE.search(body_nc)


def _wrong_side_book_price(body_nc: str) -> bool:
    return bool(
        _WRONG_BUY_SIDE_RE.search(body_nc) or _WRONG_SELL_SIDE_RE.search(body_nc)
    )


def _unbound_underlying_price(fn, source: bytes, body_nc: str) -> bool:
    haystack = f"{_sig_text(fn, source)}\n{body_nc}"
    if not _UNBOUND_UNDERLYING_RE.search(haystack):
        return False
    if not _MATH_OR_STATE_RE.search(body_nc):
        return False
    return not _SAFE_PRICE_CONTEXT_RE.search(body_nc)


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
        if not _is_matching_surface(name, body_nc):
            continue

        stale_last = _stale_last_price_without_guard(body_nc)
        wrong_side = _wrong_side_book_price(body_nc)
        unbound_underlying = _unbound_underlying_price(fn, source, body_nc)
        if not (stale_last or wrong_side or unbound_underlying):
            continue

        reasons = []
        if stale_last:
            reasons.append("stale orderbook last price")
        if wrong_side:
            reasons.append("wrong-side book price")
        if unbound_underlying:
            reasons.append("unbound underlying price")
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` computes matching or perp valuation "
                    f"from {', '.join(reasons)} without an oracle or "
                    f"current-book validation path "
                    f"(matching-engine-misprice)."
                ),
            }
        )
    return hits
