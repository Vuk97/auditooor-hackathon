"""
matching_engine_misprice_orderbook_fire23.py

Flags Rust matching, margin, and mark-price code that derives load-bearing
fill or risk prices from replayable orderbook fields: stale last trade price,
buy/sell side inversion, or raw bid/ask reads with no fresh snapshot or oracle
validation in the same function.

Source: Fire23 detector lift AA, closing measured Fire22 misses
matching-engine-misprice-fire22-positive and
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
)


_SURFACE_NAME_RE = re.compile(
    r"(?i)(match|fill|execute|settle|liquidat|margin|maintenance|"
    r"mark|mark_to_market|notional|health|collateral|risk|pnl|"
    r"quote)"
)

_SURFACE_BODY_RE = re.compile(
    r"(?i)(fill_price|fill_value|execution_price|mark_price|margin|"
    r"maintenance_margin|liquidation_value|liquidation_price|"
    r"notional|position_value|health|collateral|risk|pnl|"
    r"quote_value|settlement_value)"
)

_STALE_LAST_PRICE_RE = re.compile(
    r"(?i)\b(?:self\.)?(?:book|orderbook|order_book|market|pair)"
    r"(?:\s*\.\s*|\s*::\s*)"
    r"(?:last_px|last_price|last_trade_price|last_fill_price)\b|"
    r"\b(?:last_px|last_price|last_trade_price|last_fill_price|"
    r"orderbook_last_px|spot_last_px)\b"
)

_BOOK_BID_ASK_RE = re.compile(
    r"(?i)\b(?:self\.)?(?:book|orderbook|order_book|market|pair)"
    r"(?:\s*\.\s*|\s*::\s*)"
    r"(?:best_bid|best_ask|bid_px|ask_px|bid_price|ask_price|"
    r"bid|ask)\b|"
    r"\b(?:best_bid|best_ask|bid_px|ask_px|bid_price|ask_price)\s*\("
)

_WRONG_BUY_SIDE_RE = re.compile(
    r"(?is)Side::Buy\s*=>\s*(?:[^,{};]|\{[^{}]*\}){0,180}"
    r"(?:best_bid|bid_px|bid_price|book\s*\.\s*bid|"
    r"book\s*\.\s*best_bid|orderbook\s*\.\s*best_bid|"
    r"order_book\s*\.\s*best_bid)"
)

_WRONG_SELL_SIDE_RE = re.compile(
    r"(?is)Side::Sell\s*=>\s*(?:[^,{};]|\{[^{}]*\}){0,180}"
    r"(?:best_ask|ask_px|ask_price|book\s*\.\s*ask|"
    r"book\s*\.\s*best_ask|orderbook\s*\.\s*best_ask|"
    r"order_book\s*\.\s*best_ask)"
)

_FRESH_PRICE_GUARD_RE = re.compile(
    r"(?i)(oracle|price_feed|pyth|chainlink|twap|vwap|ema|median|"
    r"mark_price_oracle|checked_mark|checked_price|validated_price|"
    r"validate_price|assert_price|fresh|freshness|stale|staleness|"
    r"max_age|max_delay|confidence|max_deviation|deviation|"
    r"snapshot|book_snapshot|current_book|current_mid|sequence|"
    r"version|height|slot|block_time|refreshed_at|assert_fresh|"
    r"ensure_fresh|price_for_side|quote_at_snapshot)"
)

_PRICE_USED_FOR_VALUE_RE = re.compile(
    r"(?i)(\*|/|\+|-|margin\s*=|mark_price\s*=|notional\s*=|"
    r"fill_price\s*=|fill_value\s*=|execution_price\s*=|"
    r"liquidation_value\s*=|liquidation_price\s*=|"
    r"position_value\s*=|health\s*=|collateral\s*=|risk\s*=|"
    r"\.margin\s*=|\.notional\s*=|\.health\s*=)"
)


def _is_matching_surface(name: str, body_nc: str) -> bool:
    return bool(_SURFACE_NAME_RE.search(name) or _SURFACE_BODY_RE.search(body_nc))


def _has_fresh_price_guard(body_nc: str) -> bool:
    return bool(_FRESH_PRICE_GUARD_RE.search(body_nc))


def _stale_last_price(body_nc: str) -> bool:
    if not _STALE_LAST_PRICE_RE.search(body_nc):
        return False
    if not _PRICE_USED_FOR_VALUE_RE.search(body_nc):
        return False
    return not _has_fresh_price_guard(body_nc)


def _wrong_side_book_price(body_nc: str) -> bool:
    return bool(
        _WRONG_BUY_SIDE_RE.search(body_nc) or _WRONG_SELL_SIDE_RE.search(body_nc)
    )


def _unsnapshotted_book_price(body_nc: str) -> bool:
    if not _BOOK_BID_ASK_RE.search(body_nc):
        return False
    if not _PRICE_USED_FOR_VALUE_RE.search(body_nc):
        return False
    return not _has_fresh_price_guard(body_nc)


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

        stale_last = _stale_last_price(body_nc)
        wrong_side = _wrong_side_book_price(body_nc)
        unsnapshotted = _unsnapshotted_book_price(body_nc)
        if not (stale_last or wrong_side or unsnapshotted):
            continue

        reasons = []
        if stale_last:
            reasons.append("stale orderbook last price")
        if wrong_side:
            reasons.append("wrong-side bid/ask selection")
        if unsnapshotted:
            reasons.append("orderbook price without fresh snapshot guard")

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` derives matching-engine price from "
                    f"{', '.join(reasons)} without an oracle-validated mark "
                    f"or current orderbook snapshot "
                    f"(matching-engine-misprice)."
                ),
            }
        )
    return hits
