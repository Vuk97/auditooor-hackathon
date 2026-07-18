"""
matching_engine_misprice_unbound_underlying_fire23.py

Flags Rust matching-engine and perpetual valuation functions that accept a
caller-supplied or externally passed underlying, mark, index, or oracle price
and use it directly for margin, liquidation, health, notional, or fill value
without binding that price to a fresh oracle/feed snapshot, market id, pair id,
or deviation check.

Confirmed source:
- r94-loop-perp-underlying-px-from-orderbook-last-px-positive
- matching-engine-misprice-fire22-positive

Detector hits are candidate evidence only.
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


DETECTOR_ID = "rust_wave1.matching_engine_misprice_unbound_underlying_fire23"

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_SURFACE_NAME_RE = re.compile(
    r"(?i)(match|fill|execute|settle|liquidat|margin|maintenance|"
    r"mark_to_market|position_value|notional|health|collateral|risk|pnl)"
)

_SURFACE_BODY_RE = re.compile(
    r"(?i)(margin|maintenance_margin|liquidation_value|fill_value|"
    r"notional|position_value|health|collateral_required|risk|pnl|"
    r"equity|settlement|mark_to_market|execute_fill|match_order)"
)

_EXTERNAL_PRICE_RE = re.compile(
    r"(?i)(?P<field>\b(?:request|params|payload|quote|order|input|"
    r"fill|liquidation_request|margin_request)\s*\.\s*"
    r"(?:underlying_price|underlying_px|mark_price|mark_px|index_price|"
    r"index_px|oracle_price|oracle_px)\b)"
    r"|(?P<plain>\b(?:underlying_price|underlying_px|mark_price|mark_px|"
    r"index_price|index_px|oracle_price|oracle_px)\b)"
)

_PRICE_PARAM_RE = re.compile(
    r"(?i)\b(underlying_price|underlying_px|mark_price|mark_px|"
    r"index_price|index_px|oracle_price|oracle_px)\s*:"
)

_VALUE_KEYWORD_RE = re.compile(
    r"(?i)(margin|maintenance|liquidation|fill_value|fill_price|notional|"
    r"position_value|health|collateral|required_margin|pnl|equity|"
    r"mark_to_market)"
)

_VALUE_MATH_RE = re.compile(
    r"(?is)("
    r"(margin|maintenance|liquidation|fill_value|fill_price|notional|"
    r"position_value|health|collateral|required_margin|pnl|equity)"
    r"[^;{}]{0,220}"
    r"(underlying_price|underlying_px|mark_price|mark_px|index_price|"
    r"index_px|oracle_price|oracle_px)"
    r"|"
    r"(underlying_price|underlying_px|mark_price|mark_px|index_price|"
    r"index_px|oracle_price|oracle_px)"
    r"[^;{}]{0,220}"
    r"(\*|/|saturating_mul|checked_mul|saturating_div|checked_div)"
    r"|"
    r"(request|params|payload|quote|order|input|fill|liquidation_request|"
    r"margin_request)\s*\.\s*"
    r"(underlying_price|underlying_px|mark_price|mark_px|index_price|"
    r"index_px|oracle_price|oracle_px)"
    r"[^;{}]{0,220}"
    r"(\*|/|saturating_mul|checked_mul|saturating_div|checked_div)"
    r"|"
    r"(self|state|account|position)\s*\.[A-Za-z0-9_]*(margin|notional|"
    r"liquidation|fill|health|collateral|pnl|equity)[A-Za-z0-9_]*"
    r"\s*=[^;{}]{0,220}"
    r"(underlying_price|underlying_px|mark_price|mark_px|index_price|"
    r"index_px|oracle_price|oracle_px)"
    r")"
)

_PRICE_BINDING_RE = re.compile(
    r"(?is)("
    r"oracle_snapshot|price_snapshot|feed_snapshot|snapshot_price|"
    r"price_feed|oracle_feed|mark_price_oracle|index_price_oracle|"
    r"get_price_no_older_than|checked_mark_price|checked_index_price|"
    r"checked_oracle_price|fetch_oracle_price|read_oracle_price|"
    r"oracle\s*\.\s*(?:get|read|fetch|price)|"
    r"(ensure|require|assert|check|validate)_[A-Za-z0-9_]*"
    r"(fresh|stale|age|market|pair|feed|oracle|deviation|confidence|"
    r"snapshot|price)|"
    r"(ensure|require|assert|check|validate)!?\s*\([^)]*"
    r"(fresh|stale|max_age|market_id|pair_id|feed_id|oracle|deviation|"
    r"confidence|snapshot|updated_at|publish_time|timestamp)|"
    r"(market_id|pair_id|feed_id|symbol|instrument_id)[^;{}]{0,180}"
    r"(==|!=|matches|bind|ensure|require|assert|check|validate)|"
    r"(max_age|staleness|freshness|heartbeat|updated_at|publish_time|"
    r"timestamp|confidence|max_deviation|deviation_bps|within_tolerance|"
    r"abs_diff|sanity_price)"
    r")"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _sig_text(fn, source: bytes) -> str:
    return text_of(fn, source).split("{", 1)[0]


def _is_matching_surface(name: str, body_text: str) -> bool:
    return bool(_SURFACE_NAME_RE.search(name) or _SURFACE_BODY_RE.search(body_text))


def _has_external_price(signature: str, body_text: str) -> bool:
    if _PRICE_PARAM_RE.search(signature):
        return True
    return bool(_EXTERNAL_PRICE_RE.search(body_text))


def _uses_price_in_value_path(body_text: str) -> bool:
    if not _VALUE_KEYWORD_RE.search(body_text):
        return False
    return bool(_VALUE_MATH_RE.search(body_text))


def _has_price_binding(signature: str, body_text: str) -> bool:
    return bool(_PRICE_BINDING_RE.search(f"{signature}\n{body_text}"))


def _unbound_external_price(fn, source: bytes, body_text: str) -> bool:
    signature = _strip_strings(_sig_text(fn, source))
    body_clean = _strip_strings(body_text)
    if not _has_external_price(signature, body_clean):
        return False
    if not _uses_price_in_value_path(body_clean):
        return False
    return not _has_price_binding(signature, body_clean)


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
        body_text = body_text_nocomment(body, source)
        if not _is_matching_surface(name, body_text):
            continue
        if not _unbound_external_price(fn, source, body_text):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` uses a caller-supplied or externally "
                    f"passed price in matching-engine valuation without "
                    f"fresh oracle/feed snapshot, market or pair binding, "
                    f"or deviation validation "
                    f"(matching-engine-misprice)."
                ),
            }
        )
    return hits
