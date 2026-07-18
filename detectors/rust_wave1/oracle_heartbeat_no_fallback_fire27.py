"""
oracle_heartbeat_no_fallback_fire27.py

Fire27 Rust companion detector for oracle-price-manipulation paths where
heartbeat age is available but price output is still used in collateral,
health, or liquidation math without a fallback, fail-closed stale check, or
age comparison.

Rule 37 provenance:
- local miss: r94-loop-oracle-heartbeat-no-fallback-positive
- local support: detectors/rust_wave1/r94_loop_oracle_heartbeat_no_fallback.py
- attack_class: oracle-price-manipulation

Detector hits are candidate evidence only. R40/R80 proof still requires a
real in-scope PoC before any finding can cite the result.
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


DETECTOR_ID = "rust_wave1.oracle_heartbeat_no_fallback_fire27"

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_PRICE_CONTEXT_RE = re.compile(
    r"(?i)(price|oracle|feed|round|answer|collateral|debt|borrow|"
    r"health|ltv|liquidat|margin|notional|value)"
)

_TIMESTAMP_RE = re.compile(
    r"(?i)(updated_at|updatedAt|publish_time|publishTime|timestamp|"
    r"last_update|lastUpdate|slot_time|block_time)"
)

_HEARTBEAT_RE = re.compile(
    r"(?i)(heartbeat|max_heartbeat|max_age|max_staleness|max_delay|"
    r"staleness|freshness|ttl|stale_after)"
)

_AGE_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?"
    r"(?:age|stale_age|elapsed|delay|oracle_age|heartbeat_age)\s*=\s*"
    r"[^;{}]{0,220}(?:saturating_sub|-)"
    r"[^;{}]{0,220}"
    r"(?:updated_at|updatedAt|publish_time|publishTime|timestamp|"
    r"last_update|lastUpdate|slot_time|block_time)[^;{}]{0,80};"
)

_DIRECT_AGE_COMPARE_RE = re.compile(
    r"(?is)(?:now|clock|current_time|block_time|slot_time|timestamp)"
    r"[^;{}]{0,220}(?:saturating_sub|-)"
    r"[^;{}]{0,220}"
    r"(?:updated_at|updatedAt|publish_time|publishTime|last_update|"
    r"lastUpdate|timestamp)"
    r"[^;{}]{0,180}(?:>|>=|<|<=)"
    r"[^;{}]{0,180}"
    r"(?:heartbeat|max_heartbeat|max_age|max_staleness|max_delay|ttl|"
    r"stale_after|freshness)"
)

_AGE_VAR_COMPARE_RE = re.compile(
    r"(?is)\b(?:age|stale_age|elapsed|delay|oracle_age|heartbeat_age)\b"
    r"[^;{}]{0,80}(?:>|>=|<|<=)[^;{}]{0,160}"
    r"(?:heartbeat|max_heartbeat|max_age|max_staleness|max_delay|ttl|"
    r"stale_after|freshness)"
    r"|"
    r"(?:heartbeat|max_heartbeat|max_age|max_staleness|max_delay|ttl|"
    r"stale_after|freshness)"
    r"[^;{}]{0,80}(?:>|>=|<|<=)[^;{}]{0,160}"
    r"\b(?:age|stale_age|elapsed|delay|oracle_age|heartbeat_age)\b"
)

_FAIL_CLOSED_RE = re.compile(
    r"(?is)("
    r"ensure!?\s*\([^)]*(fresh|stale|heartbeat|max_age|max_staleness|ttl)|"
    r"require!?\s*\([^)]*(fresh|stale|heartbeat|max_age|max_staleness|ttl)|"
    r"assert!?\s*\([^)]*(fresh|stale|heartbeat|max_age|max_staleness|ttl)|"
    r"validate_[A-Za-z0-9_]*(fresh|stale|heartbeat|max_age)|"
    r"check_[A-Za-z0-9_]*(fresh|stale|heartbeat|max_age)|"
    r"ensure_[A-Za-z0-9_]*(fresh|stale|heartbeat|max_age)|"
    r"no_older_than|get_price_no_older_than|"
    r"return\s+(?:Err|None)\b|Err\s*\(|bail!\s*\(|panic!\s*\("
    r")"
)

_FALLBACK_RE = re.compile(
    r"(?i)(fallback|secondary|backup|last_good_price|lastGoodPrice|"
    r"circuit_breaker|circuitBreaker|pause_market|halt_market)"
)

_PRICE_TERM_RE = (
    r"(?:price|answer|oracle_price|feed_price|round_price|"
    r"current_price|latest_price|report_price|round\.answer|"
    r"round\.price|report\.price|feed\.price)"
)

_VALUE_TERM_RE = (
    r"(?:collateral|debt|borrow|health|ltv|liquidat|margin|"
    r"notional|position|loan|value)"
)

_VALUE_PRICE_MATH_RE = re.compile(
    rf"(?is)("
    rf"{_VALUE_TERM_RE}[^;{{}}]{{0,220}}"
    rf"(?:\*|/|saturating_mul|checked_mul|saturating_div|checked_div)"
    rf"[^;{{}}]{{0,220}}{_PRICE_TERM_RE}"
    rf"|{_PRICE_TERM_RE}[^;{{}}]{{0,220}}"
    rf"(?:\*|/|saturating_mul|checked_mul|saturating_div|checked_div)"
    rf"[^;{{}}]{{0,220}}{_VALUE_TERM_RE}"
    rf")"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _has_age_compare(body: str) -> bool:
    return bool(_DIRECT_AGE_COMPARE_RE.search(body) or _AGE_VAR_COMPARE_RE.search(body))


def _is_unchecked_heartbeat_price_math(name: str, body: str) -> bool:
    joined = f"{name}\n{body}"
    if not _PRICE_CONTEXT_RE.search(joined):
        return False
    if not _TIMESTAMP_RE.search(body):
        return False
    if not _HEARTBEAT_RE.search(body):
        return False
    if not _AGE_ASSIGN_RE.search(body):
        return False
    if _has_age_compare(body):
        return False
    if _FALLBACK_RE.search(body):
        return False
    if _FAIL_CLOSED_RE.search(body):
        return False
    return bool(_VALUE_PRICE_MATH_RE.search(body))


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
        if not _is_unchecked_heartbeat_price_math(name, body):
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
                    f"oracle heartbeat no fallback candidate in `{name}`: "
                    "heartbeat age is computed but not compared or enforced "
                    "before oracle price enters value or liquidation math. "
                    "Require fail-closed freshness validation or fallback "
                    "before collateral, debt, health, or liquidation math. "
                    "attack_class=oracle-price-manipulation."
                ),
            }
        )

    return hits
