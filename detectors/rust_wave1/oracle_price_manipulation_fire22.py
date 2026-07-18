"""
oracle_price_manipulation_fire22.py

Fire22 Rust lift for oracle price manipulation.

Confirmed source:
- r94-loop-oracle-heartbeat-no-fallback-positive
- r94-loop-oracle-version-expired-stale-return-positive
- r94-loop-pmm-internal-price-manipulation-positive

Detector hits are candidate evidence only. The detector looks for Rust
price code that accepts stale heartbeat data, returns an expired oracle
version as valid, trusts a mutable cached price, or derives PMM/internal
reserve price without freshness and deviation/bounds validation.
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


DETECTOR_ID = "rust_wave1.oracle_price_manipulation_fire22"

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_PRICE_NAME_RE = re.compile(
    r"(?i)(price|oracle|quote|pmm|mark|settle|liquidat|collateral|"
    r"health|ltv|version|cache|feed)"
)

_PRICE_BODY_RE = re.compile(
    r"(?i)(price|oracle|feed|round|quote|collateral|debt|health|ltv|"
    r"settlement|notional|liquidat|cached_price|last_price)"
)

_TIMESTAMP_RE = re.compile(
    r"(?i)(updated_at|updatedAt|publish_time|publishTime|timestamp|"
    r"last_update|lastUpdate|last_refreshed|refreshed_at)"
)

_HEARTBEAT_RE = re.compile(
    r"(?i)(heartbeat|max_age|max_staleness|max_delay|staleness|ttl|"
    r"freshness|stale_after)"
)

_STALE_CHECK_RE = re.compile(
    r"(?is)(now|clock|current_time|block_time|timestamp)"
    r"[^;{}]{0,180}(saturating_sub|-)"
    r"[^;{}]{0,180}(updated_at|updatedAt|publish_time|publishTime|"
    r"last_update|lastUpdate|timestamp)"
    r"[^;{}]{0,180}(>|>=|<=|<)"
    r"[^;{}]{0,180}(heartbeat|max_age|max_staleness|max_delay|ttl|"
    r"stale_after)"
)

_STALE_AGE_VAR_RE = re.compile(
    r"(?is)\blet\s+(?P<age>age|stale_age|elapsed|delay)\s*=\s*"
    r"[^;{}]{0,180}(saturating_sub|-)"
    r"[^;{}]{0,180}(updated_at|updatedAt|publish_time|publishTime|"
    r"last_update|lastUpdate|timestamp)[^;{}]{0,80};"
    r"[^{}]{0,260}\b(?P=age)\b\s*(>|>=|<=|<)"
    r"[^;{}]{0,180}(heartbeat|max_age|max_staleness|max_delay|ttl|"
    r"stale_after)"
)

_STALE_REJECT_OR_FALLBACK_RE = re.compile(
    r"(?is)("
    r"ensure!?\s*\([^)]*(fresh|stale|heartbeat|max_age|max_staleness|ttl)|"
    r"require!?\s*\([^)]*(fresh|stale|heartbeat|max_age|max_staleness|ttl)|"
    r"assert!?\s*\([^)]*(fresh|stale|heartbeat|max_age|max_staleness|ttl)|"
    r"validate_[A-Za-z0-9_]*(fresh|stale|heartbeat)|"
    r"check_[A-Za-z0-9_]*(fresh|stale|heartbeat)|"
    r"ensure_[A-Za-z0-9_]*(fresh|stale|heartbeat)|"
    r"no_older_than|get_price_no_older_than|"
    r"if\s+[^{}]{0,260}(>|>=)[^{}]{0,260}"
    r"(heartbeat|max_age|max_staleness|max_delay|ttl|stale_after)"
    r"\s*\{[^{}]{0,220}(return\s+(Err|None)|Err\s*\(|bail!\s*\(|"
    r"fallback_|secondary_|backup_)"
    r")"
)

_RETURN_PRICE_RE = re.compile(
    r"(?is)(return\s+(Ok\s*\()?[^;{}]{0,160}(price|answer|round|quote)|"
    r"Ok\s*\([^)]*(price|answer|round|quote)|"
    r"\b(price|answer|quote|oracle_price|current_price|cached_price)\b\s*"
    r"(?:;?\s*)\})"
)

_VERSION_CTX_RE = re.compile(
    r"(?i)(OracleVersion|VersionedPrice|at_version|atVersion|"
    r"commit_version|commitVersion|version_at|get_version)"
)

_EXPIRED_RE = re.compile(
    r"(?i)(timed_out|timedOut|expired|commit_timeout|commitTimeout|"
    r"past_commit_deadline|pastCommitDeadline|grace_period|GRACE_PERIOD)"
)

_PREVIOUS_RETURN_RE = re.compile(
    r"(?is)return\s+(Ok\s*\()?[^;{}]{0,180}"
    r"(previous_version|last_version|previous\.price|previous_price|"
    r"self\.last_version|self\.previous_version|last\.price)"
    r"|Ok\s*\([^)]*(previous_version|last_version|previous\.price|"
    r"previous_price|self\.last_version|last\.price)"
)

_INVALID_VERSION_RE = re.compile(
    r"(?is)(valid\s*:\s*false|\.valid\s*=\s*false|is_invalid|"
    r"mark_invalid|invalidate|return\s+(Err|None)|Err\s*\(|"
    r"OracleVersion\s*\{[^{}]{0,220}valid\s*:\s*false)"
)

_CACHED_PRICE_RE = re.compile(
    r"(?i)\b(cached_price|cached_oracle_price|stored_price|saved_price|"
    r"last_price|last_good_price|manual_price|override_price)\b"
)

_CACHED_ASSIGN_RE = re.compile(
    r"(?is)(self|state|cache|oracle)"
    r"(?:\.[A-Za-z0-9_]+)*\."
    r"(cached_price|cached_oracle_price|stored_price|saved_price|"
    r"last_price|last_good_price|manual_price|override_price)"
    r"\s*="
)

_CACHED_RETURN_RE = re.compile(
    r"(?is)(return\s+(Ok\s*\()?[^;{}]{0,160}"
    r"(cached_price|last_price|stored_price|manual_price|override_price)|"
    r"Ok\s*\([^)]*(cached_price|last_price|stored_price|manual_price|"
    r"override_price))"
)

_PMM_CTX_RE = re.compile(
    r"(?i)(base_balance|quote_balance|pmm_state|pmm_price|internal_price|"
    r"reserve0|reserve1|pool_reserve|target_price|base_reserve|"
    r"quote_reserve)"
)

_PMM_PRICE_MATH_RE = re.compile(
    r"(?is)(base_balance|quote_balance|reserve0|reserve1|base_reserve|"
    r"quote_reserve)[^;{}]{0,220}([*/]|saturating_mul|checked_mul)|"
    r"([*/]|saturating_mul|checked_mul)[^;{}]{0,220}"
    r"(base_balance|quote_balance|reserve0|reserve1|base_reserve|"
    r"quote_reserve)"
)

_FRESHNESS_OR_BOUNDS_GUARD_RE = re.compile(
    r"(?is)("
    r"ensure_[A-Za-z0-9_]*(fresh|stale|deviation|bound|sanity)|"
    r"check_[A-Za-z0-9_]*(fresh|stale|deviation|bound|sanity)|"
    r"validate_[A-Za-z0-9_]*(fresh|stale|deviation|bound|sanity)|"
    r"no_older_than|get_price_no_older_than|"
    r"max_deviation|deviation_bps|within_tolerance|abs_diff|"
    r"sanity_price|external_oracle|oracle_price|chainlink|pyth|"
    r"twap|time_weighted|median|confidence|"
    r"ensure!?\s*\([^)]*(fresh|stale|deviation|max_age|max_deviation|"
    r"heartbeat|bound|sanity)|"
    r"require!?\s*\([^)]*(fresh|stale|deviation|max_age|max_deviation|"
    r"heartbeat|bound|sanity)|"
    r"assert!?\s*\([^)]*(fresh|stale|deviation|max_age|max_deviation|"
    r"heartbeat|bound|sanity)"
    r")"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _price_context(name: str, body_text: str) -> bool:
    return bool(_PRICE_NAME_RE.search(name) or _PRICE_BODY_RE.search(body_text))


def _heartbeat_stale_acceptance(name: str, body_text: str) -> str | None:
    if not _price_context(name, body_text):
        return None
    if not _TIMESTAMP_RE.search(body_text):
        return None
    if not _HEARTBEAT_RE.search(body_text):
        return None
    if not (_STALE_CHECK_RE.search(body_text) or _STALE_AGE_VAR_RE.search(body_text)):
        return None
    if _STALE_REJECT_OR_FALLBACK_RE.search(body_text):
        return None
    if not _RETURN_PRICE_RE.search(body_text):
        return None
    return "accepts or returns oracle price after heartbeat staleness is observed"


def _expired_version_return(name: str, signature: str, body_text: str) -> str | None:
    joined = f"{name}\n{signature}\n{body_text}"
    if not _VERSION_CTX_RE.search(joined):
        return None
    if not _EXPIRED_RE.search(body_text):
        return None
    if not _PREVIOUS_RETURN_RE.search(body_text):
        return None
    if _INVALID_VERSION_RE.search(body_text):
        return None
    return "returns a previous oracle version on expiry without marking it invalid"


def _mutable_cached_price(name: str, body_text: str) -> str | None:
    if not _price_context(name, body_text):
        return None
    if not _CACHED_PRICE_RE.search(body_text):
        return None
    if not (_CACHED_ASSIGN_RE.search(body_text) or _CACHED_RETURN_RE.search(body_text)):
        return None
    if _FRESHNESS_OR_BOUNDS_GUARD_RE.search(body_text):
        return None
    return "trusts mutable cached oracle price without freshness or deviation bounds"


def _pmm_internal_price(name: str, body_text: str) -> str | None:
    if not _price_context(name, body_text):
        return None
    if not _PMM_CTX_RE.search(body_text):
        return None
    if not _PMM_PRICE_MATH_RE.search(body_text):
        return None
    if _FRESHNESS_OR_BOUNDS_GUARD_RE.search(body_text):
        return None
    return "derives PMM/internal reserve price without freshness or deviation bounds"


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body_node = fn_body(fn)
        if body_node is None:
            continue

        signature = source[fn.start_byte:body_node.start_byte].decode(
            "utf-8", errors="replace"
        )
        body = _strip_strings(body_text_nocomment(body_node, source))

        reason = (
            _heartbeat_stale_acceptance(name, body)
            or _expired_version_return(name, signature, body)
            or _mutable_cached_price(name, body)
            or _pmm_internal_price(name, body)
        )
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
                    f"oracle price manipulation candidate in `{name}`: "
                    f"{reason}. Require freshness plus deviation/bounds "
                    "validation before price output or value movement. "
                    "attack_class=oracle-price-manipulation."
                ),
            }
        )

    return hits
