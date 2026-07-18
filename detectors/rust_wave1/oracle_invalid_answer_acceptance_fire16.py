"""
oracle_invalid_answer_acceptance_fire16.py

Flags Rust oracle consumers that accept invalid oracle answers into value
movement or canonical price paths:

1. A signed Chainlink-style answer is cast to an unsigned price without a
   strict positive-answer guard.
2. A Pyth-style confidence check compares a signed delta without taking the
   absolute value.
3. A caller-supplied feed id is used to fetch a price without binding it to
   the configured asset feed.

This Fire16 lift closes the oracle-price-manipulation recall gap highlighted
by the Fire15 Rust post-priority report.
"""

from __future__ import annotations

import re

from _util import (
    IDENT,
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


DETECTOR_ID = "rust_wave1.oracle_invalid_answer_acceptance_fire16"

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')

_PRICE_GETTER_NAME_RE = re.compile(
    r"(?i)(current_price|get_price|price_of|fetch_price|query_price|"
    r"latest_price|usd_price|get_asset_price|read_price)"
)

_VALUE_CONTEXT_RE = re.compile(
    r"(?i)(borrow|mint|redeem|liquidat|settle|collateral|health|ltv|"
    r"margin|position|share|vault|loan|debt|index|payout|withdraw|"
    r"deposit|notional)"
)

_VALUE_BODY_RE = re.compile(
    r"(?i)("
    r"(amount|collateral|debt|shares|notional|margin|payout|position)"
    r"\s*[*/+\-]\s*(price|oracle_price|answer)|"
    r"(price|oracle_price|answer)\s*[*/+\-]\s*"
    r"(amount|collateral|debt|shares|notional|margin|payout|position)|"
    r"(collateral_value|health_factor|ltv|borrow_value|settlement|"
    r"index_value|notional_value|liquidation_bonus|seize)"
    r"\s*(?:=|:|[+\-*/]?=)|"
    r"\.(mint|redeem|borrow|repay|liquidat|settle|withdraw|deposit)"
    r"\s*\(|"
    r"(transfer|transfer_from|safe_transfer|send_tokens)\s*\("
    r")"
)

_LATEST_ORACLE_RE = re.compile(
    r"(?i)(latest_round_data|latestRoundData|latest_answer|latestAnswer|"
    r"aggregator\s*\.\s*latest|oracle\s*\.\s*latest)"
)

_SIGNED_CAST_RE = re.compile(
    fr"(?i)("
    fr"{IDENT}answer\s+as\s+u(?:64|128|256)|"
    fr"u(?:64|128|256)::from\s*\(\s*{IDENT}answer|"
    fr"uint256\s*\(\s*{IDENT}answer|"
    fr"{IDENT}answer\s*\.\s*(?:unsigned_abs|abs)\s*\("
    fr")"
)

_POSITIVE_ANSWER_GUARD_RE = re.compile(
    fr"(?i)("
    fr"require!?\s*\([^)]*{IDENT}answer\s*>\s*0|"
    fr"ensure!?\s*\([^)]*{IDENT}answer\s*>\s*0|"
    fr"assert!?\s*\([^)]*{IDENT}answer\s*>\s*0|"
    fr"if\s+{IDENT}answer\s*<=?\s*0\s*\{{|"
    fr"{IDENT}answer\s*\.\s*is_positive\s*\(|"
    fr"validate_[A-Za-z0-9_]*(?:positive|answer)|"
    fr"checked_[A-Za-z0-9_]*(?:positive|answer)"
    fr")"
)

_CONFIDENCE_CONTEXT_RE = re.compile(
    r"(?i)(pyth|price_feed|PriceFeed|\bconf\b|\bconfidence\b|"
    r"conf_interval|price_conf)"
)

_SIGNED_DELTA_COMPARE_RE = re.compile(
    r"(?is)("
    r"\b(?:delta|deviation|diff)\b\s*[<>]\s*"
    r"[A-Za-z0-9_\.]*(?:conf|confidence|conf_interval)|"
    r"\([^)]*(?:new_price|current_price|current_index|old_price)"
    r"[^)]*-[^)]*\)\s*[<>]\s*"
    r"[A-Za-z0-9_\.]*(?:conf|confidence|conf_interval)|"
    r"\b(?:new_price|new_px|price)\s*-\s*"
    r"(?:current_price|current_index|old_price|index)\s*[<>]\s*"
    r"[A-Za-z0-9_\.]*(?:conf|confidence|conf_interval)"
    r")"
)

_ABS_DELTA_GUARD_RE = re.compile(
    r"(?i)(\.abs\s*\(|abs\s*\(|saturating_abs|checked_abs|"
    r"\.unsigned_abs|absolute_deviation|abs_diff)"
)

_PRICE_FETCH_RE = re.compile(
    r"(?i)("
    r"\.get_price\s*\(|\.get_latest_price\s*\(|"
    r"pyth::get_price_feed\s*\(|\.price_of_feed\s*\(|"
    r"\.price_of\s*\(|\.latest_price\s*\(|"
    r"reflector::get_price\s*\(|\.price_feed\s*\(\s*&?feed|"
    r"load_price_feed_from_account(?:_info)?\s*\(|"
    r"price_feed_from_account(?:_info)?\s*\(|"
    r"\.get_price_unchecked\s*\(|\.get_price_no_older_than\s*\(|"
    r"\.get_current_price\s*\("
    r")"
)

_FEED_ID_RE = re.compile(
    r"(?i)\b(feed_id|price_id|feed_pubkey|feed_account|oracle_account|"
    r"price_feed_account|feed_account_info|oracle_pubkey)\b"
)

_FEED_ID_VALIDATION_RE = re.compile(
    r"(?is)("
    r"(?:feed_id|price_id|feed_pubkey|oracle_account)\s*==|"
    r"==\s*(?:feed_id|price_id|feed_pubkey|oracle_account)|"
    r"require!?\s*\([^)]*(?:feed_id|price_id|feed_pubkey|oracle_account)"
    r"[^)]*==|"
    r"require!?\s*\([^)]*==[^)]*"
    r"(?:feed_id|price_id|feed_pubkey|oracle_account)|"
    r"ensure!?\s*\([^)]*(?:feed_id|price_id|feed_pubkey|oracle_account)"
    r"[^)]*==|"
    r"assert_eq!?\s*\([^)]*(?:feed_id|price_id|feed_pubkey|oracle_account)|"
    r"whitelist_feeds\s*\.\s*contains\s*\([^)]*"
    r"(?:feed_id|price_id|feed_pubkey)|"
    r"(?:price_feed|feed|pf)\s*\.\s*(?:id|feed_id|price_id)\s*==|"
    r"==\s*(?:price_feed|feed|pf)\s*\.\s*(?:id|feed_id|price_id)|"
    r"\.get_price_identifier\s*\(\s*\)\s*==|"
    r"==\s*\w+\.get_price_identifier\s*\("
    r")"
)


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _strip_strings(text: str) -> str:
    return _STRING_RE.sub(_blank, text)


def _has_value_or_price_context(name: str, body_text: str) -> bool:
    return bool(
        _PRICE_GETTER_NAME_RE.search(name)
        or _VALUE_CONTEXT_RE.search(name)
        or _VALUE_BODY_RE.search(body_text)
    )


def _signed_answer_cast_hit(name: str, body_text: str) -> bool:
    if not _has_value_or_price_context(name, body_text):
        return False
    if not _LATEST_ORACLE_RE.search(body_text):
        return False
    if not _SIGNED_CAST_RE.search(body_text):
        return False
    return _POSITIVE_ANSWER_GUARD_RE.search(body_text) is None


def _confidence_signed_delta_hit(name: str, body_text: str) -> bool:
    if not _has_value_or_price_context(name, body_text):
        return False
    if not _CONFIDENCE_CONTEXT_RE.search(body_text):
        return False
    if not _SIGNED_DELTA_COMPARE_RE.search(body_text):
        return False
    return _ABS_DELTA_GUARD_RE.search(body_text) is None


def _feed_id_mismatch_hit(name: str, signature_text: str, body_text: str) -> bool:
    if not _has_value_or_price_context(name, body_text):
        return False
    if not _FEED_ID_RE.search(signature_text):
        return False
    if not _PRICE_FETCH_RE.search(body_text):
        return False
    if _FEED_ID_VALIDATION_RE.search(body_text):
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

        signature = source[fn.start_byte:body.start_byte].decode(
            "utf-8", errors="replace"
        )
        body_text = _strip_strings(body_text_nocomment(body, source))

        reasons = []
        if _signed_answer_cast_hit(name, body_text):
            reasons.append("signed oracle answer cast without positive guard")
        if _confidence_signed_delta_hit(name, body_text):
            reasons.append("signed confidence delta accepted without abs guard")
        if _feed_id_mismatch_hit(name, signature, body_text):
            reasons.append("caller-supplied feed id used without asset binding")

        if not reasons:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` accepts invalid oracle answer material "
                    f"into a price or value path: {', '.join(reasons)} "
                    "(oracle-invalid-answer-acceptance-fire16)."
                ),
            }
        )

    return hits
