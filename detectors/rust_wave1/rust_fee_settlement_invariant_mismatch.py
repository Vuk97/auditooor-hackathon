"""
rust_fee_settlement_invariant_mismatch.py

Class-general sibling for Rust fee-redirect findings.

Flags fee settlement paths where the fee amount is routed through a value
sink without preserving the intended economic invariant:

1. A fee is transferred from a recipient-like party.
2. A fee harvest swap accepts zero minimum output.
3. A fee pool offsets user debt without a health or collateral check.

This intentionally generalizes across the existing instance detectors for
fee_charged_to_wrong_party, r94_loop_fee_harvest_swap_zero_min_out, and
r94_loop_debt_erased_via_fee_offset_without_collateral_check.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    functions_in_contractimpl,
    is_pub,
    line_col,
    snippet_of,
)


_FEE_NAME_RE = re.compile(
    r"\b(fee|fees|protocol_fee|platform_fee|treasury_fee|"
    r"harvest_fee|performance_fee|fee_pool|premium)\b",
    re.IGNORECASE,
)

_RECIPIENT_DEBIT_RE = re.compile(
    r"\.transfer\s*\(\s*"
    r"(?:recipient|receiver|beneficiary|to|dst|target)\s*(?:\.clone\(\))?\s*,"
    r"[\s\S]{0,160}\b(?:fee|protocol_fee|platform_fee|treasury_fee|premium)\b",
    re.IGNORECASE,
)

_FLASHLOAN_NAME_RE = re.compile(r"flash_?loan|flashloan", re.IGNORECASE)

_FLASHLOAN_REPAYMENT_RE = re.compile(
    r"\.transfer\s*\(\s*(?:receiver|borrower)\s*(?:\.clone\(\))?\s*,"
    r"\s*(?:env\.)?current_contract_address\s*\(\s*\)\s*,"
    r"\s*amount\s*\+\s*premium",
    re.IGNORECASE,
)

_FEE_HARVEST_FN_RE = re.compile(
    r"(charge|collect|harvest|convert|swap|sell|withdraw)_?"
    r"(fee|fees|profit|profits|premium|protocol_fee)?",
    re.IGNORECASE,
)

_SWAP_CALL_RE = re.compile(
    r"(\.swap\s*\(|\.exact_input\s*\(|\.exact_output\s*\(|"
    r"swap_exact_tokens_for_tokens\s*\(|router\s*\.\s*\w*swap)",
    re.IGNORECASE,
)

_ZERO_MIN_OUT_RE = re.compile(
    r"amount_out_minimum\s*:\s*0\b|"
    r"min_out\s*:\s*0\b|"
    r"min_amount_out\s*:\s*0\b|"
    r"amountOutMin(?:imum)?\s*:\s*0\b|"
    r",\s*0\s*,\s*0\s*\)",
    re.IGNORECASE,
)

_NONZERO_MIN_OUT_RE = re.compile(
    r"amount_out_minimum\s*:\s*(?!0\b)[A-Za-z_]\w*|"
    r"min_out\s*:\s*(?!0\b)[A-Za-z_]\w*|"
    r"min_amount_out\s*:\s*(?!0\b)[A-Za-z_]\w*|"
    r"expected_out\s*[-*]\s*\w+",
    re.IGNORECASE,
)

_DEBT_OFFSET_RE = re.compile(
    r"\b(user_debt|user_borrow|borrow_balance|position\s*\.\s*debt|"
    r"principal|debt_of\s*\()[\s\S]{0,80}"
    r"(-=|\=\s*[^;\n]+-)\s*[^;\n]*\b(fee|fee_pool|premium|protocol_fee)\b",
    re.IGNORECASE,
)

_HEALTH_CHECK_RE = re.compile(
    r"health_factor|check_health|require_healthy|is_solvent|assert_healthy|"
    r"collateral_ratio|collateralization_check|verify_collateral|"
    r"ensure_collateral|post_offset_health",
    re.IGNORECASE,
)


def _reason_for_hit(name: str, body: str) -> str | None:
    if (
        _FEE_NAME_RE.search(body)
        and _RECIPIENT_DEBIT_RE.search(body)
        and not (_FLASHLOAN_NAME_RE.search(name) and _FLASHLOAN_REPAYMENT_RE.search(body))
    ):
        return (
            f"fn `{name}` transfers a fee amount from a recipient-like "
            "party. Fee settlement must debit the payer or protocol fee "
            "source, not the payout sink."
        )

    if (
        _FEE_HARVEST_FN_RE.search(name)
        and _SWAP_CALL_RE.search(body)
        and _ZERO_MIN_OUT_RE.search(body)
        and not _NONZERO_MIN_OUT_RE.search(body)
    ):
        return (
            f"fn `{name}` performs a fee harvest swap with zero minimum "
            "output. The fee settlement path can redirect value through "
            "sandwichable execution."
        )

    if _DEBT_OFFSET_RE.search(body) and not _HEALTH_CHECK_RE.search(body):
        return (
            f"fn `{name}` offsets debt with a fee pool but lacks a health "
            "or collateralization check. Fee accounting can erase debt "
            "without preserving solvency."
        )

    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        reason = _reason_for_hit(name, body_nc)
        if reason is None:
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"{reason} This is a Rust fee-redirect class sibling, "
                "not an instance-specific fee detector."
            ),
        })
    return hits
