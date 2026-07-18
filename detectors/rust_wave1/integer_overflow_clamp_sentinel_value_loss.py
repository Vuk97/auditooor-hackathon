"""
integer_overflow_clamp_sentinel_value_loss.py

Flags Rust value-moving fee, debt, liquidity, or settlement math where
overflow, underflow, or narrow-cast risk is handled by silently clamping
to zero, a max sentinel, or an input cap, then applying that clamped
amount to protocol accounting.

Lift anchors:
  - amm-protocol-fee-truncates-when-lp-fee-zero
  - bond-debt-decay-underflow

The detector is intentionally accounting-scoped. Generic saturating math
without a fee, debt, swap, settlement, or balance sink is ignored.
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


_ACCOUNTING_CONTEXT_RE = re.compile(
    r"(?i)(fee|protocol|lp_fee|swap|amount|debt|decay|bond|market|"
    r"liquidit|liquidity|reserve|share|asset|balance|settle|settlement|"
    r"payout|withdraw|deposit|mint|burn|repay|borrow|collateral|price)"
)

_VALUE_EFFECT_RE = re.compile(
    r"(?i)(return\s+|self\.[A-Za-z0-9_]*(fee|debt|liquid|reserve|share|"
    r"asset|balance|settle|payout|price)[A-Za-z0-9_]*\s*(?:\+=|-=|=)|"
    r"\.(?:insert|set|push)\s*\(|transfer|mint|burn|credit|debit|"
    r"withdraw|deposit|repay|borrow|settle)"
)

_FEE_SPLIT_RE = re.compile(
    r"(?i)(amount_in|amount|input|step\.amount_in)\s*\+\s*(fee_amount|fee)"
    r"[\s\S]{0,140}?\*\s*(protocol_fee|protocol_bps|protocol_fee_bps)"
    r"\s*/\s*(pips_denominator|pips|1_?000_?000|fee_denominator)"
)

_FEE_EXACT_ZERO_LP_RE = re.compile(
    r"(?i)(swap_fee\s*==\s*protocol_fee|protocol_fee\s*==\s*swap_fee|"
    r"lp_fee\s*==\s*0|fee_amount\s*;[\s\S]{0,80}else|"
    r"protocol_fee_amount\s*=\s*fee_amount)"
)

_SILENT_CLAMP_RE = re.compile(
    r"(?i)("
    r"checked_(?:sub|add|mul)\s*\([^;]{1,180}\)\s*"
    r"\.\s*unwrap_or(?:_default)?\s*\(\s*"
    r"(?:0|[ui](?:8|16|32|64|128|size)::MAX|u256::MAX|i256::MAX|"
    r"[A-Z][A-Z0-9_]*_MAX|MAX_[A-Z0-9_]+)\s*\)"
    r"|"
    r"\.\s*saturating_(?:sub|add|mul)\s*\("
    r"|"
    r"\.\s*min\s*\(\s*(?:u(?:8|16|32|64|128|size)::MAX|"
    r"[A-Z][A-Z0-9_]*_MAX|MAX_[A-Z0-9_]+)\s+as\s+u(?:8|16|32|64|128|size)"
    r"\s*\)\s+as\s+u(?:8|16|32|64|128|size)"
    r"|"
    r"std::cmp::min\s*\([^;]{1,160},\s*(?:u(?:8|16|32|64|128|size)::MAX|"
    r"[A-Z][A-Z0-9_]*_MAX|MAX_[A-Z0-9_]+)"
    r")"
)

_SAFE_DISPOSITION_RE = re.compile(
    r"(?i)(ok_or|ok_or_else|return\s+Err|Err\s*\(|map_err|"
    r"refund|refund_unused|residual|remainder|dust|carry_forward|"
    r"excess|unused_amount|checked_(?:sub|add|mul)\s*\([^;]{1,180}\)"
    r"\s*\?\s*)"
)


def _has_accounting_context(name: str, body: str) -> bool:
    return bool(_ACCOUNTING_CONTEXT_RE.search(name) or _ACCOUNTING_CONTEXT_RE.search(body))


def _fee_split_hit(body: str) -> bool:
    if not _FEE_SPLIT_RE.search(body):
        return False
    if _FEE_EXACT_ZERO_LP_RE.search(body):
        return False
    return bool(_VALUE_EFFECT_RE.search(body))


def _silent_clamp_hit(body: str) -> bool:
    if not _SILENT_CLAMP_RE.search(body):
        return False
    if _SAFE_DISPOSITION_RE.search(body):
        return False
    return bool(_VALUE_EFFECT_RE.search(body))


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source) or not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _has_accounting_context(name, body_nc):
            continue

        reasons: list[str] = []
        if _fee_split_hit(body_nc):
            reasons.append("protocol fee split rounds through the generic formula")
        if _silent_clamp_hit(body_nc):
            reasons.append("overflow or underflow path silently clamps before accounting")

        if not reasons:
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"pub fn `{name}` has integer-overflow-clamp-sentinel-value-loss: "
                    + "; ".join(reasons)
                    + ". Add an exact fee branch, checked error path, refund, or residual accounting."
                ),
            }
        )
    return hits
