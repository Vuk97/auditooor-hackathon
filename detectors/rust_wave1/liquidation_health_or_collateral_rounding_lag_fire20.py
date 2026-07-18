"""
liquidation_health_or_collateral_rounding_lag_fire20.py

Same-class Rust lift for `liquidation-trigger-poison`.

Flags liquidation logic that:
  1. validates only the first settlement consideration item and never rejects
     extra fake clearing-house NFTs,
  2. rounds collateral seized up while debt repaid rounds down, or
  3. uses stale EMA / smoothed health state to decide liquidatability without
     a same-path spot or refreshed-health cross-check.

Capability posture: detector-fixture smoke only. Hits are candidate evidence
for source review, not submit-ready proof.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
)


_SEAPORT_FN_RE = re.compile(
    r"(?i)(validate_)?liquidation_order|execute_liquidation|liquidat"
)
_SEAPORT_CONTEXT_RE = re.compile(
    r"(?is)collateral_nft[\s\S]{0,700}settlement_token[\s\S]{0,700}consideration|"
    r"collateral_nft[\s\S]{0,700}consideration[\s\S]{0,700}settlement_token|"
    r"consideration[\s\S]{0,700}settlement_token[\s\S]{0,700}collateral_nft|"
    r"consideration[\s\S]{0,700}collateral_nft[\s\S]{0,700}settlement_token"
)
_FIRST_CONSIDERATION_ONLY_RE = re.compile(
    r"(?is)order\.consideration\s*\[\s*0\s*\]\s*!=\s*self\.settlement_token|"
    r"consideration\s*\[\s*0\s*\][^;]{0,160}settlement_token|"
    r"settlement_token[^;]{0,160}consideration\s*\[\s*0\s*\]"
)
_EXTRA_CONSIDERATION_GUARD_RE = re.compile(
    r"(?is)consideration\.len\s*\(\s*\)\s*(?:!=|==|>|>=)\s*1|"
    r"consideration\s*\[\s*1\s*\.\.\s*\]|"
    r"consideration\.iter\s*\(\s*\)\s*\.skip\s*\(\s*1\s*\)|"
    r"authorized_clearing_nfts\s*\.\s*(?:contains_key|get)|"
    r"reject_extra_consideration|unauthorized"
)

_LIQUIDATION_FN_RE = re.compile(
    r"(?i)(liquidate|liquidation|seize_collateral|can_liquidate|is_liquidatable)"
)
_COLLATERAL_CEIL_RE = re.compile(
    r"(?is)(collateral|seiz)[a-zA-Z0-9_]*\s*=\s*[^;]*"
    r"\+\s*[^;]*-\s*1[^;]*(?:checked_div|/)|"
    r"(?:ceil_div|ceiling_div|div_ceil|mul_div_up|round_up)"
    r"[^;]*(?:collateral|seiz)|"
    r"(?:collateral|seiz)[^;]*(?:ceil_div|ceiling_div|div_ceil|mul_div_up|round_up)"
)
_DEBT_FLOOR_RE = re.compile(
    r"(?is)(debt_to_repay|debt_repaid|repay_amount|principal_paid|"
    r"repaid_debt)\s*=\s*[^;]*(?:checked_div|/|mul_div_down|floor)[^;]*;"
)
_DEBT_ROUND_UP_RE = re.compile(
    r"(?is)(debt_to_repay|debt_repaid|repay_amount|principal_paid|"
    r"repaid_debt)\s*=\s*[^;]*(?:ceil_div|ceiling_div|div_ceil|"
    r"mul_div_up|round_up|to_assets_up|to_shares_up)[^;]*;"
)

_EMA_READ_RE = re.compile(
    r"(?i)(\.ema\b|ema_price|smoothed_price|twap|time_weighted|"
    r"moving_average|rolling_price|avg_price|average_price|weighted_price)"
)
_SPOT_OR_REFRESH_RE = re.compile(
    r"(?i)(\.spot\b|spot_price|current_price|fresh_price|live_price|"
    r"latest_price|get_price_spot|refresh_health|sync_health|"
    r"update_health|reload_health|refresh_oracle|oracle\.get_price|"
    r"oracle\.latest_price|price_feed\.get)"
)


def _matches_first_only_settlement_pair(name: str, body: str) -> bool:
    if not _SEAPORT_FN_RE.search(name):
        return False
    if not _SEAPORT_CONTEXT_RE.search(body):
        return False
    if not _FIRST_CONSIDERATION_ONLY_RE.search(body):
        return False
    return _EXTRA_CONSIDERATION_GUARD_RE.search(body) is None


def _matches_collateral_up_debt_down(name: str, body: str) -> bool:
    if not _LIQUIDATION_FN_RE.search(name):
        return False
    if not _COLLATERAL_CEIL_RE.search(body):
        return False
    if not _DEBT_FLOOR_RE.search(body):
        return False
    return _DEBT_ROUND_UP_RE.search(body) is None


def _matches_ema_lag_liquidation(name: str, body: str) -> bool:
    if not _LIQUIDATION_FN_RE.search(name):
        return False
    if not _EMA_READ_RE.search(body):
        return False
    return _SPOT_OR_REFRESH_RE.search(body) is None


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body_node = fn_body(fn)
        if body_node is None:
            continue

        name = fn_name(fn, source)
        body = body_text_nocomment(body_node, source)
        reasons: list[str] = []

        if _matches_first_only_settlement_pair(name, body):
            reasons.append(
                "first settlement consideration item is validated but extra fake NFTs are not rejected"
            )
        if _matches_collateral_up_debt_down(name, body):
            reasons.append(
                "collateral seized rounds up while debt repaid rounds down"
            )
        if _matches_ema_lag_liquidation(name, body):
            reasons.append(
                "EMA or smoothed health state decides liquidation without spot refresh"
            )

        if not reasons:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:220],
            "message": (
                f"fn `{name}` matches liquidation-trigger-poison lift: "
                + "; ".join(reasons)
                + "."
            ),
        })
    return hits
