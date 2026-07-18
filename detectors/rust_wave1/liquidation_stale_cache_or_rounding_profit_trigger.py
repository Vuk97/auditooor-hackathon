"""
liquidation_stale_cache_or_rounding_profit_trigger.py

Cross-family Rust lift for liquidation-trigger-poison.

Flags liquidation or borrow trigger logic that:
  1. consumes cached concentrated-liquidity collateral without a same-path
     live position refresh,
  2. computes max-liquidation collateral with a liquidator bonus while leaving
     the debt side unbounded, or
  3. rounds repaid debt shares down after fixing seized assets without a final
     protocol-favoring asset readjustment.

Capability posture: detector-fixture smoke only. A hit is source-review input,
not submit-ready proof.
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


_TRIGGER_FN_RE = re.compile(
    r"(?i)(borrow|liquidat|health|solv|collateral|value_of_position|"
    r"get_position_value|get_collateral|ltv|loan_to_value|icr|mcr)"
)
_CACHED_LIQUIDITY_RE = re.compile(
    r"(?i)(cached_liquidity|cachedLiquidity|cached_position_liquidity|"
    r"stored_liquidity|storedLiquidity|position_liquidity|positionLiquidity|"
    r"liquidity_at_deposit|liquidityAtDeposit|deposited_liquidity|"
    r"get_position_liquidity_at_deposit|liquidity_cache|account_liquidity|"
    r"accounts?\s*\[[^\]]+\]\s*\.\s*liquidity)"
)
_LIVE_LIQUIDITY_RE = re.compile(
    r"(?i)(get_current_liquidity|fetch_from_amm|query_amm_liquidity|"
    r"refresh_liquidity|sync_liquidity|update_liquidity|get_position_info|"
    r"(?:position_manager|nft_position_manager|pool)\s*\.\s*positions\s*\()"
)

_MAX_LIQ_FN_RE = re.compile(
    r"(?i)(calculate_max_liquidation|max_liquidat|max_liquidable|liquidation_bounds)"
)
_MAX_COLLATERAL_RE = re.compile(r"(?i)max_liquidable_collateral")
_MAX_DEBT_RE = re.compile(r"(?i)max_liquidable_debt|max_liquidable_repay")
_LIQUIDATION_BONUS_RE = re.compile(
    r"(?i)(liquidation_bonus|liq_bonus|liquidation_incentive|bonus|discount)"
)
_DEBT_SIDE_BOUND_RE = re.compile(
    r"(?i)(max_liquidable_debt\s*=\s*(?:cmp::)?min\s*\(|"
    r"min\s*\(\s*max_liquidable_debt|"
    r"max_liquidable_debt\s*=\s*max_liquidable_debt\s*\.min\s*\(|"
    r"max_liquidable_debt\s*=\s*position\.debt_amount\s*\.min\s*\()"
)
_DIRECT_DEBT_VALUE_RE = re.compile(
    r"(?i)max_liquidable_debt\s*=\s*(?:position\.)?debt_value\s*(?:as\s+\w+)?\s*;"
)

_REPAID_ASSETS_UP_RE = re.compile(
    r"(?is)repaid_?assets\s*=\s*[^;]*(to_assets_up|toAssetsUp|"
    r"mul_div_up|mulDivUp|w_div_up|wDivUp|ceil_div|ceilDiv|div_ceil)"
)
_REPAID_SHARES_DOWN_RE = re.compile(
    r"(?is)repaid_?shares\s*=\s*[^;]*(to_shares_down|toSharesDown|"
    r"mul_div_down|mulDivDown|w_div_down|wDivDown|floor)"
)
_FINAL_ASSET_READJUST_RE = re.compile(
    r"(?is)repaid_?assets\s*=\s*[^;]*(to_assets_up|toAssetsUp|"
    r"mul_div_up|mulDivUp|w_div_up|wDivUp)\s*\(\s*repaid_?shares|"
    r"repaid_?assets\s*=\s*[^;]*repaid_?shares[^;]*(to_assets_up|"
    r"toAssetsUp|mul_div_up|mulDivUp|w_div_up|wDivUp)"
)

_BAD_DEBT_BRANCH_RE = re.compile(
    r"(?i)(collateral\s*<\s*debt|debt\s*>\s*collateral|"
    r"collateral_value\s*<\s*debt_value|seized\s*<\s*debt|"
    r"recovered\s*<\s*debt|actual\w*\s*<\s*debt)"
)
_BAD_DEBT_HANDLER_RE = re.compile(
    r"(?i)(socialize_debt|accumulate_bad_debt|absorb_loss|record_bad_debt|"
    r"insurance_fund|bad_debt|bad_debt_fund|record_deficit|deficit_fund|"
    r"record_loss|treasury|return\s+Err|panic_with_error|panic!)"
)


def _matches_stale_cache(name: str, body: str) -> bool:
    if not _TRIGGER_FN_RE.search(name):
        return False
    if not _CACHED_LIQUIDITY_RE.search(body):
        return False
    return _LIVE_LIQUIDITY_RE.search(body) is None


def _matches_underbounded_max_liquidation(name: str, body: str) -> bool:
    if not _MAX_LIQ_FN_RE.search(name):
        return False
    if not _MAX_COLLATERAL_RE.search(body):
        return False
    if not _MAX_DEBT_RE.search(body):
        return False
    if not _LIQUIDATION_BONUS_RE.search(body):
        return False
    if _DEBT_SIDE_BOUND_RE.search(body):
        return False
    return True


def _matches_rounding_readjust_gap(name: str, body: str) -> bool:
    if not re.search(r"(?i)liquidat", name):
        return False
    if not _REPAID_ASSETS_UP_RE.search(body):
        return False
    if not _REPAID_SHARES_DOWN_RE.search(body):
        return False
    return _FINAL_ASSET_READJUST_RE.search(body) is None


def _matches_bad_debt_skip(name: str, body: str) -> bool:
    if not re.search(r"(?i)liquidat", name):
        return False
    branch = _BAD_DEBT_BRANCH_RE.search(body)
    if branch is None:
        return False
    window = body[branch.start():branch.start() + 350]
    return _BAD_DEBT_HANDLER_RE.search(window) is None


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
        if _matches_stale_cache(name, body):
            reasons.append("cached liquidity used in borrow or health trigger without live refresh")
        if _matches_underbounded_max_liquidation(name, body):
            if _DIRECT_DEBT_VALUE_RE.search(body):
                reasons.append("max liquidation debt uses raw debt value and is not capped")
            else:
                reasons.append("max liquidation applies bonus but never caps the debt side")
        if _matches_rounding_readjust_gap(name, body):
            reasons.append("debt shares round down without final repaid asset readjustment")
        if _matches_bad_debt_skip(name, body):
            reasons.append("bad-debt branch caps recovery without recording the deficit")

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
