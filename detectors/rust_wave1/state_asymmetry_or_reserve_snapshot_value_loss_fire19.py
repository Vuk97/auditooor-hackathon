"""
state_asymmetry_or_reserve_snapshot_value_loss_fire19.py

Recall lift for Rust fund-loss-via-arithmetic misses where value-bearing
state is computed from stale reserves, stale ticks, stale compensation
snapshots, or one-sided debit and credit math.

Detector hits are candidate evidence only. They are not finding evidence.
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


_VALUE_FN_RE = re.compile(
    r"(?i)(claim|redeem|withdraw|burn|exit|unwind|reallocate|rebalance|"
    r"release|collect|settle|compensate|payout|swap)"
)
_VALUE_MOVE_RE = re.compile(
    r"(?i)(\.transfer\s*\(|::transfer\s*\(|token::transfer\s*\(|"
    r"\.try_transfer\s*\(|\.mint_to\s*\(|\.send\s*\(|pay_out\s*\(|"
    r"payout\s*\(|release_funds\s*\(|credit_to_user\s*\()"
)
_ACCOUNTING_RESET_RE = re.compile(
    r"(?i)(set_claim(ed)?\s*\(|mark_claim(ed)?\s*\(|"
    r"set_(claimed|consumed|redeemed|processed)\s*\(|"
    r"mark_(claimed|consumed|redeemed|processed)\s*\(|"
    r"(claimed|consumed|redeemed|processed)[A-Za-z0-9_]*\s*=\s*(true|1)|"
    r"\.remove\s*\(|\.take\s*\(|\.set\s*\([^;]+,\s*&?0(?:[iu]\d+)?|"
    r"\.insert\s*\([^;]+,\s*&?0(?:[iu]\d+)?|-=|checked_sub\s*\(|"
    r"saturating_sub\s*\(|wrapping_sub\s*\(|debit_[A-Za-z0-9_]*\s*\(|"
    r"deduct_[A-Za-z0-9_]*\s*\(|consume_[A-Za-z0-9_]*\s*\(|"
    r"reset_[A-Za-z0-9_]*\s*\()"
)

_STALE_VALUE_RE = re.compile(
    r"(?i)(impermanent_loss|il_compensation|il_protect|compensate_il|"
    r"compensation_snapshot|snapshot_compensation|snapshot_reserve|"
    r"snapshot_tick|stale_reserve|stale_tick|current_reserve|"
    r"protocol_reserve|protocol_reserves|reserve_a|reserve_b|reserve0|"
    r"reserve1|tick_lower|tick_upper)"
)
_STALE_CONTEXT_RE = re.compile(
    r"(?i)(impermanent_loss|il_compensation|il_protect|compensate_il|"
    r"compensation|snapshot|stale_|current_reserve|protocol_reserve|"
    r"protocol_reserves|tick_lower|tick_upper)"
)
_VALUE_MATH_RE = re.compile(
    r"(?is)(impermanent_loss|il_compensation|compensation|snapshot|"
    r"reserve|shares|liquidity|claim|payout)[^;]{0,260}"
    r"(\+|\*|/|checked_mul\s*\(|checked_div\s*\(|saturating_add\s*\()"
)
_FRESHNESS_GUARD_RE = re.compile(
    r"(?i)(twap|time_weighted|vault_oracle|snapshot_block|delay_window|"
    r"rolling_average|refresh_(reserve|reserves|tick|ticks|snapshot)|"
    r"snapshot_reserve\s*\(|"
    r"sync_(reserve|reserves|tick|ticks|state)|"
    r"update_(reserve|reserves|tick|ticks|snapshot)|"
    r"capture_(reserve|reserves|tick|ticks|snapshot)|"
    r"settle_(reserve|reserves|tick|ticks|state)|"
    r"recompute_(reserve|reserves|tick|ticks|snapshot))"
)

_POOL_BURN_RE = re.compile(
    r"(?i)(pool|uniswap|v3_pool|nft_position_manager)\s*\.\s*burn\s*\(\s*"
    r"(tick_lower|tickLower|tl)\s*,\s*(tick_upper|tickUpper|tu)"
)
_OWNER_OR_PAIR_KEY_RE = re.compile(
    r"(?i)(position_key\s*\(|pair_liquidity_at\s*\(|owner_liquidity|"
    r"pair_liquidity|liquidity_by_pair|liquidity_by_owner|"
    r"positions?\s*\.\s*get|owner_id|pair_id|caller|account)"
)

_USER_CREDIT_RE = re.compile(
    r"(?i)(let\s+)?(user_)?(credit|claimable|owed|balance|compensation|"
    r"payout)[A-Za-z0-9_\.]*\s*(=|\+=|\.set\s*\(|\.insert\s*\(|"
    r"checked_add\s*\(|saturating_add\s*\()"
)
_POOL_CONTEXT_RE = re.compile(
    r"(?i)(pool|vault|reserve|escrow|liquidity|treasury|collateral|debt)"
)
_POOL_DEBIT_OR_BALANCE_RE = re.compile(
    r"(?i)((pool|vault|reserve|escrow|liquidity|treasury|collateral|debt)"
    r"[A-Za-z0-9_\.]*\s*(-=|=|\.set\s*\(|\.insert\s*\()[^;]{0,160}"
    r"(checked_sub\s*\(|saturating_sub\s*\(|-\s*[A-Za-z_])|"
    r"checked_sub\s*\(|saturating_sub\s*\(|debit_[A-Za-z0-9_]*\s*\(|"
    r"burn_[A-Za-z0-9_]*\s*\(|remove\s*\(|take\s*\(|transfer_from\s*\(|"
    r"settle_both|update_both|assert_balanced|pre_balance|post_balance)"
)


def _reset_before_value_move(body_text: str) -> bool:
    value_match = _VALUE_MOVE_RE.search(body_text)
    if value_match is None:
        return True
    reset_match = _ACCOUNTING_RESET_RE.search(body_text)
    return reset_match is not None and reset_match.start() < value_match.start()


def _stale_reserve_or_snapshot_math(name: str, body_text: str) -> bool:
    if not _VALUE_FN_RE.search(name):
        return False
    if not _STALE_CONTEXT_RE.search(body_text):
        return False
    if not _STALE_VALUE_RE.search(body_text):
        return False
    if _FRESHNESS_GUARD_RE.search(body_text):
        return False
    return _VALUE_MATH_RE.search(body_text) is not None


def _unkeyed_tick_range_burn(body_text: str) -> bool:
    if _POOL_BURN_RE.search(body_text) is None:
        return False
    return _OWNER_OR_PAIR_KEY_RE.search(body_text) is None


def _asymmetric_credit_without_pool_debit(name: str, body_text: str) -> bool:
    if not _VALUE_FN_RE.search(name):
        return False
    if _VALUE_MOVE_RE.search(body_text) is None:
        return False
    if _USER_CREDIT_RE.search(body_text) is None:
        return False
    if _POOL_CONTEXT_RE.search(body_text) is None:
        return False
    return _POOL_DEBIT_OR_BALANCE_RE.search(body_text) is None


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
        line, col = line_col(fn)

        value_match = _VALUE_MOVE_RE.search(body_nc)
        if (
            value_match is not None
            and _VALUE_FN_RE.search(name)
            and _ACCOUNTING_RESET_RE.search(body_nc) is not None
        ):
            if not _reset_before_value_move(body_nc):
                hits.append(
                    {
                        "severity": "high",
                        "line": line,
                        "col": col,
                        "snippet": snippet_of(fn, source, 200),
                        "message": (
                            f"pub fn `{name}` moves value before a claimed, "
                            f"consumed, or reserve debit marker is written. "
                            f"One-sided arithmetic state can be replayed "
                            f"(state-asymmetry-or-reserve-snapshot-value-loss-fire19)."
                        ),
                    }
                )

        if _stale_reserve_or_snapshot_math(name, body_nc):
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source, 200),
                    "message": (
                        f"pub fn `{name}` computes payout or compensation "
                        f"from reserve, tick, or snapshot math without a "
                        f"freshness guard. Stale value-bearing state can "
                        f"inflate withdrawal math "
                        f"(state-asymmetry-or-reserve-snapshot-value-loss-fire19)."
                    ),
                }
            )

        if _unkeyed_tick_range_burn(body_nc):
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source, 200),
                    "message": (
                        f"pub fn `{name}` burns tick-range liquidity without "
                        f"pair, owner, or position keying. Shared tick "
                        f"accounting can let one side extract another "
                        f"position's value "
                        f"(state-asymmetry-or-reserve-snapshot-value-loss-fire19)."
                    ),
                }
            )

        if _asymmetric_credit_without_pool_debit(name, body_nc):
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source, 200),
                    "message": (
                        f"pub fn `{name}` credits user-facing value and "
                        f"transfers funds without matching pool, vault, or "
                        f"reserve debit evidence. Asymmetric debit and "
                        f"credit math can leak value "
                        f"(state-asymmetry-or-reserve-snapshot-value-loss-fire19)."
                    ),
                }
            )

    return hits
