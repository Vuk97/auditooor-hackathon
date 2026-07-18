"""
rewards_checkpoint_or_denominator_fire16.py

Fire16 same-class lift for Rust rewards-distribution-skew misses.

Flags reward, gauge, prize, and stake paths where the reward share is
derived from an ambiguous checkpoint, a raw total-supply denominator, or
an instantaneous balance. The detector is intentionally bounded to those
three concrete shapes so generic reward bookkeeping does not fire.

Seed misses:
- r94-loop-checkpoint-same-block-ambiguity-positive
- r94-loop-draw-reward-wrong-denominator-positive
- r94-loop-gauge-reward-stake-withdraw-burst-game-positive

Class: rewards-distribution-skew.
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


_CHECKPOINT_CALL_RE = re.compile(
    r"(?i)\b("
    r"get_at_block|getAtBlock|getPastVotesAt|get_past_votes_at|"
    r"checkpoint_at_block|weight_at_block|balance_at_block"
    r")\s*\("
)

_CHECKPOINT_CONTEXT_RE = re.compile(
    r"(?i)(reward|rewards|emission|incentive|prize|draw|gauge|"
    r"stake|staking|weight|checkpoint|balance|votes?)"
)

_CHECKPOINT_DISAMBIG_RE = re.compile(
    r"(?i)(timestamp|timepoint|seq_no|seqno|sequence|ordinal|"
    r"within_block|same_block_index|checkpoint_index|block_index|"
    r"disambiguat)"
)

_DENOM_FN_RE = re.compile(
    r"(?i)(claim_(?:prize|draw|reward)|claim(?:Prize|Draw|Reward)|"
    r"distribute_(?:prize|draw|reward)|distribute(?:Prize|Draw|Reward)|"
    r"award_(?:prize|reward)|award(?:Prize|Reward)|"
    r"payout_(?:draw|prize|reward)|payout(?:Draw|Prize|Reward)|"
    r"calculate_(?:prize|reward)|calculate(?:Prize|Reward)|"
    r"pending_reward|pendingReward|earned)"
)

_RAW_TOTAL_DENOM_RE = re.compile(
    r"(?is)("
    r"/\s*(?:[\w\.]*total_(?:supply|stake|staked|shares|weight|"
    r"power|balance)\s*\(\s*\)|[\w\.]*total(?:Supply|Stake|"
    r"Shares|Weight|Power|Balance)\s*\(\s*\))"
    r"|"
    r"(?:reward|rewards|prize|draw|emission|fee)[A-Za-z0-9_]*"
    r"\s*\*\s*[A-Za-z0-9_\.]+\s*/\s*"
    r"(?:[\w\.]*total_(?:supply|stake|staked|shares|weight|power|"
    r"balance)\b|[\w\.]*total(?:Supply|Stake|Shares|Weight|"
    r"Power|Balance)\b)"
    r")"
)

_ELIGIBLE_DENOM_RE = re.compile(
    r"(?i)(eligible|qualified|active|participating|draw_supply|"
    r"reward_supply|eligible_supply|eligible_weight|qualified_supply|"
    r"qualified_weight|active_supply|active_weight|time_weighted|"
    r"snapshot|weighted_total|total_weighted)"
)

_GAUGE_FN_RE = re.compile(
    r"(?i)(stake|withdraw|deposit|exit|update_reward|update_rewards|"
    r"claim_reward|claim_rewards|settle_reward|settle_rewards)"
)

_INSTANT_BALANCE_RE = re.compile(
    r"(?is)("
    r"(?:accrue|settle|update|claim)[A-Za-z0-9_]*\s*\(\s*"
    r"(?:[\w\.]*balance_of\s*\(|current_balance|user_balance|"
    r"balance\s*\))"
    r"|"
    r"(?:reward_per_token|reward_per_share|rewards_per_weight)"
    r"\s*\(\s*(?:[\w\.]*balance_of\s*\(|current_balance|"
    r"user_balance)"
    r"|"
    r"user_reward\s*\+=\s*[A-Za-z0-9_\.]*current_balance"
    r")"
)

_TIME_WEIGHTED_RE = re.compile(
    r"(?i)(time_weighted|time_weighted_balance|effective_balance|"
    r"average_balance|average_balance_over|stake_duration|"
    r"duration_weighted|ve_balance|veBalance|lock_multiplier|"
    r"snapshot_balance|checkpointed_balance)"
)


def _checkpoint_hit(name: str, body: str) -> bool:
    if not _CHECKPOINT_CALL_RE.search(body):
        return False
    if not _CHECKPOINT_CONTEXT_RE.search(name) and not _CHECKPOINT_CONTEXT_RE.search(body):
        return False
    return _CHECKPOINT_DISAMBIG_RE.search(body) is None


def _wrong_denominator_hit(name: str, body: str) -> bool:
    if not _DENOM_FN_RE.search(name):
        return False
    if not _RAW_TOTAL_DENOM_RE.search(body):
        return False
    return _ELIGIBLE_DENOM_RE.search(body) is None


def _instant_balance_hit(name: str, body: str) -> bool:
    if not _GAUGE_FN_RE.search(name):
        return False
    if not _INSTANT_BALANCE_RE.search(body):
        return False
    return _TIME_WEIGHTED_RE.search(body) is None


def _message(name: str, shape: str) -> str:
    if shape == "ambiguous-checkpoint":
        detail = (
            "reads a checkpoint by block without a timestamp, sequence, "
            "or same-block ordering discriminator"
        )
    elif shape == "wrong-denominator":
        detail = (
            "divides rewards by raw total supply or total weight instead "
            "of an eligible reward denominator"
        )
    else:
        detail = (
            "settles gauge rewards from an instantaneous balance without "
            "a time-weighted or checkpointed balance"
        )
    return (
        f"pub fn `{name}` {detail}; reward allocation can be skewed "
        f"(rewards-distribution-skew, Fire16 checkpoint-or-denominator lift)."
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        name = fn_name(fn, source)
        body_nc = body_text_nocomment(body, source)
        shape = None
        if _checkpoint_hit(name, body_nc):
            shape = "ambiguous-checkpoint"
        elif _wrong_denominator_hit(name, body_nc):
            shape = "wrong-denominator"
        elif _instant_balance_hit(name, body_nc):
            shape = "instant-balance"

        if shape is None:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": _message(name, shape),
        })
    return hits
