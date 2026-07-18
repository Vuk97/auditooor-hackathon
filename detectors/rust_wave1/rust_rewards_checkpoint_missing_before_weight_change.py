"""
rust_rewards_checkpoint_missing_before_weight_change.py

Flags Rust reward-accounting entrypoints that change distribution weight
before checkpointing or syncing the reward accumulator. The detector is
limited to concrete stake, share, delegation, bucket, or weight mutations.
Generic reward naming alone is not enough.

Also catches two same-class recall gaps:
- boost, lock, or multiplier mutation before reward settlement
- recursive rewardable collateral balance without source-principal tracking

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
    source_nocomment,
    snippet_of,
)


_FN_NAME_RE = re.compile(
    r"(?i)(transfer|stake|unstake|withdraw|deposit|delegate|redelegate|"
    r"change_delegate|set_delegate|bond|unbond|lock|unlock|set_weight|"
    r"update_weight|change_weight|set_boost|update_boost|change_boost|"
    r"set_multiplier|update_multiplier|join_bucket|leave_bucket|"
    r"move_bucket|set_bucket|mutate_bucket|set_shares|update_shares|"
    r"rebalance)"
)

_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(reward|emission|incentive|accumulator|accumulated|acc_reward|"
    r"reward_per_(?:token|share|weight)|reward_index|reward_debt|"
    r"last_reward|paid_index|checkpoint|boost|boost_factor|multiplier|"
    r"lock_status|lock_duration)"
)

_CHECKPOINT_CALL_RE = re.compile(
    r"(?is)(?:\b|\.)"
    r"(?:checkpoint|sync|settle|update|accrue)_"
    r"(?:reward|rewards|reward_index|reward_accumulator|accumulator|"
    r"global_index|user_index|account|position|stake|bucket|delegation|"
    r"shares)\s*\(|"
    r"(?:\b|\.)"
    r"(?:checkpoint_rewards|sync_rewards|settle_rewards|update_rewards|"
    r"accrue_rewards|checkpoint_user|checkpoint_account|"
    r"checkpoint_position|sync_accumulator|update_accumulator|"
    r"update_reward_index|update_global_index|settle_account)\s*\("
)

_WEIGHT_FIELD = (
    r"(?:stake|stakes|stake_of|staked|balance|balances|balance_of|"
    r"share|shares|share_of|weight|weights|reward_weight|"
    r"reward_weights|voting_power|delegate_power|delegated_power|"
    r"delegation|delegations|delegated_to|bucket|buckets|bucket_weight|"
    r"bucket_weights|bucket_shares|total_stake|total_weight|"
    r"total_shares|total_supply|locked_shares|locked_weight|"
    r"boost|boosts|boost_factor|boost_factors|multiplier|multipliers|"
    r"lock_status|lock_duration)"
)

_MUTATION_RES = [
    re.compile(
        rf"(?is)\b(?:self|state|pool|account|position|bucket|delegation|"
        rf"user|validator)\s*\.\s*{_WEIGHT_FIELD}\b\s*(?:[+\-*/]?=)"
    ),
    re.compile(
        rf"(?is)\b(?:self\.)?{_WEIGHT_FIELD}\s*\[[^\]]+\]\s*"
        rf"(?:[+\-*/]?=)"
    ),
    re.compile(
        rf"(?is)\b(?:self\.)?{_WEIGHT_FIELD}\s*\.\s*"
        rf"(?:insert|set|remove|push)\s*\("
    ),
    re.compile(
        r"(?is)\b(?:lock_status|lock_duration|boost|boost_factor|"
        r"multiplier)\s*(?:[+\-*/]?=)"
    ),
]

_RECURSIVE_DEPOSIT_RE = re.compile(
    r"(?is)\bfn\s+deposit_collateral\s*\([^)]*\btoken\s*:\s*TokenId"
    r"[^)]*\bamount\s*:\s*u64[^)]*\)\s*(?:->\s*[^{]+)?\{"
    r"[\s\S]{0,1600}?position\s*\.\s*balance\s*\+=\s*amount"
    r"[\s\S]{0,600}?pool\s*\.\s*total_supply\s*\+=\s*amount"
)

_RECURSIVE_REWARD_RE = re.compile(
    r"(?is)\bfn\s+claim_rewards\s*\([^)]*\)[\s\S]{0,1600}?"
    r"position\s*\.\s*balance\s*\*\s*pool\s*\.\s*reward_per_token_stored"
)

_RECURSION_GUARD_RE = re.compile(
    r"(?i)source_position|underlying_source|yield_bearing_tokens|"
    r"is_yield_bearing|tracked_deposit|deposit_principal|"
    r"recursive_deposit_blocked"
)


def _first_match(patterns: list[re.Pattern[str]], text: str) -> re.Match[str] | None:
    best = None
    for pattern in patterns:
        match = pattern.search(text)
        if match is None:
            continue
        if best is None or match.start() < best.start():
            best = match
    return best


def _recursive_rewardable_collateral_hit(
    filepath: str,
    text: str,
) -> dict | None:
    deposit = _RECURSIVE_DEPOSIT_RE.search(text)
    if deposit is None:
        return None
    if _RECURSIVE_REWARD_RE.search(text) is None:
        return None
    if _RECURSION_GUARD_RE.search(text):
        return None

    line = text[: deposit.start()].count("\n") + 1
    snippet = text[deposit.start() : deposit.start() + 200]
    snippet = " ".join(snippet.split())
    return {
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": snippet,
        "message": (
            f"{filepath}: rewardable collateral deposits update balance and "
            f"total_supply while claim_rewards pays from raw balance, but "
            f"the module lacks source-principal or yield-bearing-token "
            f"tracking. Recursive deposits can skew rewards "
            f"(rewards-distribution-skew)."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    source_text = source_nocomment(source)
    if not _REWARD_CONTEXT_RE.search(source_text):
        return hits

    recursive_hit = _recursive_rewardable_collateral_hit(filepath, source_text)
    if recursive_hit is not None:
        hits.append(recursive_hit)

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        mutation = _first_match(_MUTATION_RES, body_nc)
        if mutation is None:
            continue

        checkpoint = _CHECKPOINT_CALL_RE.search(body_nc)
        if checkpoint is not None and checkpoint.start() < mutation.start():
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` changes reward distribution weight before "
                f"checkpointing or syncing the reward accumulator. Stake, "
                f"share, delegation, or bucket mutation can skew rewards "
                f"(rewards-distribution-skew)."
            ),
        })
    return hits
