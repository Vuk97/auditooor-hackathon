"""
rust_rewards_transfer_orphans_accrual_fire29.py

Rust Fire29 lift for rewards-distribution-skew.

Flags token, share, stake, or owner transfer paths that mutate ownership
or balance state before settling the sender and receiver reward snapshots.
If reward settlement happens after the transfer mutation, accrued rewards
can be orphaned for the sender or credited to the wrong account.

Source refs:
  - reference/patterns.dsl/r94-loop-token-transfer-orphans-accrued-rewards.yaml
  - reference/patterns.dsl.r94_solodit_tokenomics/pool-token-transfer-orphans-future-rewards-for-sender.yaml
  - reference/patterns.dsl/staking-reward-missing-checkpoint-on-transfer.yaml
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
    source_nocomment,
)


_TRANSFER_FN_RE = re.compile(
    r"(?i)(?:^|_)(?:transfer|transfer_from|transferfrom|move|handoff|"
    r"assign|update|before_transfer|after_transfer|on_transfer|"
    r"handle_transfer|set_owner|change_owner|move_owner)(?:_|$)"
)

_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(reward|rewards|reward_per_(?:token|share|stake|weight)|"
    r"reward_index|reward_debt|last_reward|paid_index|acc_reward|"
    r"pending_reward|accrued|emission|incentive)"
)

_TRANSFER_CONTEXT_RE = re.compile(
    r"(?i)(from|sender|src|source|owner|holder|to|receiver|recipient|dst|"
    r"destination|balance|balances|share|shares|stake|stakes|staked|"
    r"owner_of|owners|holder_of|position|positions)"
)

_STATE_FIELD = (
    r"(?:balances?|balance_of|shares?|share_of|stakes?|stake_of|staked|"
    r"owners?|owner_of|holder_of|holders?|positions?|position_owner|"
    r"token_owner|pool_tokens?|pool_shares?|user_stake|user_shares)"
)

_OWNERSHIP_MUTATION_RES = [
    re.compile(
        rf"(?is)\b(?:self\.)?{_STATE_FIELD}\s*\.\s*"
        r"(?:insert|set|remove)\s*\("
    ),
    re.compile(
        rf"(?is)\b(?:self\.)?{_STATE_FIELD}\s*\[[^\]]+\]\s*"
        r"(?:[+\-*/]?=)"
    ),
    re.compile(
        rf"(?is)\b(?:from_account|sender_account|to_account|"
        rf"receiver_account|recipient_account|account|position|token|"
        rf"stake_record|share_record)\s*\.\s*{_STATE_FIELD}\b\s*"
        r"(?:[+\-*/]?=)"
    ),
]

_SETTLE_CALL_RE = re.compile(
    r"(?is)(?:\b|\.)"
    r"(?:settle|settle_user|settle_account|settle_position|"
    r"settle_reward|settle_rewards|update_reward|update_rewards|"
    r"update_user_rewards|checkpoint_reward|checkpoint_rewards|"
    r"checkpoint_user|checkpoint_account|checkpoint_position|"
    r"accrue_reward|accrue_rewards|sync_reward|sync_rewards|"
    r"sync_reward_index|sync_accumulator|update_reward_index|"
    r"update_user_index|harvest_reward|harvest_rewards)\s*\("
)

_REWARD_SNAPSHOT_WRITE_RE = re.compile(
    r"(?is)\b(?:self\.)?(?:user_)?(?:reward_debt|reward_index|"
    r"reward_per_token_paid|reward_per_share_paid|last_reward|"
    r"last_reward_per_token|paid_index|accrued_rewards)\s*"
    r"(?:\.insert\s*\(|\.set\s*\(|\[[^\]]+\]\s*(?:[+\-*/]?=)|"
    r"(?:[+\-*/]?=))"
)


def _first_match(patterns: list[re.Pattern[str]], text: str) -> re.Match[str] | None:
    best: re.Match[str] | None = None
    for pattern in patterns:
        match = pattern.search(text)
        if match is None:
            continue
        if best is None or match.start() < best.start():
            best = match
    return best


def _has_settlement_before(body: str, mutation_start: int) -> bool:
    prefix = body[:mutation_start]
    return bool(_SETTLE_CALL_RE.search(prefix) or _REWARD_SNAPSHOT_WRITE_RE.search(prefix))


def _has_transfer_shape(name: str, body: str) -> bool:
    if _TRANSFER_FN_RE.search(name):
        return True
    if re.search(r"(?i)\b(from|sender|owner)\b", body) and re.search(
        r"(?i)\b(to|receiver|recipient)\b", body
    ):
        return bool(_TRANSFER_CONTEXT_RE.search(body))
    return False


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    module_text = source_nocomment(source)
    if not _REWARD_CONTEXT_RE.search(module_text):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        if not _has_transfer_shape(name, body_nc):
            continue
        if not _REWARD_CONTEXT_RE.search(body_nc):
            continue

        mutation = _first_match(_OWNERSHIP_MUTATION_RES, body_nc)
        if mutation is None:
            continue

        if _has_settlement_before(body_nc, mutation.start()):
            continue

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"fn `{name}` mutates token, share, stake, or owner "
                    f"state before settling reward snapshots. Transfer-time "
                    f"ownership changes can orphan accrued rewards or credit "
                    f"future rewards to the wrong account "
                    f"(rewards-distribution-skew)."
                ),
            }
        )
    return hits
