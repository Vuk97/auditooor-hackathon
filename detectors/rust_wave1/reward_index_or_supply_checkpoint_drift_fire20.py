"""
reward_index_or_supply_checkpoint_drift_fire20.py

Fire20 same-class Rust lift for rewards-distribution-skew misses where
reward payout math observes a stale index, stale supply denominator, or
mutated withdrawal membership before user rewards are checkpointed.

Seed misses:
- r94-loop-reward-cached-vs-current-index-drift-positive
- r94-loop-reward-cliff-boundary-wrong-supply-positive
- r94-loop-restaking-withdraw-dos-erc20-buffer-overflow-positive

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
    source_nocomment,
)


_REWARD_SOURCE_RE = re.compile(
    r"(?i)(reward|emission|incentive|index|per_?(?:token|share)|"
    r"checkpoint|settle|cliff|supply|shares|stake|withdraw|buffer|"
    r"restak|delegat|member)"
)

_INDEX_FN_RE = re.compile(
    r"(?i)(claim|earned|reward|get_?reward|pending|accrue|settle)"
)

_CACHED_INDEX_RE = re.compile(
    r"(?i)(reward_per_token_stored|rewardPerTokenStored|cached_?index|"
    r"reward_per_token_paid|rewardPerTokenPaid|last_?reward_?index|"
    r"user_?reward_?index|global_?reward_?index|reward_?debt)"
)

_REWARD_SETTLE_RE = re.compile(
    r"(?is)(?:\b|\.)("
    r"update_?(?:reward|rewards|reward_index|global_index|user_index)|"
    r"_update_?(?:reward|rewards)|"
    r"settle_?(?:reward|rewards|user_rewards|account|position|stake)|"
    r"checkpoint_?(?:reward|rewards|user_rewards|account_rewards|user|"
    r"account|position|stake|shares)|"
    r"accrue_?(?:reward|rewards)|"
    r"sync_?(?:reward|rewards|reward_index|accumulator)|"
    r"reward_per_token"
    r")\s*\("
)

_CLIFF_FN_RE = re.compile(r"(?i)(mint|reward|claim|distribute|emit)")
_CLIFF_RE = re.compile(r"(?i)(cliff|total_?cliffs|reduction)")
_SUPPLY_READ_RE = re.compile(
    r"(?is)(?:total_?supply|totalSupply)\s*\(\s*\)|"
    r"(?:self|pool|state|strategy)\s*\.\s*total_?(?:supply|shares)"
)
_MINT_OR_SUPPLY_MUTATION_RE = re.compile(
    r"(?is)(?:do_)?mint\s*\(|mint_?reward\s*\(|"
    r"total_?(?:supply|shares)\s*(?:\+=|=)"
)
_SUPPLY_CHECKPOINT_RE = re.compile(
    r"(?i)(pre_?mint_?supply|supply_?before|before_?supply|"
    r"cached_?supply|snapshot_?supply|supply_?snapshot|"
    r"pre_?mutation_?supply|pre_?withdraw_?supply)"
)

_WITHDRAW_FN_RE = re.compile(
    r"(?i)(withdraw|unstake|unbond|exit|redeem|leave|complete_queued)"
)
_WITHDRAW_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(reward|reward_?index|reward_?debt|claimable|earned|"
    r"total_?(?:supply|shares|stake|weight)|member|members|delegation|"
    r"withdrawal_?queue|stake|shares)"
)
_WITHDRAW_DENOM_MUTATION_RE = re.compile(
    r"(?is)("
    r"(?:self|state|pool|account|position|strategy)\s*\.\s*"
    r"(?:total_?(?:supply|shares|stake|weight)|shares|stake|balance|"
    r"members|delegations|withdrawal_?queue)\s*(?:\-=|\+=|=)|"
    r"(?:members|delegations|withdrawal_?queue|positions|shares)\s*\."
    r"(?:remove|insert|push|set)\s*\("
    r")"
)

_BUFFER_FN_RE = re.compile(
    r"(?i)(complete_queued_withdrawal|complete_withdrawal|"
    r"finalize_withdrawal|claim_withdrawal|fill_.*buffer)"
)
_BUFFER_RE = re.compile(
    r"(?i)(erc20_buffer|withdraw_?buffer|withdrawal_?buffer|"
    r"buffer_?(?:cap|max|limit)|deposit_queue_buffer)"
)
_BUFFER_FALLTHROUGH_RE = re.compile(
    r"(?is)(buffer_?space|remaining_?cap|leftover|saturating_sub|"
    r"\.min\s*\(|skip_if_full|buffer_full|transfer_leftover|"
    r"if\s+[^{}]{0,120}buffer[^{}]{0,120}(?:>=|>|==)[^{}]{0,80}cap"
    r"[^{}]{0,240}(?:return|continue))"
)


def _first(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    return pattern.search(text)


def _call_before(pattern: re.Pattern[str], text: str, pos: int) -> bool:
    match = pattern.search(text)
    return bool(match and match.start() < pos)


def _cached_index_hit(name: str, body: str) -> bool:
    if not _INDEX_FN_RE.search(name):
        return False
    cached = _first(_CACHED_INDEX_RE, body)
    if cached is None:
        return False
    return not _call_before(_REWARD_SETTLE_RE, body, cached.start())


def _cliff_supply_hit(name: str, body: str) -> bool:
    if not _CLIFF_FN_RE.search(name):
        return False
    supply = _first(_SUPPLY_READ_RE, body)
    if supply is None:
        return False
    if not _CLIFF_RE.search(body):
        return False
    if not _MINT_OR_SUPPLY_MUTATION_RE.search(body):
        return False
    return _SUPPLY_CHECKPOINT_RE.search(body) is None


def _withdraw_denominator_hit(name: str, body: str) -> bool:
    if not _WITHDRAW_FN_RE.search(name):
        return False
    if not _WITHDRAW_REWARD_CONTEXT_RE.search(body):
        return False
    mutation = _first(_WITHDRAW_DENOM_MUTATION_RE, body)
    if mutation is None:
        return False
    return not _call_before(_REWARD_SETTLE_RE, body, mutation.start())


def _buffer_cap_hit(name: str, body: str) -> bool:
    if not _BUFFER_FN_RE.search(name):
        return False
    if not _BUFFER_RE.search(body):
        return False
    return _BUFFER_FALLTHROUGH_RE.search(body) is None


def _shape_for(name: str, body: str) -> str | None:
    if _cached_index_hit(name, body):
        return "cached-index-before-settle"
    if _cliff_supply_hit(name, body):
        return "cliff-supply-without-checkpoint"
    if _withdraw_denominator_hit(name, body):
        return "withdraw-denominator-before-settle"
    if _buffer_cap_hit(name, body):
        return "withdraw-buffer-no-fallthrough"
    return None


def _message(name: str, shape: str) -> str:
    if shape == "cached-index-before-settle":
        detail = (
            "reads cached reward index state before updating or settling "
            "the current reward index"
        )
    elif shape == "cliff-supply-without-checkpoint":
        detail = (
            "computes cliff or reward reduction from total supply without "
            "a pre-mutation supply checkpoint"
        )
    elif shape == "withdraw-denominator-before-settle":
        detail = (
            "mutates withdrawal membership or payout denominator before "
            "settling user rewards"
        )
    else:
        detail = (
            "fills a withdrawal buffer without a cap-saturation fallthrough "
            "path before exit settlement"
        )
    return (
        f"pub fn `{name}` {detail}; reward payout accounting can observe "
        f"the wrong index or denominator (rewards-distribution-skew, "
        f"Fire20 reward index and supply checkpoint lift)."
    )


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    source_text = source_nocomment(source)
    if not _REWARD_SOURCE_RE.search(source_text):
        return hits

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
        if not _REWARD_SOURCE_RE.search(name + "\n" + body_nc):
            continue

        shape = _shape_for(name, body_nc)
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
