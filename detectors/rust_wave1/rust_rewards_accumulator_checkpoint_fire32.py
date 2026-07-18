"""
rust_rewards_accumulator_checkpoint_fire32.py

Fire32 Rust lift for rewards-distribution-skew ordering misses.

Flags public reward, stake, deposit, withdraw, transfer, claim, allocation,
or emission-update paths that mutate stake, shares, total supply, or reward
debt before the function checkpoints pending rewards, updates the reward
accumulator, or settles the user's reward index.

Source refs:
- reports/detector_lift_fire31_20260605/post_priorities_rust.md
- detectors/wave17/rewards_supply_checkpoint_fire31.py
- reference/patterns.dsl/rewardloss-in-staking-contracts.yaml
- reference/patterns.dsl.zellic_k2_mined/wrong-supply-query-type-skips-reward-settlement.yaml

Candidate evidence only. A detector hit is NOT_SUBMIT_READY and must not be
cited as proof without source existence, a real in-scope entrypoint, a clean
negative control, and R40/R76/R80 evidence honesty.

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


_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(reward|rewards|emission|incentive|claimable|pending|earned|"
    r"accrued|accumulator|reward_?index|reward_?debt|"
    r"reward_?per_?(?:share|token|stake|weight)|acc_?reward|"
    r"checkpoint|settle|stake|staked|shares?|total_?(?:supply|stake|shares))"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)(stake|unstake|deposit|withdraw|mint|burn|transfer|claim|"
    r"harvest|collect|settle|checkpoint|allocate|distribute|notify|"
    r"set_?emission|claim_all_rewards|update_?(?:stake|shares|balance|position))"
)

_SETTLEMENT_CALL_RE = re.compile(
    r"(?is)(?:\b|\.)("
    r"update_?(?:reward|rewards|reward_index|global_index|user_index|"
    r"global_accumulator|accumulator|pool)|"
    r"sync_?(?:reward|rewards|reward_index|accumulator|pool)|"
    r"settle_?(?:reward|rewards|user_rewards|account|position|stake|"
    r"user_index|index|pending)|"
    r"checkpoint_?(?:reward|rewards|user_rewards|account_rewards|"
    r"user|account|position|stake|shares|pending|index)|"
    r"accrue_?(?:reward|rewards|account|position)|"
    r"harvest_?(?:reward|rewards)|"
    r"claim_all_rewards"
    r")\s*\("
)

_PENDING_CREDIT_RE = re.compile(
    r"(?is)\b(?:pending_?rewards?|claimable_?rewards?|accrued_?rewards?|"
    r"earned_?rewards?|cached_?rewards?|user_?rewards?)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:=|\+=)"
)

_PENDING_REWARD_USE_RE = re.compile(
    r"(?is)\b(?:pending_?reward|pending_?rewards|claimable_?reward|"
    r"claimable_?rewards|earned|earned_?reward|accrued_?reward|"
    r"calculate_?reward|get_?reward|reward_due|owed|payout)\s*\("
    r"|\blet\s+(?:pending|claimable|earned|accrued|owed|payout|reward_due)\b"
    r"|\b(?:pending|claimable|earned|accrued|owed|payout|reward_due)\s*="
)

_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'",
    re.DOTALL,
)

_TOTAL_FIELD = (
    r"total_?(?:supply|shares|stake|staked|weight)|"
    r"share_?supply|staking_?supply|reward_?supply"
)
_STAKE_SHARE_FIELD = (
    r"shares?|share_?amount|stake|stakes|staked|stake_?amount|"
    r"amount_?staked|staked_?amount"
)
_REWARD_DEBT_FIELD = (
    r"reward_?debt|reward_?debts|user_?reward_?debt|"
    r"user_?reward_?debts|reward_?index_?paid|"
    r"user_?reward_?index|last_?reward_?index|paid_?index"
)
_SENSITIVE_FIELD = rf"(?:{_TOTAL_FIELD}|{_STAKE_SHARE_FIELD}|{_REWARD_DEBT_FIELD})"
_RECEIVER = (
    r"(?:self|state|pool|vault|staking|strategy|account|user|position|"
    r"stake|staker|share|holder|info)"
    r"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*|\s*\[[^\]]+\]){0,6}"
)

_DOTTED_WRITE_RE = re.compile(
    rf"(?is)\b{_RECEIVER}\s*\.\s*(?P<slot>{_SENSITIVE_FIELD})"
    r"\s*(?:\+=|-=|\*=|/=|=)"
)

_INDEXED_WRITE_RE = re.compile(
    rf"(?is)\b(?P<slot>(?:stakes?|shares?|staked|positions?|"
    rf"reward_?debts?|user_?reward_?debts?|{_TOTAL_FIELD}))"
    r"\s*(?:\[[^\]]+\]\s*){1,3}(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:\+=|-=|\*=|/=|=)"
)

_MAP_MUTATION_RE = re.compile(
    rf"(?is)\b(?P<slot>(?:self\.)?(?:stakes?|shares?|staked|positions?|"
    rf"reward_?debts?|user_?reward_?debts?))"
    r"\s*\.\s*(?:insert|set|remove)\s*\("
)

_BARE_TOTAL_WRITE_RE = re.compile(
    rf"(?is)\b(?P<slot>{_TOTAL_FIELD})\s*(?:\+=|-=|\*=|/=|=)"
)

_BARE_REWARD_DEBT_WRITE_RE = re.compile(
    rf"(?is)\b(?P<slot>{_REWARD_DEBT_FIELD})\s*(?:\+=|-=|\*=|/=|=)"
)


def _strip_strings(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = match.group(0)
        return "\n" * value.count("\n") if "\n" in value else " "

    return _STRING_RE.sub(repl, text)


def _first_sensitive_write(body: str) -> tuple[str, re.Match[str]] | None:
    candidates: list[tuple[str, re.Match[str]]] = []
    for label, pattern in (
        ("stake, share, supply, or reward debt field", _DOTTED_WRITE_RE),
        ("indexed stake, share, supply, or reward debt slot", _INDEXED_WRITE_RE),
        ("stake, share, position, or reward debt map", _MAP_MUTATION_RE),
        ("total supply, total stake, or total shares slot", _BARE_TOTAL_WRITE_RE),
        ("reward debt slot", _BARE_REWARD_DEBT_WRITE_RE),
    ):
        for match in pattern.finditer(body):
            candidates.append((label, match))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[1].start())


def _slot_from_match(match: re.Match[str]) -> str:
    return match.groupdict().get("slot") or "reward accounting state"


def _has_settlement_before(body: str, pos: int) -> bool:
    prefix = body[:pos]
    return bool(
        _SETTLEMENT_CALL_RE.search(prefix)
        or _PENDING_CREDIT_RE.search(prefix)
        or _PENDING_REWARD_USE_RE.search(prefix)
    )


def _has_late_reward_settlement(body: str, pos: int) -> bool:
    tail = body[pos:]
    return bool(
        _SETTLEMENT_CALL_RE.search(tail)
        or _PENDING_CREDIT_RE.search(tail)
        or _PENDING_REWARD_USE_RE.search(tail)
    )


def _unsafe_write(name: str, body: str) -> tuple[str, re.Match[str]] | None:
    if not _REWARD_CONTEXT_RE.search(f"{name}\n{body}"):
        return None
    if not (_ENTRY_FN_RE.search(name) or _SETTLEMENT_CALL_RE.search(body)):
        return None

    candidate = _first_sensitive_write(body)
    if candidate is None:
        return None

    label, match = candidate
    if _has_settlement_before(body, match.start()):
        return None
    if not _has_late_reward_settlement(body, match.end()):
        return None
    return label, match


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    module_text = source_nocomment(source)
    if not _REWARD_CONTEXT_RE.search(module_text):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = _strip_strings(body_text_nocomment(body, source))
        result = _unsafe_write(name, body_nc)
        if result is None:
            continue

        label, match = result
        slot = _slot_from_match(match)
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` mutates {label} `{slot}` before "
                    f"checkpointing pending rewards, updating the reward "
                    f"accumulator, or settling the user reward index "
                    f"(rewards-distribution-skew, Fire32 rewards accumulator "
                    f"checkpoint lift)."
                ),
            }
        )
    return hits
