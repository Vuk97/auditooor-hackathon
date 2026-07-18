"""
rewards_orphan_checkpoint_fire38.py

Fire38 Rust lift for rewards-distribution-skew orphan checkpoint paths.

Flags public transfer, vault allocation, delegation, and vote checkpoint
entrypoints where the first mutation to balances, shares, delegated weight,
allocation weight, reward denominator, or vote checkpoint state happens before
the function settles accrued rewards or synchronizes reward checkpoints.

Source refs:
- reports/detector_lift_fire37_20260605/post_priorities_rust.md
- detectors/rust_wave1/rewards_delegate_weight_checkpoint_fire37.py
- detectors/rust_wave1/rewards_distribution_skew_checkpoint_fire24.py
- detectors/rust_wave1/r94_loop_token_transfer_orphans_accrued_rewards.py
- detectors/rust_wave1/rust_rewards_transfer_orphans_accrual_fire29.py

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


DETECTOR_ID = "rust_wave1.rewards_orphan_checkpoint_fire38"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"


_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(reward|rewards|emission|incentive|claimable|pending|earned|"
    r"accrued|reward_?debt|reward_?index|user_?index|paid_?index|"
    r"last_?reward|reward_?per_?(?:share|token|stake|weight)|"
    r"acc_?reward|accumulator|checkpoint|settle|reward_?denom|"
    r"reward_?denominator|reward_?supply|delegate_?weight|vote_?weight|"
    r"voting_?power)"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)(?:"
    r"transfer|transfer_?from|before_?transfer|after_?transfer|"
    r"on_?transfer|move_?(?:stake|shares?|position|vault)|"
    r"allocate|deallocate|rebalance|deposit|withdraw|mint|burn|"
    r"delegate|redelegate|undelegate|set_?delegate|change_?delegate|"
    r"checkpoint_?(?:vote|votes|delegate|delegation|weight|power)|"
    r"write_?checkpoint|record_?checkpoint|push_?checkpoint|"
    r"cast_?vote|vote"
    r")"
)

_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'",
    re.DOTALL,
)

_SETTLEMENT_CALL_RE = re.compile(
    r"(?is)(?:\b|\.)"
    r"(?:"
    r"(?:update|sync|settle|checkpoint|accrue|harvest|claim)_?"
    r"(?:all_?|global_?|user_?|account_?|position_?|stake_?|share_?|"
    r"vault_?|delegation_?|delegate_?|vote_?|voter_?)?"
    r"(?:reward|rewards|reward_?index|reward_?checkpoint|"
    r"user_?index|accumulator|pending|accrual|checkpoint|"
    r"reward_?debt|rewards_?before_?mutation)|"
    r"(?:settle|checkpoint)_?"
    r"(?:accrued_?)?(?:reward|rewards|accounts?|positions?|"
    r"transfer_?rewards?|vote_?rewards?)|"
    r"sync_?reward_?checkpoint|sync_?checkpoint|"
    r"update_?reward_?checkpoint"
    r")\s*\("
)

_SNAPSHOT_WRITE_RE = re.compile(
    r"(?is)\b(?:self\.)?"
    r"(?:user_?)?"
    r"(?:reward_?debt|reward_?debts|reward_?index|"
    r"reward_?per_?(?:token|share|stake|weight)_?paid|"
    r"last_?reward(?:_?index)?|paid_?index|"
    r"accrued_?rewards?|pending_?rewards?|reward_?checkpoint)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}"
    r"(?:\.\s*(?:insert|set)\s*\([^;{}]*\)|\s*(?:\+=|-=|=))"
)

_BALANCE_SLOT = (
    r"balances?|balance_?of|shares?|share_?of|vault_?shares?|"
    r"stakes?|stake_?of|staked|user_?stake|user_?shares|"
    r"positions?|position_?shares|position_?owner|owners?|owner_?of|"
    r"holders?|holder_?of"
)

_ALLOCATION_SLOT = (
    r"vault_?allocations?|strategy_?allocations?|asset_?allocations?|"
    r"allocations?|vault_?weights?|strategy_?weights?|asset_?weights?|"
    r"total_?(?:allocated|allocation|assets|shares|stake|weight)|"
    r"reward_?(?:denom|denominator|denominators|supply|weight)|"
    r"total_?reward_?(?:denom|denominator|supply|weight)"
)

_VOTE_SLOT = (
    r"vote_?checkpoints?|voter_?checkpoints?|delegate_?checkpoints?|"
    r"delegation_?checkpoints?|voting_?power_?checkpoints?|"
    r"delegated_?(?:weight|weights|power|powers)|"
    r"delegate_?(?:weight|weights|power|powers)|"
    r"vote_?(?:weight|weights|power|powers)|"
    r"voting_?(?:weight|weights|power|powers)"
)

_BALANCE_MAP_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_BALANCE_SLOT})\s*\."
    r"(?:insert|set|remove|entry|get_mut)\s*\("
)

_BALANCE_INDEX_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_BALANCE_SLOT})"
    r"\s*(?:\[[^\]]+\]\s*){1,3}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|-=|\*=|/=|=)"
)

_ACCOUNT_FIELD_WRITE_RE = re.compile(
    rf"(?is)\b(?:from|sender|src|source|owner|holder|old_?owner|"
    rf"to|receiver|recipient|dst|destination|new_?owner|account|user|"
    rf"position|vault|allocation)(?:_[A-Za-z0-9]+)?"
    rf"\s*\.\s*(?P<slot>{_BALANCE_SLOT}|{_ALLOCATION_SLOT}|{_VOTE_SLOT})"
    r"\s*(?:\+=|-=|\*=|/=|=)"
)

_ALLOCATION_MAP_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_ALLOCATION_SLOT})\s*\."
    r"(?:insert|set|remove|entry|get_mut)\s*\("
)

_ALLOCATION_FIELD_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_ALLOCATION_SLOT})"
    r"(?:\s*(?:\[[^\]]+\]\s*){0,2})"
    r"\s*(?:\+=|-=|\*=|/=|=)"
)

_VOTE_MAP_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_VOTE_SLOT})\s*\."
    r"(?:push|insert|set|remove|entry|get_mut|or_default)\s*\("
)

_VOTE_INDEX_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_VOTE_SLOT})"
    r"\s*(?:\[[^\]]+\]\s*){0,3}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|-=|\*=|/=|=)"
)

_VOTE_CHECKPOINT_CALL_RE = re.compile(
    r"(?is)\b(?P<slot>"
    r"(?:write|record|push|store|save)_?"
    r"(?:vote|voter|delegate|delegation|voting_?power)_?"
    r"checkpoint"
    r")\s*\("
)

_MUTATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("balance or stake transfer write", _BALANCE_MAP_WRITE_RE),
    ("indexed balance or stake transfer write", _BALANCE_INDEX_WRITE_RE),
    ("account balance, allocation, or vote field write", _ACCOUNT_FIELD_WRITE_RE),
    ("vault allocation or reward denominator write", _ALLOCATION_MAP_WRITE_RE),
    ("reward denominator or allocation field write", _ALLOCATION_FIELD_WRITE_RE),
    ("vote checkpoint or delegated weight write", _VOTE_MAP_WRITE_RE),
    ("indexed vote checkpoint or delegated weight write", _VOTE_INDEX_WRITE_RE),
    ("vote checkpoint writer call", _VOTE_CHECKPOINT_CALL_RE),
)


def _strip_strings(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = match.group(0)
        return "\n" * value.count("\n") if "\n" in value else " "

    return _STRING_RE.sub(repl, text)


def _first_risky_mutation(body: str) -> tuple[str, re.Match[str]] | None:
    candidates: list[tuple[str, re.Match[str]]] = []
    for label, pattern in _MUTATION_PATTERNS:
        for match in pattern.finditer(body):
            candidates.append((label, match))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[1].start())


def _has_checkpoint_sync_before(body: str, mutation_start: int) -> bool:
    prefix = body[:mutation_start]
    return bool(_SETTLEMENT_CALL_RE.search(prefix) or _SNAPSHOT_WRITE_RE.search(prefix))


def _slot_from_match(match: re.Match[str]) -> str:
    return match.groupdict().get("slot") or "reward-sensitive state"


def _has_relevant_entry_shape(name: str, body: str) -> bool:
    if _ENTRY_FN_RE.search(name):
        return True
    return bool(
        _REWARD_CONTEXT_RE.search(body)
        and re.search(
            r"(?i)(from|sender|to|receiver|vault|allocat|delegate|vote|checkpoint)",
            body,
        )
    )


def _unsafe_orphan_checkpoint(name: str, body: str) -> tuple[str, re.Match[str]] | None:
    if not _REWARD_CONTEXT_RE.search(f"{name}\n{body}"):
        return None
    if not _has_relevant_entry_shape(name, body):
        return None

    candidate = _first_risky_mutation(body)
    if candidate is None:
        return None

    _label, match = candidate
    if _has_checkpoint_sync_before(body, match.start()):
        return None
    return candidate


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    module_text = _strip_strings(source_nocomment(source))
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
        result = _unsafe_orphan_checkpoint(name, body_nc)
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
                    f"pub fn `{name}` performs a {label} on `{slot}` "
                    f"before settling accrued rewards or synchronizing "
                    f"reward checkpoints. Balance, vault allocation, "
                    f"delegated weight, reward denominator, or vote "
                    f"checkpoint mutations can orphan reward accrual "
                    f"(rewards-distribution-skew, Fire38 orphan "
                    f"checkpoint lift)."
                ),
            }
        )
    return hits
