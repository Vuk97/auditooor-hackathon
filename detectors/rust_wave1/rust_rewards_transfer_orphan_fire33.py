"""
rust_rewards_transfer_orphan_fire33.py

Fire33 Rust lift for rewards-distribution-skew transfer orphan misses.

Flags token, stake, vault-share, boost, or delegation transfer paths that
move balance or ownership state before checkpointing reward accounting for
both the source and destination side. If old reward debt, user index, or
accrued rewards are settled after the movement, rewards earned by the old
holder can follow the transferred position to the wrong account.

Source refs:
- reports/detector_lift_fire32_20260605/post_priorities_rust.md
- reference/patterns.dsl/staking-reward-missing-checkpoint-on-transfer.yaml
- reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml
- reference/patterns.dsl/reward-distribution-missing-update.yaml

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
    line_col,
    snippet_of,
    source_nocomment,
)


_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(reward|rewards|emission|incentive|claimable|pending|earned|"
    r"accrued|reward_?debt|reward_?debts|reward_?index|user_?index|"
    r"paid_?index|last_?reward|reward_?per_?(?:share|token|stake|weight)|"
    r"acc_?reward|accumulator|checkpoint|settle|user_?reward|"
    r"boost_?reward|delegat(?:e|ion).*reward)"
)

_TRANSFER_FN_RE = re.compile(
    r"(?i)(?:^|_)(?:transfer|transfer_?from|move|move_?stake|move_?shares|"
    r"move_?position|handoff|assign|reassign|set_?owner|change_?owner|"
    r"delegate|redelegate|move_?delegation|transfer_?boost|move_?boost|"
    r"shift_?boost|transfer_?vault|rotate_?stake)(?:_|$)"
)

_SOURCE_ACTOR_RE = re.compile(
    r"(?i)\b(from|sender|src|source|owner|holder|old_?owner|old_?holder|"
    r"delegator|old_?delegate|old_?delegatee|from_?vault|from_?account|"
    r"source_?account|from_?position|old_?position)\b"
)

_DEST_ACTOR_RE = re.compile(
    r"(?i)\b(to|receiver|recipient|dst|destination|new_?owner|new_?holder|"
    r"delegatee|new_?delegate|to_?vault|to_?account|dest_?account|"
    r"recipient_?account|to_?position|new_?position)\b"
)

_TRANSFER_CONTEXT_RE = re.compile(
    r"(?i)(balance|balances|balance_of|shares?|share_of|stake|stakes|"
    r"staked|vault_?shares?|position|positions|owner|owners|owner_of|"
    r"holder|holders|delegat(?:e|ion|ions)|boost|weight|multiplier)"
)

_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'",
    re.DOTALL,
)

_TRANSFER_SLOT = (
    r"balances?|balance_?of|shares?|share_?of|vault_?shares?|"
    r"stakes?|stake_?of|staked|user_?stake|user_?shares|positions?|"
    r"position_?owner|owners?|owner_?of|holders?|holder_?of|"
    r"delegations?|delegation_?boosts?|boost_?delegations?|delegates?|"
    r"delegatees?|boosts?|boost_?weight|weights?|multipliers?"
)

_MAP_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_TRANSFER_SLOT})\s*\."
    r"(?:insert|set|remove)\s*\([^;{}]*(?:"
    r"from|sender|src|source|owner|holder|old_?owner|old_?holder|"
    r"delegator|old_?delegate|old_?delegatee|from_?vault|from_?account|"
    r"to|receiver|recipient|dst|destination|new_?owner|new_?holder|"
    r"delegatee|new_?delegate|to_?vault|to_?account)"
)

_INDEX_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_TRANSFER_SLOT})"
    r"\s*(?:\[[^\]]*(?:"
    r"from|sender|src|source|owner|holder|old_?owner|old_?holder|"
    r"delegator|old_?delegate|old_?delegatee|from_?vault|from_?account|"
    r"to|receiver|recipient|dst|destination|new_?owner|new_?holder|"
    r"delegatee|new_?delegate|to_?vault|to_?account)[^\]]*\]\s*){1,3}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|-=|\*=|/=|=)"
)

_ENTRY_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_TRANSFER_SLOT})\s*\."
    r"(?:entry|get_mut)\s*\([^;{}]*(?:"
    r"from|sender|src|source|owner|holder|old_?owner|old_?holder|"
    r"delegator|old_?delegate|old_?delegatee|from_?vault|from_?account|"
    r"to|receiver|recipient|dst|destination|new_?owner|new_?holder|"
    r"delegatee|new_?delegate|to_?vault|to_?account)"
)

_DOTTED_WRITE_RE = re.compile(
    rf"(?is)\b(?:from|sender|src|source|owner|holder|old_?owner|old_?holder|"
    rf"delegator|old_?delegate|old_?delegatee|from_?vault|from_?account|"
    rf"source_?account|from_?position|old_?position|to|receiver|recipient|"
    rf"dst|destination|new_?owner|new_?holder|delegatee|new_?delegate|"
    rf"to_?vault|to_?account|dest_?account|recipient_?account|"
    rf"to_?position|new_?position)"
    rf"(?:_[A-Za-z0-9]+)?\s*\.\s*(?P<slot>{_TRANSFER_SLOT})"
    r"\s*(?:\+=|-=|\*=|/=|=)"
)

_NESTED_ACCOUNT_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?:users?|accounts?|holders?|stakers?|positions?|"
    rf"delegations?|boosts?)\s*\[[^\]]*(?:from|sender|src|source|owner|"
    rf"old_?owner|delegator|old_?delegate|to|receiver|recipient|dst|"
    rf"destination|new_?owner|delegatee|new_?delegate)[^\]]*\]\s*\."
    rf"(?P<slot>{_TRANSFER_SLOT})\s*(?:\+=|-=|\*=|/=|=)"
)

_SETTLEMENT_CALL_RE = re.compile(
    r"(?is)(?:\b|\.|_)"
    r"(?P<name>"
    r"(?:update|sync|settle|checkpoint|accrue|harvest|claim)_?"
    r"(?:user_?|account_?|position_?|stake_?|share_?|boost_?|"
    r"delegation_?)?"
    r"(?:reward|rewards|reward_?index|user_?index|accumulator|"
    r"pending|accrual|checkpoint)|"
    r"(?:settle|checkpoint)_?transfer_?(?:reward|rewards|accrual)?|"
    r"update_?reward|update_?rewards|settle_?rewards|checkpoint_?rewards|"
    r"accrue|settle|checkpoint|harvest"
    r")\s*\((?P<args>[^;{}()]*)\)"
)

_SNAPSHOT_WRITE_RE = re.compile(
    r"(?is)\b(?:self\.)?(?:user_)?(?:reward_?debt|reward_?debts|"
    r"reward_?index|reward_?per_?(?:token|share|stake|weight)_?paid|"
    r"last_?reward(?:_?index)?|paid_?index|accrued_?rewards?|"
    r"pending_?rewards?)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}"
    r"(?:\.\s*(?:insert|set)\s*\([^;{}]*\)|\s*(?:\+=|-=|=))"
)

_DOTTED_SNAPSHOT_WRITE_RE = re.compile(
    r"(?is)\b(?:from|sender|src|source|owner|holder|old_?owner|old_?holder|"
    r"delegator|old_?delegate|old_?delegatee|from_?account|to|receiver|"
    r"recipient|dst|destination|new_?owner|new_?holder|delegatee|"
    r"new_?delegate|to_?account)(?:_[A-Za-z0-9]+)?\s*\.\s*"
    r"(?:reward_?debt|reward_?index|user_?index|paid_?index|"
    r"last_?reward(?:_?index)?|accrued_?rewards?|pending_?rewards?)"
    r"\s*(?:\+=|-=|=)"
)

_NESTED_SNAPSHOT_WRITE_RE = re.compile(
    r"(?is)\b(?:self\.)?(?:users?|accounts?|holders?|stakers?|positions?|"
    r"delegations?|delegation_?boosts?|boosts?)"
    r"(?:\s*\[[^\]]*(?:from|sender|src|source|owner|old_?owner|delegator|"
    r"old_?delegate|to|receiver|recipient|dst|destination|new_?owner|"
    r"delegatee|new_?delegate)[^\]]*\]\s*|\s*\.\s*get_mut\s*\([^;{}]*"
    r"(?:from|sender|src|source|owner|old_?owner|delegator|old_?delegate|"
    r"to|receiver|recipient|dst|destination|new_?owner|delegatee|"
    r"new_?delegate)[^;{}]*\)\s*)"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*|\s*\?\s*){0,4}\s*\.\s*"
    r"(?:reward_?debt|reward_?index|user_?index|paid_?index|"
    r"last_?reward(?:_?index)?|accrued_?rewards?|pending_?rewards?)"
    r"\s*(?:\+=|-=|=)"
)


def _strip_strings(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = match.group(0)
        return "\n" * value.count("\n") if "\n" in value else " "

    return _STRING_RE.sub(repl, text)


def _side_mask(text: str) -> int:
    mask = 0
    if _SOURCE_ACTOR_RE.search(text):
        mask |= 1
    if _DEST_ACTOR_RE.search(text):
        mask |= 2
    return mask


def _has_transfer_shape(name: str, body: str) -> bool:
    if _TRANSFER_FN_RE.search(name):
        return True
    return (
        bool(_SOURCE_ACTOR_RE.search(body))
        and bool(_DEST_ACTOR_RE.search(body))
        and bool(_TRANSFER_CONTEXT_RE.search(body))
    )


def _first_transfer_mutation(body: str) -> tuple[str, re.Match[str]] | None:
    candidates: list[tuple[str, re.Match[str]]] = []
    for label, pattern in (
        ("map transfer-state write", _MAP_WRITE_RE),
        ("indexed transfer-state write", _INDEX_WRITE_RE),
        ("entry transfer-state write", _ENTRY_WRITE_RE),
        ("account field transfer-state write", _DOTTED_WRITE_RE),
        ("nested account transfer-state write", _NESTED_ACCOUNT_WRITE_RE),
    ):
        for match in pattern.finditer(body):
            candidates.append((label, match))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[1].start())


def _slot_from_match(match: re.Match[str]) -> str:
    return match.groupdict().get("slot") or "transfer accounting state"


def _settled_sides_before(body: str, mutation_pos: int) -> int:
    prefix = body[:mutation_pos]
    mask = 0
    for match in _SETTLEMENT_CALL_RE.finditer(prefix):
        mask |= _side_mask(match.group(0))
    for match in _SNAPSHOT_WRITE_RE.finditer(prefix):
        mask |= _side_mask(match.group(0))
    for match in _DOTTED_SNAPSHOT_WRITE_RE.finditer(prefix):
        mask |= _side_mask(match.group(0))
    for match in _NESTED_SNAPSHOT_WRITE_RE.finditer(prefix):
        mask |= _side_mask(match.group(0))
    return mask


def _unsafe_transfer_orphan(name: str, body: str) -> tuple[str, re.Match[str]] | None:
    if not _has_transfer_shape(name, body):
        return None
    if not _REWARD_CONTEXT_RE.search(body):
        return None
    if _side_mask(body) != 3:
        return None

    candidate = _first_transfer_mutation(body)
    if candidate is None:
        return None

    label, match = candidate
    if _settled_sides_before(body, match.start()) == 3:
        return None
    return label, match


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    module_text = _strip_strings(source_nocomment(source))
    if not _REWARD_CONTEXT_RE.search(module_text):
        return hits

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue

        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = _strip_strings(body_text_nocomment(body, source))
        result = _unsafe_transfer_orphan(name, body_nc)
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
                    f"fn `{name}` performs a {label} on `{slot}` before "
                    f"checkpointing reward debt, user index, or accrued "
                    f"rewards for both transfer sides. Old rewards can "
                    f"follow the moved token, stake, vault, boost, or "
                    f"delegation position to the wrong account "
                    f"(rewards-distribution-skew, Fire33 transfer orphan "
                    f"lift)."
                ),
            }
        )
    return hits
