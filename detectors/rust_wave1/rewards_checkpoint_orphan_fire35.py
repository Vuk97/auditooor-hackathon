"""
rewards_checkpoint_orphan_fire35.py

Fire35 Rust lift for rewards-distribution-skew checkpoint orphan paths.

Flags transfer, delegation-change, owner reassignment, and withdrawal paths
that mutate old stake or reward ownership before settling the old account.
New-side-only settlement does not clear the hit because accrued rewards tied
to the previous holder can be orphaned or assigned to the wrong user.

Source refs:
- reports/detector_lift_fire34_20260605/post_priorities_rust.md
- reference/patterns.dsl/rewards-distribution-skew.yaml
  (requested source ref; absent in this checkout, see worker result)
- detectors/rust_wave1/rust_rewards_accumulator_checkpoint_fire32.py
- detectors/rust_wave1/rust_rewards_transfer_orphan_fire33.py

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
    r"accrued|reward_?debt|reward_?index|user_?index|paid_?index|"
    r"last_?reward|reward_?per_?(?:share|token|stake|weight)|"
    r"acc_?reward|accumulator|checkpoint|settle|delegat(?:e|ion)|"
    r"stake|staked|shares?|owner_?shares|position_?owner)"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)(transfer|transfer_?position|move_?position|assign|reassign|"
    r"set_?owner|change_?owner|delegate|redelegate|change_?delegation|"
    r"set_?delegate|withdraw|unstake|unbond|slash|move_?stake|"
    r"move_?shares|rotate_?owner|rotate_?stake)"
)

_OWNERSHIP_CONTEXT_RE = re.compile(
    r"(?i)(transfer|withdraw|unstake|unbond|owner|holder|position|"
    r"delegat(?:e|ion|or)|validator|stake|staked|shares?|vault|"
    r"reward_?owner|old_?owner|old_?delegate|from|sender|source)"
)

_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'",
    re.DOTALL,
)

_OLD_ARG = (
    r"from|sender|src|source|old_?owner|old_?holder|old_?account|"
    r"old_?position|old_?delegate|old_?delegatee|old_?validator|"
    r"previous|prior|delegator|account|user|owner|holder"
)
_NEW_ARG = (
    r"to|receiver|recipient|dst|destination|new_?owner|new_?holder|"
    r"new_?account|new_?position|new_?delegate|new_?delegatee|"
    r"new_?validator|delegatee|validator"
)
_MUTATION_ARG = rf"(?:{_OLD_ARG}|{_NEW_ARG}|position_?id|token_?id)"

_STATE_SLOT = (
    r"owner_?shares|vault_?shares|position_?owner|reward_?owners?|"
    r"validator_?(?:stake|weight)|delegate_?(?:stake|weight)|"
    r"stakes?|stake_?of|staked|balances?|balance_?of|shares?|"
    r"share_?of|positions?|owners?|owner_?of|holders?|holder_?of|"
    r"delegations?|delegatees?|delegates?|delegated_?to|"
    r"delegation_?(?:stake|weight|owner|boosts?)"
)

_MAP_MUTATION_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_STATE_SLOT})\s*\."
    rf"(?:insert|set|remove|take)\s*\([^;{{}}]*(?:{_MUTATION_ARG})"
)

_ENTRY_MUTATION_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_STATE_SLOT})\s*\."
    rf"(?:entry|get_mut)\s*\([^;{{}}]*(?:{_OLD_ARG}|{_NEW_ARG})"
)

_INDEX_MUTATION_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_STATE_SLOT})"
    rf"\s*(?:\[[^\]]*(?:{_MUTATION_ARG})[^\]]*\]\s*){{1,3}}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|-=|\*=|/=|=)"
)

_DOTTED_MUTATION_RE = re.compile(
    rf"(?is)\b(?:{_OLD_ARG}|{_NEW_ARG})(?:_[A-Za-z0-9]+)?"
    rf"\s*\.\s*(?P<slot>{_STATE_SLOT})\s*(?:\+=|-=|\*=|/=|=)"
)

_OWNER_FIELD_REASSIGN_RE = re.compile(
    rf"(?is)\b(?:position|stake|delegation|account|holder|owner)"
    rf"(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*|\s*\[[^\]]+\]){{0,4}}"
    rf"\s*\.\s*(?P<slot>owner|holder|delegatee|validator|reward_?owner)"
    rf"\s*=\s*(?:{_NEW_ARG})\b"
)

_SETTLEMENT_CALL_RE = re.compile(
    r"(?is)(?:\b|\.)"
    r"(?P<name>"
    r"(?:update|sync|settle|checkpoint|accrue|harvest)_?"
    r"(?:all_?|user_?|account_?|owner_?|holder_?|position_?|"
    r"stake_?|share_?|delegation_?|validator_?)?"
    r"(?:reward|rewards|reward_?index|user_?index|accumulator|"
    r"pending|accrual|checkpoint|index|account|position|stake|"
    r"delegation)?|"
    r"(?:settle|checkpoint)_?all_?(?:rewards|accounts|positions)?"
    r")\s*\((?P<args>[^;{}()]*)\)"
)

_OLD_SNAPSHOT_WRITE_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?:user_)?(?:reward_?debt|reward_?debts|"
    rf"reward_?index|reward_?index_?paid|user_?reward_?index|"
    rf"last_?reward(?:_?index)?|paid_?index|accrued_?rewards?|"
    rf"pending_?rewards?)"
    rf"(?:\s*\[[^\]]*(?:{_OLD_ARG})[^\]]*\]\s*|"
    rf"\s*\.\s*(?:insert|set)\s*\([^;{{}}]*(?:{_OLD_ARG}))"
)

_OLD_ARG_RE = re.compile(rf"(?i)\b(?:{_OLD_ARG})\b")
_BROAD_SETTLE_NAME_RE = re.compile(r"(?i)\b(?:all|everyone|every_?account|users|accounts)\b")


def _strip_strings(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = match.group(0)
        return "\n" * value.count("\n") if "\n" in value else " "

    return _STRING_RE.sub(repl, text)


def _first_ownership_mutation(body: str) -> tuple[str, re.Match[str]] | None:
    candidates: list[tuple[str, re.Match[str]]] = []
    for label, pattern in (
        ("map ownership or stake write", _MAP_MUTATION_RE),
        ("entry ownership or stake write", _ENTRY_MUTATION_RE),
        ("indexed ownership or stake write", _INDEX_MUTATION_RE),
        ("account ownership or stake field write", _DOTTED_MUTATION_RE),
        ("position owner field reassignment", _OWNER_FIELD_REASSIGN_RE),
    ):
        for match in pattern.finditer(body):
            candidates.append((label, match))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[1].start())


def _slot_from_match(match: re.Match[str]) -> str:
    return match.groupdict().get("slot") or "reward ownership state"


def _settles_old_side_before(body: str, pos: int) -> bool:
    prefix = body[:pos]
    if _OLD_SNAPSHOT_WRITE_RE.search(prefix):
        return True

    for match in _SETTLEMENT_CALL_RE.finditer(prefix):
        name = match.group("name") or ""
        args = match.group("args") or ""
        if _OLD_ARG_RE.search(args):
            return True
        if _BROAD_SETTLE_NAME_RE.search(name):
            return True
    return False


def _has_relevant_shape(name: str, body: str) -> bool:
    if _ENTRY_FN_RE.search(name):
        return True
    return bool(_OLD_ARG_RE.search(body) and _OWNERSHIP_CONTEXT_RE.search(body))


def _unsafe_checkpoint_orphan(
    name: str,
    body: str,
) -> tuple[str, re.Match[str]] | None:
    if not _REWARD_CONTEXT_RE.search(f"{name}\n{body}"):
        return None
    if not _has_relevant_shape(name, body):
        return None

    candidate = _first_ownership_mutation(body)
    if candidate is None:
        return None

    label, match = candidate
    if _settles_old_side_before(body, match.start()):
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
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue

        body_nc = _strip_strings(body_text_nocomment(body, source))
        result = _unsafe_checkpoint_orphan(name, body_nc)
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
                    f"before settling the old reward account. Transfer, "
                    f"delegation, withdrawal, or owner-change rewards can "
                    f"be orphaned or assigned to the wrong user "
                    f"(rewards-distribution-skew, Fire35 checkpoint "
                    f"orphan lift)."
                ),
            }
        )
    return hits
