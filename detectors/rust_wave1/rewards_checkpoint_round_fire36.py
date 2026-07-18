"""
rewards_checkpoint_round_fire36.py

Fire36 Rust lift for rewards-distribution-skew checkpoint-round paths.

Flags public reward round, epoch, checkpoint, accrual, distribution, or
settlement entrypoints that start accrual, then read mutable supply,
delegate-set, round-index, or pending-reward state before settlement
finalizes. The unsafe shape is a round that begins with one eligibility
surface, then computes or settles with a later live surface.

Source refs:
- reports/detector_lift_fire35_20260605/post_priorities_rust.md
- reference/patterns.dsl/rewards-distribution-skew.yaml
  (requested source ref; absent in this checkout)
- reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml
- detectors/rust_wave1/rewards_checkpoint_orphan_fire35.py
- detectors/wave17/rewards_delegate_drift_fire35.py

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
    r"(?i)(reward|rewards|emission|incentive|distribution|distribute|"
    r"accrual|accrue|claimable|pending|earned|accrued|checkpoint|"
    r"settle|settlement|round|epoch|reward_?index|reward_?debt|"
    r"reward_?per_?(?:share|token|stake|weight)|acc_?reward|"
    r"accumulator|delegate|delegation|total_?(?:supply|stake|shares|weight))"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)(checkpoint|settle|finalize|complete|close|seal|commit|"
    r"start|begin|open|activate|notify|fund|accrue|distribute|"
    r"allocate|claim|harvest|round|epoch|cycle)"
)

_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'",
    re.DOTALL,
)

_ACCRUAL_START_RE = re.compile(
    r"(?is)(?:"
    r"(?:\b|\.)(?P<call>"
    r"(?:start|begin|open|activate|queue|fund|notify|accrue|create|init)"
    r"_?(?:reward|rewards|reward_?round|reward_?epoch|distribution|"
    r"accrual|round|epoch|checkpoint|cycle)|"
    r"(?:reward|rewards|distribution|accrual)_?"
    r"(?:start|begin|open|activate|funding|queued)"
    r")\s*\(|"
    r"\b(?:self\.)?(?P<slot>"
    r"current_?round|active_?round|reward_?round|round_?index|"
    r"current_?epoch|active_?epoch|reward_?epoch|epoch_?index|"
    r"round_?rewards?|reward_?rounds?|epoch_?rewards?|"
    r"pending_?rewards?|accrual_?started|round_?open|"
    r"distribution_?active"
    r")\s*(?:=|\+=|-=|\.insert\s*\(|\.set\s*\()"
    r")"
)

_FINALIZE_RE = re.compile(
    r"(?is)(?:"
    r"(?:\b|\.)(?P<call>"
    r"(?:finalize|settle|complete|close|commit|seal|finish|mark)"
    r"_?[A-Za-z0-9_]*"
    r"(?:reward|rewards|round|epoch|distribution|settlement|"
    r"checkpoint|accrual|cycle)[A-Za-z0-9_]*|"
    r"(?:settle|checkpoint)_?(?:all|round|epoch|pending|rewards|"
    r"settlement)|"
    r"materialize_?(?:reward|rewards)|"
    r"credit_?(?:pending_?)?(?:reward|rewards)"
    r")\s*\(|"
    r"\b(?:self\.)?(?P<slot>"
    r"round_?settled|settled_?rounds?|settlement_?finalized|"
    r"finalized_?round|closed_?round|round_?status|epoch_?status"
    r")\s*(?:=|\.insert\s*\(|\.set\s*\()"
    r")"
)

_SUPPLY_FIELD = (
    r"total_?(?:supply|stake|staked|shares|share|weight|delegated_?"
    r"(?:power|votes|weight))|share_?supply|stake_?supply|"
    r"reward_?supply|eligible_?supply|qualified_?supply|"
    r"active_?stake|active_?shares|active_?weight"
)

_SUPPLY_READ_RE = re.compile(
    rf"(?is)(?:"
    rf"\blet\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*"
    rf"(?:supply|stake|shares?|weight|denom|total)[A-Za-z0-9_]*"
    rf"\s*=\s*(?:&\s*)?(?:self\.)?(?P<slot>{_SUPPLY_FIELD})\b|"
    rf"/\s*(?:self\.)?(?P<div_slot>{_SUPPLY_FIELD})\b|"
    rf"(?:\b|\.)"
    rf"(?P<method>total_?(?:supply|stake|shares|weight)|"
    rf"eligible_?(?:supply|stake|shares|weight)|"
    rf"active_?(?:stake|shares|weight))\s*\("
    rf")"
)

_DELEGATE_FIELD = (
    r"delegates?|delegate_?set|delegatees?|delegations?|validators?|"
    r"validator_?set|validator_?weights?|operator_?set|reward_?delegates?"
)

_DELEGATE_READ_RE = re.compile(
    rf"(?is)\b(?:self\.)?(?P<slot>{_DELEGATE_FIELD})"
    rf"(?:\s*\[[^\]]+\]\s*)?"
    rf"\s*\.\s*(?:len|get|contains_key|contains|iter|keys|values)\s*\("
)

_ROUND_FIELD = (
    r"current_?round|active_?round|reward_?round|round_?index|"
    r"last_?round|next_?round|current_?epoch|active_?epoch|"
    r"reward_?epoch|epoch_?index|last_?epoch|next_?epoch"
)

_ROUND_READ_RE = re.compile(
    rf"(?is)(?:"
    rf"\blet\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*"
    rf"(?:round|epoch|index)[A-Za-z0-9_]*\s*="
    rf"\s*(?:&\s*)?(?:self\.)?(?P<slot>{_ROUND_FIELD})\b|"
    rf"\b(?:self\.)?(?:rounds?|reward_?rounds?|epochs?|reward_?epochs?)"
    rf"\s*\.\s*(?:get|contains_key)\s*\([^;{{}}]*"
    rf"(?:self\.)?(?P<nested_slot>{_ROUND_FIELD})"
    rf")"
)

_PENDING_FIELD = (
    r"pending_?rewards?|claimable_?rewards?|accrued_?rewards?|"
    r"earned_?rewards?|unclaimed_?rewards?|reward_?balances?|"
    r"reward_?credits?|owed_?rewards?"
)

_PENDING_READ_RE = re.compile(
    rf"(?is)(?:"
    rf"\b(?:self\.)?(?P<slot>{_PENDING_FIELD})"
    rf"(?:\s*\[[^\]]+\]\s*|\s*\.\s*(?:get|contains_key)\s*\()[^;{{}}]*|"
    rf"(?:\b|\.)(?P<call>"
    rf"pending_?reward|pending_?rewards|claimable_?reward|"
    rf"claimable_?rewards|earned|earned_?reward|accrued_?reward|"
    rf"reward_?due|owed_?reward|get_?reward"
    rf")\s*\("
    rf")"
)

_MUTABLE_READ_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("live supply or weight read", _SUPPLY_READ_RE),
    ("delegate-set read", _DELEGATE_READ_RE),
    ("round or epoch index read", _ROUND_READ_RE),
    ("pending reward state read", _PENDING_READ_RE),
)


def _strip_strings(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = match.group(0)
        return "\n" * value.count("\n") if "\n" in value else " "

    return _STRING_RE.sub(repl, text)


def _slot_from_match(match: re.Match[str]) -> str:
    for key in ("slot", "div_slot", "method", "nested_slot", "call"):
        value = match.groupdict().get(key)
        if value:
            return value
    return "mutable reward checkpoint state"


def _first_match(pattern: re.Pattern[str], text: str, pos: int = 0) -> re.Match[str] | None:
    return pattern.search(text, pos)


def _first_mutable_read(window: str) -> tuple[str, re.Match[str]] | None:
    candidates: list[tuple[str, re.Match[str]]] = []
    for label, pattern in _MUTABLE_READ_PATTERNS:
        for match in pattern.finditer(window):
            candidates.append((label, match))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[1].start())


def _unsafe_round_checkpoint(name: str, body: str) -> tuple[str, str, re.Match[str]] | None:
    if not _REWARD_CONTEXT_RE.search(f"{name}\n{body}"):
        return None
    if not _ENTRY_FN_RE.search(name):
        return None

    start = _first_match(_ACCRUAL_START_RE, body)
    if start is None:
        return None

    finalize = _first_match(_FINALIZE_RE, body, start.end())
    if finalize is None:
        return None

    window = body[start.end() : finalize.start()]
    candidate = _first_mutable_read(window)
    if candidate is None:
        return None

    label, match = candidate
    return label, _slot_from_match(match), match


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
        result = _unsafe_round_checkpoint(name, body_nc)
        if result is None:
            continue

        label, slot, _match = result
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` starts a reward accrual round, then "
                    f"performs a {label} on `{slot}` before settlement "
                    f"finalizes. Checkpointed rewards can be skewed if "
                    f"mutable supply, delegate, round, or pending state is "
                    f"read after accrual start and before final settlement "
                    f"(rewards-distribution-skew, Fire36 checkpoint round "
                    f"lift)."
                ),
            }
        )
    return hits
