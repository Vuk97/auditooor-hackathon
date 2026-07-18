"""
rewards_delegate_weight_checkpoint_fire37.py

Fire37 Rust lift for rewards-distribution-skew live delegate denominator
paths.

Flags public claim, reward distribution, and epoch accounting entrypoints
that compute reward payout math from live delegate weight, live total stake,
live active validator count, or the current recipient set instead of a
committed epoch checkpoint or snapshotted denominator. The unsafe shape lets
stake, validator membership, or recipient membership drift after eligibility
was supposed to be fixed for the epoch.

Source refs:
- reports/detector_lift_fire36_20260605/post_priorities_rust.md
- reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml
- detectors/rust_wave1/rewards_checkpoint_round_fire36.py
- detectors/rust_wave1/reward_index_or_supply_checkpoint_drift_fire20.py

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


DETECTOR_ID = "rust_wave1.rewards_delegate_weight_checkpoint_fire37"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"


_REWARD_CONTEXT_RE = re.compile(
    r"(?i)(reward|rewards|emission|incentive|distribution|distribute|"
    r"claim|claimable|pending|earned|accrued|owed|payout|epoch|round|"
    r"validator|delegate|delegation|stake|staked|weight|recipient|"
    r"reward_?index|reward_?debt|reward_?per_?(?:share|token|stake|weight)|"
    r"acc_?reward|accumulator)"
)

_ENTRY_FN_RE = re.compile(
    r"(?i)(claim|harvest|collect|withdraw_?reward|distribute|allocate|"
    r"account_?epoch|accrue_?epoch|settle_?epoch|finalize_?epoch|"
    r"close_?epoch|epoch_?account|checkpoint_?reward|update_?reward|"
    r"reward_?index|pay_?validator|pay_?delegate|settle_?validator)"
)

_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'",
    re.DOTALL,
)

_SAFE_DENOM_RE = re.compile(
    r"(?i)(snapshot|snapshotted|checkpoint|checkpointed|committed|"
    r"epoch_?checkpoint|epoch_?snapshot|reward_?epoch|"
    r"eligible_?(?:stake|weight|validators?|recipients?)|"
    r"qualified_?(?:stake|weight|validators?|recipients?)|"
    r"denominator_?snapshot|stake_?at_?epoch|weight_?at_?epoch|"
    r"validator_?count_?at_?epoch|recipients?_?at_?epoch|"
    r"total_?stake_?snapshot|delegate_?weight_?snapshot|"
    r"validator_?count_?snapshot|recipient_?count_?snapshot|"
    r"recipient_?set_?snapshot|frozen_?(?:stake|weight|validators?|recipients?))"
)

_PAYOUT_MATH_RE = re.compile(
    r"(?is)(?:"
    r"(?:reward|rewards|emission|payout|amount|epoch_?reward|"
    r"validator_?reward|delegate_?reward)[A-Za-z0-9_]*"
    r"[^;{}]{0,180}(?:/|\*|saturating_(?:mul|div)|checked_(?:mul|div))|"
    r"(?:reward_?per_?(?:share|stake|weight|validator|recipient)|"
    r"reward_?index|global_?index|acc_?reward|accumulator|owed|claimable|"
    r"pending|payout)[A-Za-z0-9_]*\s*(?:\+=|=)|"
    r"/\s*(?:[A-Za-z_][A-Za-z0-9_]*|self\.[A-Za-z_][A-Za-z0-9_]*)"
    r")"
)

_LIVE_TOTAL_STAKE_RE = re.compile(
    r"(?is)(?:"
    r"\blet\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:total|stake|staked|denom|denominator|weight)[A-Za-z0-9_]*"
    r"\s*=\s*(?:&\s*)?(?:self|state|pool|ledger|book|rewards?)\s*\."
    r"(?:total_?(?:stake|staked|delegated|weight|shares|supply)|"
    r"active_?(?:stake|staked|weight)|delegated_?(?:stake|weight))\b|"
    r"/\s*(?:self|state|pool|ledger|book|rewards?)\s*\."
    r"(?:total_?(?:stake|staked|delegated|weight|shares|supply)|"
    r"active_?(?:stake|staked|weight)|delegated_?(?:stake|weight))\b|"
    r"(?:\b|\.)"
    r"(?:total_?(?:stake|staked|delegated|weight|shares|supply)|"
    r"active_?(?:stake|staked|weight)|delegated_?(?:stake|weight))\s*\("
    r")"
)

_LIVE_DELEGATE_WEIGHT_RE = re.compile(
    r"(?is)(?:"
    r"\blet\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:delegate|validator|operator)?_?(?:weight|stake|power)[A-Za-z0-9_]*"
    r"\s*=\s*(?:&\s*)?(?:self|state|pool|ledger|book|rewards?)\s*\."
    r"(?:delegate|delegation|validator|operator)_?"
    r"(?:weights?|stake|stakes?|power|powers?)"
    r"\s*\.\s*(?:get|entry)\s*\(|"
    r"\b(?:self|state|pool|ledger|book|rewards?)\s*\."
    r"(?:delegate|delegation|validator|operator)_?"
    r"(?:weights?|stake|stakes?|power|powers?)"
    r"\s*\.\s*(?:get|entry)\s*\(|"
    r"(?:\b|\.)"
    r"(?:delegate|delegation|validator|operator)_?"
    r"(?:weight|stake|power|shares?)\s*\("
    r")"
)

_LIVE_VALIDATOR_COUNT_RE = re.compile(
    r"(?is)(?:"
    r"\blet\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:validator|validators|active|count)[A-Za-z0-9_]*"
    r"\s*=\s*(?:&\s*)?(?:self|state|pool|ledger|book|rewards?)\s*\."
    r"(?:active_?validators?|validators?|validator_?set|current_?validators?)"
    r"\s*\.\s*(?:len|iter)\s*\(|"
    r"\b(?:self|state|pool|ledger|book|rewards?)\s*\."
    r"(?:active_?validators?|validators?|validator_?set|current_?validators?)"
    r"\s*\.\s*(?:len|iter)\s*\(|"
    r"(?:\b|\.)"
    r"(?:active_?validator_?count|validator_?count|current_?validator_?count)"
    r"\s*\("
    r")"
)

_LIVE_RECIPIENT_SET_RE = re.compile(
    r"(?is)(?:"
    r"\blet\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:recipient|recipients|payee|payees|count)[A-Za-z0-9_]*"
    r"\s*=\s*(?:&\s*)?(?:self|state|pool|ledger|book|rewards?)\s*\."
    r"(?:current_?recipients?|reward_?recipients?|recipient_?set|"
    r"recipients?|payees?|payout_?recipients?)"
    r"\s*\.\s*(?:len|iter|keys|values)\s*\(|"
    r"\b(?:self|state|pool|ledger|book|rewards?)\s*\."
    r"(?:current_?recipients?|reward_?recipients?|recipient_?set|"
    r"recipients?|payees?|payout_?recipients?)"
    r"\s*\.\s*(?:len|iter|keys|values)\s*\(|"
    r"(?:\b|\.)"
    r"(?:current_?recipient_?count|recipient_?count|payee_?count)"
    r"\s*\("
    r")"
)

_LIVE_DENOM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("live total stake denominator", _LIVE_TOTAL_STAKE_RE),
    ("live delegate or validator weight", _LIVE_DELEGATE_WEIGHT_RE),
    ("live active validator count", _LIVE_VALIDATOR_COUNT_RE),
    ("current reward recipient set", _LIVE_RECIPIENT_SET_RE),
)


def _strip_strings(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        value = match.group(0)
        return "\n" * value.count("\n") if "\n" in value else " "

    return _STRING_RE.sub(repl, text)


def _line_window(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end]


def _math_near_live_read(body: str, match: re.Match[str]) -> bool:
    start = max(0, match.start() - 260)
    end = min(len(body), match.end() + 420)
    return bool(_PAYOUT_MATH_RE.search(body[start:end]))


def _first_unsafe_live_denominator(
    name: str,
    body: str,
) -> tuple[str, re.Match[str]] | None:
    if not _REWARD_CONTEXT_RE.search(f"{name}\n{body}"):
        return None
    if not _ENTRY_FN_RE.search(name):
        return None

    candidates: list[tuple[str, re.Match[str]]] = []
    for label, pattern in _LIVE_DENOM_PATTERNS:
        for match in pattern.finditer(body):
            line = _line_window(body, match.start(), match.end())
            if _SAFE_DENOM_RE.search(line):
                continue
            if not _math_near_live_read(body, match):
                continue
            candidates.append((label, match))

    if not candidates:
        return None
    return min(candidates, key=lambda item: item[1].start())


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
        result = _first_unsafe_live_denominator(name, body_nc)
        if result is None:
            continue

        label, _match = result
        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:220],
                "message": (
                    f"pub fn `{name}` computes reward claim or epoch "
                    f"accounting from a {label} instead of a committed "
                    f"epoch checkpoint or snapshotted denominator. Reward "
                    f"distribution can be skewed if stake, validator, or "
                    f"recipient membership changes before the claim or "
                    f"epoch payout (rewards-distribution-skew, Fire37 "
                    f"delegate weight checkpoint lift)."
                ),
            }
        )
    return hits
