"""
rewards-supply-checkpoint-fire31

Fire31 Solidity lift for rewards-distribution-skew misses where a reward
denominator, reward accumulator, user reward debt, or reward checkpoint slot
is mutated before old rewards are settled.

Source refs:
- reports/detector_lift_fire30_20260605/post_priorities_solidity.md
- detectors/wave17/reward_per_token_precision_floor_fire30.py
- reference/patterns.dsl/rewardloss-in-staking-contracts.yaml

Candidate evidence only. A hit is NOT_SUBMIT_READY and must not be cited as
proof without source existence, a real in-scope entrypoint, negative control,
and R40/R76/R80 evidence honesty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-supply-checkpoint-fire31"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    body_line: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_VISIBILITY_RE = re.compile(r"\b(?:external|public|internal)\b", re.IGNORECASE)
_PURE_VIEW_RE = re.compile(r"\b(?:pure|view)\b", re.IGNORECASE)
_REWARD_CONTEXT_RE = re.compile(
    r"\b(?:reward[A-Za-z0-9_]*|rewards[A-Za-z0-9_]*|"
    r"userReward[A-Za-z0-9_]*|accReward[A-Za-z0-9_]*|"
    r"pendingReward[A-Za-z0-9_]*|claimableReward[A-Za-z0-9_]*|"
    r"accruedReward[A-Za-z0-9_]*|earnedReward[A-Za-z0-9_]*|"
    r"unclaimedReward[A-Za-z0-9_]*|checkpoint[A-Za-z0-9_]*|"
    r"stake[A-Za-z0-9_]*|staking[A-Za-z0-9_]*|"
    r"staked[A-Za-z0-9_]*|share[A-Za-z0-9_]*|shares[A-Za-z0-9_]*|"
    r"totalStaked|totalShares)\b",
    re.IGNORECASE,
)
_ENTRY_CONTEXT_RE = re.compile(
    r"\b(?:claim|collect|deposit|distribute|getReward|harvest|mint|"
    r"notify|redeem|settle|stake|sync|update|withdraw|unstake|exit|"
    r"checkpoint|reward)[A-Za-z0-9_]*",
    re.IGNORECASE,
)

_PREFIX = r"(?:[A-Za-z_][A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*)*\.\s*)?"
_INDEXES = r"(?:\s*\[[^\]]+\]\s*)*"
_FIELD = r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
_ASSIGN_OP = r"(?P<op>\+=|-=|=|\+\+|--)"
_ASSIGN_TAIL = r"\s*(?P<expr>[^;{}]{0,360})?;"

_SUPPLY_SLOT = (
    r"(?:_?totalSupply|totalStaked|totalStake|stakingSupply|"
    r"stakedSupply|totalShares|shareSupply|sharesSupply|totalWeight|"
    r"totalRewardWeight|rewardSupply|rewardWeight|allocPoint|"
    r"allocationPoint)"
)
_ACCUMULATOR_SLOT = (
    r"(?:rewardPerTokenStored|rewardPerToken|rewardPerShare|"
    r"accRewardPerShare|accPerShare|rewardIndex|globalRewardIndex|"
    r"rewardAccumulator|rewardsPerShare)"
)
_USER_DEBT_SLOT = (
    r"(?:rewardDebt|rewardDebts|userRewardDebt|userRewardDebts|"
    r"userRewardPerTokenPaid|rewardIndexPaid|lastRewardIndex|"
    r"paidRewardIndex|claimedRewardIndex)"
)
_CHECKPOINT_SLOT = (
    r"(?:rewardCheckpoint|rewardCheckpoints|rewardCursor|"
    r"rewardEpochCursor|lastClaimedEpoch|lastRewardEpoch|"
    r"lastRewardCheckpoint|checkpointRewardIndex|rewardCheckpointIndex)"
)

_SUPPLY_WRITE_RE = re.compile(
    rf"\b(?P<slot>{_PREFIX}{_SUPPLY_SLOT}){_INDEXES}{_FIELD}\s*"
    rf"{_ASSIGN_OP}{_ASSIGN_TAIL}",
    re.IGNORECASE | re.DOTALL,
)
_ACCUMULATOR_WRITE_RE = re.compile(
    rf"\b(?P<slot>{_PREFIX}{_ACCUMULATOR_SLOT}){_INDEXES}{_FIELD}\s*"
    rf"{_ASSIGN_OP}{_ASSIGN_TAIL}",
    re.IGNORECASE | re.DOTALL,
)
_USER_DEBT_WRITE_RE = re.compile(
    rf"\b(?P<slot>{_PREFIX}{_USER_DEBT_SLOT}){_INDEXES}{_FIELD}\s*"
    rf"{_ASSIGN_OP}{_ASSIGN_TAIL}",
    re.IGNORECASE | re.DOTALL,
)
_CHECKPOINT_WRITE_RE = re.compile(
    rf"\b(?P<slot>{_PREFIX}{_CHECKPOINT_SLOT}){_INDEXES}{_FIELD}\s*"
    rf"{_ASSIGN_OP}{_ASSIGN_TAIL}|"
    rf"\bdelete\s+(?P<delete_slot>{_PREFIX}{_CHECKPOINT_SLOT})"
    rf"{_INDEXES}{_FIELD}\s*;",
    re.IGNORECASE | re.DOTALL,
)

_SETTLEMENT_CALL_RE = re.compile(
    r"\b(?:"
    r"_?updateRewards?|_?updateReward|_?settleRewards?|_?settleReward|"
    r"_?checkpointRewards?|_?checkpointReward|_?checkpointUser|"
    r"_?checkpointAccount|_?checkpointPosition|_?checkpointStake|"
    r"_?accrueRewards?|_?accrueReward|_?syncRewards?|_?syncReward|"
    r"_?harvestRewards?|_?harvestReward|_?claimRewards?|_?claimReward|"
    r"_?updatePool|_?updateRewardIndex|_?settleAccount|"
    r"_?settlePosition|earned|rewardPerToken"
    r")\s*\(",
    re.IGNORECASE,
)
_PRIOR_REWARD_CREDIT_RE = re.compile(
    r"\b(?:pendingRewards?|claimableRewards?|accruedRewards?|"
    r"earnedRewards?|unclaimedRewards?|cachedRewards?|userRewards?|"
    r"rewards)\s*(?:\[[^\]]+\]\s*)+"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|=)",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_GLOBAL_ACCUMULATOR_RE = re.compile(
    r"\b(?:rewardPerToken\s*\(|_?rewardPerToken\s*\(|"
    r"lastTimeRewardApplicable\s*\(|mulDiv\s*\(|"
    r"FullMath\s*\.\s*mulDiv|Math\s*\.\s*mulDiv)\b|"
    r"\*\s*(?:PRECISION|ACC_PRECISION|SCALE|WAD|RAY|1e18|1e12|"
    r"1000000000000000000|1000000000000)\s*\)*\s*/\s*"
    r"(?:_?totalSupply|totalStaked|totalStake|stakingSupply|"
    r"totalShares|shareSupply)",
    re.IGNORECASE | re.DOTALL,
)
_LATE_SETTLEMENT_RE = re.compile(
    r"\b(?:_?updateRewards?|_?updateReward|_?settleRewards?|"
    r"_?settleReward|_?checkpointRewards?|_?checkpointReward|"
    r"_?accrueRewards?|_?accrueReward|_?syncRewards?|"
    r"_?syncReward|_?updatePool|_?claimRewards?|_?claimReward)\s*\("
    r"|"
    r"\b(?:pendingRewards?|claimableRewards?|accruedRewards?|"
    r"earnedRewards?|userRewardPerTokenPaid|rewardDebt|rewardDebts|"
    r"userRewardDebt|rewardIndexPaid|rewardCheckpoint|lastRewardIndex)"
    r"\s*(?:\[[^\]]+\]\s*)+(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|=)",
    re.IGNORECASE | re.DOTALL,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    i = open_pos + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    close_brace = _find_matching_delimiter(source, open_brace, "{", "}")
    if close_brace < 0:
        return None, open_brace
    return source[open_brace + 1 : close_brace], close_brace + 1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        j = close_paren + 1
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, close_paren + 1)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start() : body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _slot_from_match(match: re.Match[str]) -> str:
    return (
        match.groupdict().get("slot")
        or match.groupdict().get("delete_slot")
        or "reward accounting state"
    )


def _has_prior_settlement(text: str) -> bool:
    return bool(_SETTLEMENT_CALL_RE.search(text) or _PRIOR_REWARD_CREDIT_RE.search(text))


def _safe_global_accumulator_write(match: re.Match[str]) -> bool:
    expr = match.groupdict().get("expr") or ""
    op = match.groupdict().get("op") or ""
    if op == "+=" and _SAFE_GLOBAL_ACCUMULATOR_RE.search(expr):
        return True
    return bool(_SAFE_GLOBAL_ACCUMULATOR_RE.search(expr))


def _sensitive_writes(fn: FunctionSlice) -> list[tuple[str, re.Match[str]]]:
    out: list[tuple[str, re.Match[str]]] = []
    for label, regex in (
        ("supply denominator", _SUPPLY_WRITE_RE),
        ("reward accumulator", _ACCUMULATOR_WRITE_RE),
        ("user reward debt", _USER_DEBT_WRITE_RE),
        ("reward checkpoint", _CHECKPOINT_WRITE_RE),
    ):
        for match in regex.finditer(fn.body):
            if label == "reward accumulator" and _safe_global_accumulator_write(match):
                continue
            out.append((label, match))
    return sorted(out, key=lambda item: item[1].start())


def _first_unsettled_sensitive_write(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    full_text = f"{fn.header}\n{fn.body}"
    if not _VISIBILITY_RE.search(fn.header):
        return None
    if _PURE_VIEW_RE.search(fn.header):
        return None
    if not _REWARD_CONTEXT_RE.search(full_text):
        return None
    if not (_ENTRY_CONTEXT_RE.search(fn.name) or _ENTRY_CONTEXT_RE.search(full_text)):
        return None

    for label, match in _sensitive_writes(fn):
        prefix = f"{fn.header}\n{fn.body[:match.start()]}"
        if _has_prior_settlement(prefix):
            continue
        tail = fn.body[match.end() : match.end() + 1400]
        if label == "supply denominator" and not _LATE_SETTLEMENT_RE.search(tail):
            continue
        return label, match
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _REWARD_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _first_unsettled_sensitive_write(fn)
        if result is None:
            continue
        label, match = result
        slot = _slot_from_match(match)
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_match(fn, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` mutates {label} `{slot}` before old "
                    "rewards are settled. Settle or checkpoint rewards, "
                    "credit pending rewards, and update user reward debt "
                    "before changing supply, accumulators, debt, or "
                    "checkpoint cursors."
                ),
            )
        )
    return findings


__all__ = ["DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT", "Finding", "scan"]
