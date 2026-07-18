"""
rewards-delegate-drift-fire35

Fire35 Solidity lift for rewards-distribution-skew variants where delegated,
boosted, recipient-list, checkpoint, or reward-supply accounting is mutated
before pending rewards are settled, then the same function reads or credits
pending reward state.

Source refs:
- reports/detector_lift_fire34_20260605/post_priorities_all.md
- reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml
- reference/patterns.dsl/r94-loop-boost-mutation-without-settling-rewards.yaml
- reference/patterns.dsl/r94-loop-reward-multiplier-reset-by-griefer.yaml
- detectors/wave17/rewards_live_supply_drift_fire34.py
- detectors/rust_wave1/rust_rewards_accumulator_checkpoint_fire32.py

Candidate evidence only. A hit is NOT_SUBMIT_READY and must not be cited as
proof without source existence, a real in-scope entrypoint, negative control,
and R40/R76/R80 evidence honesty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-delegate-drift-fire35"
DETECTOR_SEVERITY_DEFAULT = "Medium"
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
COVERAGE_CLAIM = "detector_fixture_smoke_only"
PROMOTION_ALLOWED = False
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"


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
    function_line: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_VISIBILITY_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_PURE_VIEW_RE = re.compile(r"\b(?:pure|view)\b", re.IGNORECASE)
_REWARD_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|rewards\w*|emission\w*|incentive\w*|"
    r"claimable\w*|pending\w*|earned\w*|accrued\w*|"
    r"rewardDebt\w*|rewardIndex\w*|rewardPer\w*|accReward\w*|"
    r"checkpoint\w*|delegate\w*|boost\w*|multiplier\w*)\b",
    re.IGNORECASE,
)
_ENTRY_CONTEXT_RE = re.compile(
    r"^(?:delegate|delegateRewards|setDelegate|setRewardDelegate|"
    r"redelegate|moveDelegates|updateDelegate|setRewardRecipients|"
    r"setRecipients|configureRecipients|updateRecipients|updateBoost|"
    r"setBoost|setMultiplier|refreshMultiplier|recomputeBoost|"
    r"updateStakeWeight|setWeight|stake|deposit|mint|increaseStake|"
    r"increaseBoostedBalance|withdraw|unstake|burn|transfer|"
    r"transferFrom|checkpoint|syncAccount|handleBalanceUpdate)",
    re.IGNORECASE,
)

_SETTLEMENT_CALL_RE = re.compile(
    r"\b(?:"
    r"_?settle[A-Za-z0-9_]*(?:Reward|Rewards|Account|User|Position)?|"
    r"_?update[A-Za-z0-9_]*(?:Reward|Rewards|RewardIndex|UserIndex|"
    r"GlobalIndex|Accumulator|Pool)|"
    r"_?sync[A-Za-z0-9_]*(?:Reward|Rewards|RewardIndex|Accumulator|Pool)|"
    r"_?checkpoint[A-Za-z0-9_]*(?:Reward|Rewards|Account|User|Position|"
    r"Stake|Shares|Delegate|Delegates|Votes|Index)?|"
    r"_?accrue[A-Za-z0-9_]*(?:Reward|Rewards|Account|User|Position)?|"
    r"_?harvest[A-Za-z0-9_]*(?:Reward|Rewards)?|"
    r"_?claim[A-Za-z0-9_]*(?:Reward|Rewards)?|"
    r"creditPendingRewards|materializeRewards"
    r")\s*\(",
    re.IGNORECASE,
)

_PENDING_REWARD_USE_RE = re.compile(
    r"\b(?:pendingReward|pendingRewards|claimableReward|claimableRewards|"
    r"earned|earnedReward|accruedReward|rewardDue|owedReward|"
    r"calculateReward|getReward|rewardOf)\s*\(|"
    r"\b(?:pending|claimable|earned|accrued|owed|rewardDue|payout)\s*="
    r"|\b(?:pendingRewards?|claimableRewards?|accruedRewards?|"
    r"earnedRewards?|unclaimedRewards?|rewardsAccrued|rewardBalances?)"
    r"\s*(?:\[[^\]]+\]\s*){1,3}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|=)",
    re.IGNORECASE | re.DOTALL,
)

_INDEXES = r"(?:\s*\[[^\]]+\]\s*)+"
_FIELD_TAIL = r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"

_DELEGATE_WRITE_RE = re.compile(
    rf"\bdelete\s+(?P<delete_slot>"
    rf"(?:rewardDelegates?|delegateOf|delegates?|delegatee|delegation)"
    rf"){_INDEXES}\s*;|"
    rf"\b(?P<slot>"
    rf"(?:rewardDelegates?|delegateOf|delegates?|delegatee|delegation)"
    rf"){_INDEXES}{_FIELD_TAIL}\s*(?:=|\+=|-=)",
    re.IGNORECASE | re.DOTALL,
)

_RECIPIENT_WRITE_RE = re.compile(
    rf"\bdelete\s+(?P<delete_slot>"
    rf"(?:rewardRecipients?|payoutRecipients?|recipientList|recipients)"
    rf"){_INDEXES}\s*;|"
    rf"\b(?P<slot>"
    rf"(?:rewardRecipients?|payoutRecipients?|recipientList|recipients)"
    rf"){_INDEXES}{_FIELD_TAIL}\s*(?:=|\+=|-=)|"
    rf"\b(?P<push_slot>"
    rf"(?:rewardRecipients?|payoutRecipients?|recipientList|recipients)"
    rf"){_INDEXES}\s*\.\s*(?:push|pop)\s*\(",
    re.IGNORECASE | re.DOTALL,
)

_BOOST_OR_WEIGHT_WRITE_RE = re.compile(
    rf"\b(?P<slot>"
    rf"(?:boosts?|boostMultiplier|boostMultipliers|boostFactor|"
    rf"boostFactors|multiplier|multipliers|rewardMultiplier|"
    rf"rewardMultipliers|weight|weights|stakeWeight|stakeWeights|"
    rf"rewardWeight|rewardWeights|boostedBalance|boostedBalances|"
    rf"votingPower|votingPowerOf|delegateVotes|delegatedVotes|"
    rf"delegatedPower)"
    rf"){_INDEXES}{_FIELD_TAIL}\s*(?:=|\+=|-=|\*=|/=)",
    re.IGNORECASE | re.DOTALL,
)

_SUPPLY_WRITE_RE = re.compile(
    r"\b(?P<slot>"
    r"(?:totalBoostedSupply|totalRewardSupply|rewardSupply|"
    r"totalEligibleSupply|eligibleSupply|totalWeight|totalStakeWeight|"
    r"totalVotingPower|totalDelegatedPower|totalDelegatedVotes|"
    r"totalStaked|totalStake|totalShares|shareSupply|_?totalSupply)"
    r")\s*(?:=|\+=|-=|\*=|/=)",
    re.IGNORECASE,
)

_CHECKPOINT_WRITE_RE = re.compile(
    rf"\b(?P<slot>"
    rf"(?:delegateCheckpoint|delegateCheckpoints|rewardCheckpoint|"
    rf"rewardCheckpoints|checkpoints|checkpointEpoch|rewardEpoch|"
    rf"rewardIndexPaid|userRewardIndex|userRewardIndexes|"
    rf"lastRewardIndex|lastRewardIndexes|rewardDebt|rewardDebts)"
    rf"){_INDEXES}{_FIELD_TAIL}\s*(?:=|\+=|-=)",
    re.IGNORECASE | re.DOTALL,
)

_MUTATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("delegate assignment", _DELEGATE_WRITE_RE),
    ("reward recipient list mutation", _RECIPIENT_WRITE_RE),
    ("boost, multiplier, or weight mutation", _BOOST_OR_WEIGHT_WRITE_RE),
    ("reward supply denominator mutation", _SUPPLY_WRITE_RE),
    ("reward checkpoint or debt mutation", _CHECKPOINT_WRITE_RE),
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
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, function_line=line))
        pos = end_pos
    return out


def _line_for_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.function_line + fn.body.count("\n", 0, match.start())


def _is_mutable_entrypoint(fn: FunctionSlice) -> bool:
    if not _VISIBILITY_RE.search(fn.header):
        return False
    if _PURE_VIEW_RE.search(fn.header):
        return False
    text = f"{fn.name}\n{fn.header}\n{fn.body[:1600]}"
    return bool(_ENTRY_CONTEXT_RE.search(fn.name) or _REWARD_CONTEXT_RE.search(text))


def _slot_from_match(match: re.Match[str]) -> str:
    groups = match.groupdict()
    for key in ("slot", "delete_slot", "push_slot"):
        value = groups.get(key)
        if value:
            return value
    return "reward accounting state"


def _first_mutation(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    candidates: list[tuple[str, re.Match[str]]] = []
    for label, pattern in _MUTATION_PATTERNS:
        for match in pattern.finditer(fn.body):
            candidates.append((label, match))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[1].start())


def _has_settlement_before(fn: FunctionSlice, pos: int) -> bool:
    prefix = f"{fn.header}\n{fn.body[:pos]}"
    return bool(_SETTLEMENT_CALL_RE.search(prefix))


def _has_late_pending_reward_use(fn: FunctionSlice, pos: int) -> bool:
    return bool(_PENDING_REWARD_USE_RE.search(fn.body[pos:]))


def _unsafe_delegate_drift(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _is_mutable_entrypoint(fn):
        return None

    candidate = _first_mutation(fn)
    if candidate is None:
        return None

    label, match = candidate
    if _has_settlement_before(fn, match.start()):
        return None
    if not _has_late_pending_reward_use(fn, match.end()):
        return None
    return label, match


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _REWARD_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _unsafe_delegate_drift(fn)
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
                    f"`{fn.name}` mutates {label} `{slot}` before any visible "
                    "reward settlement or checkpoint, then reads or credits "
                    "pending reward state later in the same function. Settle "
                    "pending rewards against the old delegate, recipient, "
                    "boost, checkpoint, or denominator before changing it."
                ),
            )
        )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "scan",
]
