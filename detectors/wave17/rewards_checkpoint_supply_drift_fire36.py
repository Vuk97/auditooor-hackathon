"""
rewards-checkpoint-supply-drift-fire36

Fire36 Solidity lift for rewards-distribution-skew variants where a reward
epoch, checkpoint, reward-per-token, or delegate reward accrual path divides
by live supply or a mutable delegate set instead of the committed denominator
for the reward epoch.

Source refs:
- reports/detector_lift_fire35_20260605/post_priorities_all.md
- reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml
- reference/patterns.dsl/can-reward-dist-precomputed-totalsupply.yaml
- detectors/wave17/rewards_delegate_drift_fire35.py
- detectors/wave17/rewards_live_supply_drift_fire34.py
- detectors/rust_wave1/reward_index_or_supply_checkpoint_drift_fire20.py

Candidate evidence only. A hit is NOT_SUBMIT_READY and must not be cited as
proof without source existence, a real in-scope entrypoint, negative control,
and R40/R76/R80 evidence honesty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-checkpoint-supply-drift-fire36"
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
    body_line: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_REWARD_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|rewards\w*|emission\w*|incentive\w*|"
    r"earned\w*|claimable\w*|pending\w*|accrued\w*|"
    r"rewardPer\w*|accReward\w*|rewardIndex\w*|rewardDebt\w*|"
    r"checkpoint\w*|delegate\w*|delegation\w*)\b",
    re.IGNORECASE,
)
_EPOCH_CONTEXT_RE = re.compile(
    r"\b(?:epoch\w*|period\w*|round\w*|cycle\w*|week\w*|"
    r"rewardEpoch\w*|currentEpoch\w*|epochReward\w*|"
    r"tokenRewardsPerEpoch|rewardsPerEpoch|rewardForEpoch)\b",
    re.IGNORECASE,
)
_ACCRUAL_FN_RE = re.compile(
    r"^(?:rewardPerToken|rewardPerShare|rewardPerVote|earned|claimable|"
    r"pendingReward|calculateReward|getReward|checkpoint|checkpointAccount|"
    r"checkpointRewards|accrue|accrueRewards|settle|settleRewards|"
    r"updateReward|updateRewards|distribute|distributeRewards|"
    r"notifyRewardAmount|allocateRewards|delegateRewardShare|"
    r"delegateRewards|rewardForEpoch)",
    re.IGNORECASE,
)

_SAFE_DENOMINATOR_HINT_RE = re.compile(
    r"(?:snapshot|checkpoint|committed|frozen|fixed|eligible|qualified|"
    r"distribution|epoch|period|round|week|past|prior|atBlock|atEpoch|"
    r"supplyAt|sharesAt|stakeAt|weightAt|balanceOfAt|totalSupplyAt|"
    r"getPastVotes|getPriorVotes|getPastTotalSupply|denominatorByEpoch|"
    r"epochDenominator|epochSupply|rewardEpochSupply|supplySnapshot|"
    r"checkpointSupply)",
    re.IGNORECASE,
)
_SAFE_GUARD_RE = re.compile(
    r"\b(?:require|if)\s*\([^;{}]{0,220}"
    r"(?:epochSupply|rewardEpochSupply|committedSupply|"
    r"checkpointSupply|distributionSupply|eligibleSupply|"
    r"supplySnapshot|denominatorByEpoch)[^;{}]{0,220}"
    r"(?:!=|>|>=)\s*0",
    re.IGNORECASE | re.DOTALL,
)

_LIVE_SUPPLY_DENOMINATOR_RE = re.compile(
    r"/\s*(?P<denom>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:totalSupply|totalStaked|totalStake|totalShares|totalDeposits|"
    r"totalWeight|stakeWeight|shareSupply|totalVotingPower|"
    r"votingPower|votePower|totalDelegatedPower|totalDelegatedVotes)"
    r"\s*(?:\(\s*\))?|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"balanceOf\s*\([^;{}]{0,180}\)|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:getVotes|getCurrentVotes|getVotingPower|currentVotes|"
    r"votingPowerOf|balanceOfVotes)\s*\([^;{}]{0,180}\)"
    r")(?=\s*(?:[;)+\-*/]|$))",
    re.IGNORECASE | re.DOTALL,
)
_LIVE_SUPPLY_ASSIGN_RE = re.compile(
    r"\b(?:uint(?:256|128|96|64)?|int(?:256|128|96|64)?)\s+"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<source>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:totalSupply|totalStaked|totalStake|totalShares|totalDeposits|"
    r"totalWeight|stakeWeight|shareSupply|totalVotingPower|"
    r"votingPower|votePower|totalDelegatedPower|totalDelegatedVotes)"
    r"\s*(?:\(\s*\))?|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"balanceOf\s*\([^;{}]{0,180}\)|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:getVotes|getCurrentVotes|getVotingPower|currentVotes|"
    r"votingPowerOf|balanceOfVotes)\s*\([^;{}]{0,180}\)"
    r")\s*;",
    re.IGNORECASE | re.DOTALL,
)

_MUTABLE_DELEGATE_DENOMINATOR_RE = re.compile(
    r"/\s*(?P<denom>"
    r"(?:rewardDelegates?|delegates?|delegatees?|delegationSet|"
    r"delegateSet|activeDelegates|rewardRecipients?|recipientSet)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*\.\s*length|"
    r"(?:delegateCount|delegatesCount|activeDelegateCount|"
    r"recipientCount|rewardRecipientCount)\s*(?:\(\s*[^;{}]{0,160}\))?"
    r")(?=\s*(?:[;)+\-*/]|$))",
    re.IGNORECASE | re.DOTALL,
)
_MUTABLE_DELEGATE_ASSIGN_RE = re.compile(
    r"\b(?:uint(?:256|128|96|64)?|int(?:256|128|96|64)?)\s+"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<source>"
    r"(?:rewardDelegates?|delegates?|delegatees?|delegationSet|"
    r"delegateSet|activeDelegates|rewardRecipients?|recipientSet)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*\.\s*length|"
    r"(?:delegateCount|delegatesCount|activeDelegateCount|"
    r"recipientCount|rewardRecipientCount)\s*(?:\(\s*[^;{}]{0,160}\))?"
    r")\s*;",
    re.IGNORECASE | re.DOTALL,
)

_ACCRUAL_STATEMENT_RE = re.compile(
    r"(?P<stmt>"
    r"(?:return\b|"
    r"\b(?:uint(?:256|128|96|64)?|int(?:256|128|96|64)?)\s+"
    r"[A-Za-z_][A-Za-z0-9_]*\s*=|"
    r"\b(?:rewardPerTokenStored|rewardPerToken|rewardPerShare|"
    r"accRewardPerShare|accPerShare|rewardIndex|globalRewardIndex|"
    r"globalIndex|rewardAccumulator|rewardsPerShare|rewardPerVote|"
    r"voteRewardIndex|emissionIndex|incentiveIndex|claimableRewards?|"
    r"pendingRewards?|accruedRewards?|earnedRewards?|userRewards?|"
    r"rewardDebt|rewardDebts)\b"
    r"(?:\s*\[[^\]]+\]\s*){0,3}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|=))"
    r"[^;]{0,1400}/[^;]{0,700};"
    r")",
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


def _is_externally_reachable(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_OR_EXTERNAL_RE.search(fn.header))


def _has_epoch_reward_context(fn: FunctionSlice) -> bool:
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    return bool(_REWARD_CONTEXT_RE.search(text) and _EPOCH_CONTEXT_RE.search(text))


def _safe_denominator_source(text: str) -> bool:
    return bool(_SAFE_DENOMINATOR_HINT_RE.search(text))


def _local_denominator_vars(fn: FunctionSlice) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for pattern, label in (
        (_LIVE_SUPPLY_ASSIGN_RE, "live supply denominator"),
        (_MUTABLE_DELEGATE_ASSIGN_RE, "mutable delegate-set denominator"),
    ):
        for match in pattern.finditer(fn.body):
            var_name = match.group("var")
            source = re.sub(r"\s+", " ", match.group("source")).strip()
            if _safe_denominator_source(var_name) or _safe_denominator_source(source):
                continue
            out[var_name] = (label, source)
    return out


def _direct_denominator(statement: str) -> tuple[str, str] | None:
    for pattern, label in (
        (_LIVE_SUPPLY_DENOMINATOR_RE, "live supply denominator"),
        (_MUTABLE_DELEGATE_DENOMINATOR_RE, "mutable delegate-set denominator"),
    ):
        match = pattern.search(statement)
        if match is None:
            continue
        denominator = re.sub(r"\s+", " ", match.group("denom")).strip()
        if _safe_denominator_source(denominator):
            continue
        return label, denominator
    return None


def _local_var_denominator(
    statement: str,
    locals_by_name: dict[str, tuple[str, str]],
) -> tuple[str, str] | None:
    for var_name, (label, source) in locals_by_name.items():
        var_denominator_re = re.compile(r"/\s*" + re.escape(var_name) + r"\b")
        if var_denominator_re.search(statement):
            return label, source
    return None


def _unsafe_checkpoint_supply_drift(fn: FunctionSlice) -> tuple[re.Match[str], str, str] | None:
    if not _is_externally_reachable(fn):
        return None
    if not (_ACCRUAL_FN_RE.search(fn.name) or _REWARD_CONTEXT_RE.search(fn.body)):
        return None
    if not _has_epoch_reward_context(fn):
        return None
    if _SAFE_GUARD_RE.search(fn.body) and not re.search(
        r"/\s*(?:totalSupply|totalStaked|totalStake|totalShares|"
        r"totalWeight|balanceOf|getVotes|delegateCount|"
        r"delegates?[^;]{0,160}\.length)",
        fn.body,
        re.IGNORECASE | re.DOTALL,
    ):
        return None

    locals_by_name = _local_denominator_vars(fn)
    for match in _ACCRUAL_STATEMENT_RE.finditer(fn.body):
        statement = match.group("stmt")

        result = _direct_denominator(statement)
        if result is None:
            result = _local_var_denominator(statement, locals_by_name)
        if result is None:
            continue

        label, denominator = result
        return match, label, denominator
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not (_REWARD_CONTEXT_RE.search(clean) and _EPOCH_CONTEXT_RE.search(clean)):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _unsafe_checkpoint_supply_drift(fn)
        if result is None:
            continue

        match, label, denominator = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_match(fn, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` accrues reward epoch accounting with "
                    f"{label} `{denominator}` instead of a committed, "
                    "checkpointed, or epoch-bound denominator. Bind reward "
                    "per token, checkpoint, and delegate reward math to the "
                    "denominator committed for the reward epoch."
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
