"""
rewards-live-supply-drift-fire34

Solidity same-class recall detector for rewards-distribution-skew cases where
public reward distribution math divides by a live stake, share, totalSupply,
balanceOf, or voting-power denominator after users can change the denominator,
and no eligibility snapshot, supply checkpoint, cooldown, or past-vote lookup
is visible in the same distribution path.

Source refs:
- reports/detector_lift_fire33_20260605/post_priorities_all.md
- reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml
- detectors/rust_wave1/reward_index_or_supply_checkpoint_drift_fire20.py

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-live-supply-drift-fire34"
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
_PURE_VIEW_RE = re.compile(r"\b(?:pure|view)\b", re.IGNORECASE)
_REWARD_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|rewards\w*|yield\w*|emission\w*|incentive\w*|"
    r"distribut\w*|accReward\w*|rewardPer\w*|rewardIndex\w*|"
    r"globalIndex\w*|checkpoint\w*|claimable\w*|pendingReward\w*)\b",
    re.IGNORECASE,
)
_DISTRIBUTION_NAME_RE = re.compile(
    r"^(?:distribute|distributeRewards|notifyRewardAmount|"
    r"immediateDistribution|instantDistribution|oneTimeDistribution|"
    r"startDistribution|fundRewards|addRewards|queueRewards|allocateRewards|"
    r"checkpointRewards|updateRewardIndex|accrueRewards|syncRewards|"
    r"fundIncentives|allocateIncentives)$",
    re.IGNORECASE,
)
_DISTRIBUTION_BODY_RE = re.compile(
    r"\b(?:reward\w*|rewards\w*|yield\w*|emission\w*|amount|tokens|"
    r"index|perShare|rewardPerToken|rewardPerShare|accRewardPerShare|"
    r"globalRewardIndex|rewardIndex|accumulator)\b",
    re.IGNORECASE,
)

_MUTABLE_ENTRY_NAME_RE = re.compile(
    r"^(?:deposit|stake|mint|join|enter|addLiquidity|increaseStake|"
    r"increaseShares|delegate|delegateTo|transfer|transferFrom|"
    r"safeTransferFrom|moveVotingPower|moveVotes|redelegate|lock|"
    r"extendLock|withdraw|unstake|redeem|burn)$",
    re.IGNORECASE,
)
_MUTABLE_SUPPLY_BODY_RE = re.compile(
    r"\b(?:totalStaked|totalStake|totalShares|shareSupply|totalDeposits|"
    r"totalWeight|stakeWeight|totalVotingPower|votingPower|votePower|"
    r"delegatedVotes|delegateVotes|votingUnits|_?totalSupply|"
    r"balances|balanceOf|stakedBalance|stakeOf|stakes|shares|userShares|"
    r"weights)\b\s*(?:\[[^\]]+\]\s*)*(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:\+=|-=|=|\+\+|--)|"
    r"\b(?:_?mint|_?burn|_?stake|_?unstake|_?deposit|_?withdraw|"
    r"_?delegate|_?moveVotingPower|_?moveVotes)\s*\(|"
    r"\b(?:safeTransferFrom|transferFrom)\s*\(",
    re.IGNORECASE | re.DOTALL,
)

_SAFE_DENOMINATOR_RE = re.compile(
    r"\b(?:snapshotSupply|supplySnapshot|snapshotTotal|totalSupplySnapshot|"
    r"distributionSnapshot|checkpointSupply|checkpointedSupply|"
    r"eligibleSupply|qualifiedSupply|distributionSupply|supplyAt|"
    r"sharesAt|stakeAt|weightAt|votePowerAt|votingPowerAt|"
    r"balanceOfAt|totalSupplyAt|getPastVotes|getPriorVotes|"
    r"getPastTotalSupply|pastTotalSupply|cooldown|lastStake|lastDeposit|"
    r"lockUntil|distributionUnlock|timeWeighted|twap|epochStart|"
    r"periodStart|_snapshot|snapshot\s*\(|_?checkpointSupply\s*\(|"
    r"_?checkpointDistribution\s*\(|_?checkpointEligibility\s*\()\b",
    re.IGNORECASE,
)
_SAFE_DENOMINATOR_NAME_RE = re.compile(
    r"(?:snapshot|eligible|qualified|distribution|checkpoint|atEpoch|"
    r"atBlock|past|cooldown|timeWeighted|twap)",
    re.IGNORECASE,
)

_ACCUMULATOR_SLOT = (
    r"(?:rewardPerTokenStored|rewardPerToken|rewardPerShare|"
    r"accRewardPerShare|accPerShare|rewardIndex|globalRewardIndex|"
    r"globalIndex|rewardAccumulator|rewardsPerShare|rewardPerVote|"
    r"voteRewardIndex|emissionIndex|incentiveIndex)"
)
_ACCUMULATOR_ASSIGN_RE = re.compile(
    rf"\b(?P<slot>{_ACCUMULATOR_SLOT})\b\s*(?:\[[^\]]+\]\s*)?"
    rf"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|=)\s*"
    rf"(?P<expr>[^;]{{0,900}});",
    re.IGNORECASE | re.DOTALL,
)

_DIRECT_LIVE_DENOMINATOR_RE = re.compile(
    r"/\s*(?P<denom>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:totalSupply|totalStaked|totalStake|totalShares|totalDeposits|"
    r"totalWeight|stakeWeight|shareSupply|totalVotingPower|"
    r"votingPower|votePower)\s*(?:\(\s*\))?|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"balanceOf\s*\([^;{}]{0,180}\)|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:getVotes|getCurrentVotes|getVotingPower|currentVotes|"
    r"votingPowerOf|balanceOfVotes)\s*\([^;{}]{0,180}\)"
    r")(?=\s*(?:[;)+\-*/]|$))",
    re.IGNORECASE | re.DOTALL,
)
_LIVE_DENOMINATOR_ASSIGN_RE = re.compile(
    r"\b(?:uint(?:256|128|96|64)?|int(?:256|128|96|64)?)\s+"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<source>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:totalSupply|totalStaked|totalStake|totalShares|totalDeposits|"
    r"totalWeight|stakeWeight|shareSupply|totalVotingPower|"
    r"votingPower|votePower)\s*(?:\(\s*\))?|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"balanceOf\s*\([^;{}]{0,180}\)|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?"
    r"(?:getVotes|getCurrentVotes|getVotingPower|currentVotes|"
    r"votingPowerOf|balanceOfVotes)\s*\([^;{}]{0,180}\)"
    r")\s*;",
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


def _is_callable_mutable(fn: FunctionSlice) -> bool:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return False
    if _PURE_VIEW_RE.search(fn.header):
        return False
    return True


def _has_user_controlled_denominator_change(functions: list[FunctionSlice]) -> bool:
    for fn in functions:
        if not _is_callable_mutable(fn):
            continue
        if not _MUTABLE_ENTRY_NAME_RE.search(fn.name):
            continue
        if _MUTABLE_SUPPLY_BODY_RE.search(fn.body):
            return True
    return False


def _safe_denominator_handling(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    return bool(_SAFE_DENOMINATOR_RE.search(text))


def _local_live_denominator_vars(fn: FunctionSlice) -> dict[str, re.Match[str]]:
    out: dict[str, re.Match[str]] = {}
    for match in _LIVE_DENOMINATOR_ASSIGN_RE.finditer(fn.body):
        var_name = match.group("var")
        if _SAFE_DENOMINATOR_NAME_RE.search(var_name):
            continue
        out[var_name] = match
    return out


def _formula_uses_live_denominator(
    fn: FunctionSlice,
    locals_by_name: dict[str, re.Match[str]],
) -> tuple[re.Match[str], str] | None:
    for assignment in _ACCUMULATOR_ASSIGN_RE.finditer(fn.body):
        expr = assignment.group("expr")
        direct = _DIRECT_LIVE_DENOMINATOR_RE.search(expr)
        if direct is not None:
            denominator = re.sub(r"\s+", " ", direct.group("denom")).strip()
            return assignment, denominator

        for var_name, source_match in locals_by_name.items():
            var_denominator_re = re.compile(r"/\s*" + re.escape(var_name) + r"\b")
            if var_denominator_re.search(expr):
                denominator = re.sub(r"\s+", " ", source_match.group("source")).strip()
                return assignment, denominator
    return None


def _live_supply_distribution_hit(fn: FunctionSlice) -> tuple[re.Match[str], str] | None:
    if not _is_callable_mutable(fn):
        return None
    if not _DISTRIBUTION_NAME_RE.search(fn.name):
        return None
    full_text = f"{fn.header}\n{fn.body}"
    if not _DISTRIBUTION_BODY_RE.search(full_text):
        return None
    if _safe_denominator_handling(fn):
        return None

    locals_by_name = _local_live_denominator_vars(fn)
    return _formula_uses_live_denominator(fn, locals_by_name)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _REWARD_CONTEXT_RE.search(clean):
        return []

    functions = _split_functions(clean)
    if not _has_user_controlled_denominator_change(functions):
        return []

    findings: list[Finding] = []
    for fn in functions:
        result = _live_supply_distribution_hit(fn)
        if result is None:
            continue
        match, denominator = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_match(fn, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` updates reward-per-share math using live "
                    f"denominator `{denominator}` while users can change "
                    "stake, shares, supply, or voting power elsewhere in the "
                    "contract. Bind distribution math to a checkpointed "
                    "eligible denominator, cooldown, or past-vote snapshot "
                    "before funding rewards."
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
