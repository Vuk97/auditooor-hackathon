"""
rewards-distribution-skew-fire18

Solidity recall-lift detector for reward, validator, auction, and period
accounting paths where the distribution basis can be skewed by a stale
denominator, an immediate forced withdrawal, a wall-clock assumption, or a
state update that lands after value is paid out.

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-distribution-skew-fire18"
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
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_CONTEXT_RE = re.compile(
    r"\b(reward\w*|emission\w*|incentive\w*|validator\w*|stake\w*|"
    r"staked\w*|auction\w*|epoch\w*|period\w*|round\w*|heap\w*|"
    r"distribution\w*|withdrawal\w*|unstake\w*)\b",
    re.IGNORECASE,
)

_REQUEST_UNSTAKE_NAME_RE = re.compile(
    r"^(requestUnstake|requestWithdrawal|unstake|withdrawStake|withdraw)$",
    re.IGNORECASE,
)
_REQUESTED_WITHDRAWAL_WRITE_RE = re.compile(
    r"\b(requestedWithdrawalBalance|requestedUnstakeBalance|pendingWithdrawal|"
    r"queuedWithdrawal|withdrawalQueue)\b\s*(?:\[[^\]]+\]\s*)?(?:\+=|=)",
    re.IGNORECASE,
)
_EXIT_DENOMINATOR_MATH_RE = re.compile(
    r"\b(coveredExitBalance|requestedExits|exitsRequired|exitDeficit)\b|"
    r"\bPOOL_CAPACITY\b|32\s*ether",
    re.IGNORECASE,
)
_EXIT_REQUEST_CALL_RE = re.compile(
    r"\b(requestExits|exitValidators|forceValidatorWithdrawal|"
    r"requestValidatorExit|requestWithdrawal)\s*\(",
    re.IGNORECASE,
)
_AVAILABLE_OFFSET_WORD = (
    r"(?<!get)(availableWithdrawal\w*|withdrawableBalance\w*|availableBalance\w*)"
)
_AVAILABLE_OFFSET_RE = re.compile(
    _AVAILABLE_OFFSET_WORD
    +
    r".{0,220}"
    r"(coveredExitBalance|requestedExits|exitsRequired|exitDeficit|POOL_CAPACITY)|"
    r"(coveredExitBalance|requestedExits|exitsRequired|exitDeficit|POOL_CAPACITY)"
    r".{0,220}"
    + _AVAILABLE_OFFSET_WORD,
    re.IGNORECASE | re.DOTALL,
)

_BLOCK_TIME_RE = re.compile(
    r"block\.number\s*\*\s*(12|13|15)\b|"
    r"\(\s*block\.number\s*[-+]\s*[^)]+\)\s*\*\s*(12|13|15)\b|"
    r"\bblocksPerDay\s*=\s*\d+",
    re.IGNORECASE,
)
_REWARD_TIME_CONTEXT_RE = re.compile(
    r"\b(reward\w*|emission\w*|incentive\w*|accru\w*|vesting\w*|"
    r"unlock\w*|perSecond|period\w*|epoch\w*)\b",
    re.IGNORECASE,
)

_REWARD_PAYOUT_ENTRY_RE = re.compile(
    r"^(claim|claimReward|claimRewards|distribute|distributeRewards|payout|"
    r"release|settleReward|settleRewards)\w*$",
    re.IGNORECASE,
)
_REWARD_PAYOUT_RE = re.compile(
    r"\b(?:safeTransfer|transfer|sendValue|mint|_mint)\s*\([^;{}]*"
    r"\b(reward|rewards|pending|claimable|payout|share|amount)\w*\b",
    re.IGNORECASE | re.DOTALL,
)
_CLAIM_STATE_WRITE_RE = re.compile(
    r"\b(lastClaimedEpoch|lastClaimedPeriod|lastRewardEpoch|claimedEpoch|"
    r"claimedPeriod|paidEpoch|paidPeriod|rewardDebt|userRewardPerTokenPaid|"
    r"distributionCursor|nextDistribution|epochPaid|periodPaid)\b"
    r"\s*(?:\[[^\]]+\]\s*)*(?:=|\+=|\+\+)",
    re.IGNORECASE,
)
_CHECKPOINT_OR_SYNC_RE = re.compile(
    r"\b(_?checkpoint\w*|_?updateRewards?|_?settleRewards?|"
    r"_?advanceEpoch|_?advancePeriod|_?syncRewards?)\s*\(",
    re.IGNORECASE,
)

_FINALIZER_NAME_RE = re.compile(
    r"^(finalize|close|settle|end|resolve|rollover|advance|distribute)"
    r"\w*(Auction|Period|Epoch|Round|Rewards?|Emission)?\w*$",
    re.IGNORECASE,
)
_PERIOD_ADVANCE_RE = re.compile(
    r"\b(currentPeriod|rewardPeriod|period|periodIndex|auctionId|epoch|round)"
    r"\b\s*(\+\+|\+=\s*1|=\s*\1\s*\+\s*1)",
    re.IGNORECASE,
)
_PERIOD_ADVANCE_CALL_RE = re.compile(
    r"\b(_?advancePeriod|_?advanceEpoch|_?advanceRound|_?rollEpoch|"
    r"_?rollPeriod|_?startNextPeriod|_?startNextEpoch)\s*\(",
    re.IGNORECASE,
)
_IF_BLOCK_RE = re.compile(r"\bif\s*\((?P<cond>[^)]*)\)\s*\{(?P<body>.*?)\}", re.DOTALL)
_TERMINAL_RE = re.compile(r"\b(return\s*;|revert\b)", re.IGNORECASE)
_FAILURE_BRANCH_RE = re.compile(
    r"(FAILED|FAILURE|UNDERSOLD|NOT_FILLED|CANCELLED|EXPIRED|"
    r"!\s*success|success\s*==\s*false|bidCount\s*==\s*0|"
    r"bids?\.length\s*==\s*0|totalRaised\s*<\s*min|"
    r"amountRaised\s*<\s*min|raised\s*<\s*min|sold\s*==\s*0|"
    r"filled\s*==\s*0|winningBid\s*==\s*0|clearingPrice\s*==\s*0)",
    re.IGNORECASE,
)

def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            i += 1

        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, i)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for(fn: FunctionSlice, match: re.Match[str] | None) -> int:
    if match is None:
        return fn.body_line
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _has_period_advance(source: str) -> bool:
    return bool(_PERIOD_ADVANCE_RE.search(source) or _PERIOD_ADVANCE_CALL_RE.search(source))


def _forced_validator_withdrawal(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _REQUEST_UNSTAKE_NAME_RE.search(fn.name):
        return None
    requested = _REQUESTED_WITHDRAWAL_WRITE_RE.search(fn.body)
    if requested is None:
        return None
    if _EXIT_REQUEST_CALL_RE.search(fn.body) is None:
        return None
    if _EXIT_DENOMINATOR_MATH_RE.search(fn.body) is None:
        return None
    if _AVAILABLE_OFFSET_RE.search(fn.body):
        return None
    return (
        "requests validator exits from queued withdrawals without offsetting "
        "currently withdrawable balance",
        requested,
    )


def _block_number_reward_time(source: str, fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _REWARD_TIME_CONTEXT_RE.search(source):
        return None
    if "block.timestamp" in fn.body:
        return None
    match = _BLOCK_TIME_RE.search(fn.body)
    if match is None:
        return None
    return (
        "converts block.number into reward or emission time using a fixed "
        "seconds-per-block denominator",
        match,
    )


def _payout_before_claim_state(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _REWARD_PAYOUT_ENTRY_RE.search(fn.name):
        return None
    payout = _REWARD_PAYOUT_RE.search(fn.body)
    if payout is None:
        return None
    state_write = _CLAIM_STATE_WRITE_RE.search(fn.body)
    if state_write is None:
        return None
    if state_write.start() < payout.start():
        return None
    checkpoint = _CHECKPOINT_OR_SYNC_RE.search(fn.body)
    if checkpoint is not None and checkpoint.start() < payout.start():
        return None
    return (
        "pays reward value before claim or distribution state is advanced",
        payout,
    )


def _terminal_failure_without_period_advance(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _FINALIZER_NAME_RE.search(fn.name):
        return None
    if not _has_period_advance(fn.body):
        return None
    for match in _IF_BLOCK_RE.finditer(fn.body):
        branch_text = f"{match.group('cond')}\n{match.group('body')}"
        if not _FAILURE_BRANCH_RE.search(branch_text):
            continue
        body = match.group("body")
        if not _TERMINAL_RE.search(body):
            continue
        if _has_period_advance(body):
            continue
        return (
            "terminal failure branch exits before period or epoch state advances",
            match,
        )
    return None


def _first_reason(source: str, fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    for check in (
        lambda: _forced_validator_withdrawal(fn),
        lambda: _block_number_reward_time(source, fn),
        lambda: _payout_before_claim_state(fn),
        lambda: _terminal_failure_without_period_advance(fn),
    ):
        result = check()
        if result is not None:
            return result
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments_and_strings(source)
    if not _CONTEXT_RE.search(clean_source):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean_source):
        if not _PUBLIC_HEADER_RE.search(fn.header):
            continue
        reason = _first_reason(clean_source, fn)
        if reason is None:
            continue
        message, anchor = reason
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` {message}. Reward distribution must use "
                    "checkpointed denominators and advance claim or period "
                    "state before allocation."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
