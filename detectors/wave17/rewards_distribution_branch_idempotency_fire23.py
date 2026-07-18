"""
rewards-distribution-branch-idempotency-fire23

Solidity same-class recall detector for a rewards-distribution-skew subshape:
one reward claim or settlement branch updates a claimed, processed, paid, or
checkpoint marker while a sibling branch still pays, accrues, or releases
reward value without the same idempotency update.

Confirmed source: branch-asymmetric-idempotency-flag-toggled-in-only-one-arm
from reference/patterns.dsl/branch-asymmetric-idempotency-flag-toggled-in-only-one-arm.yaml.

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-distribution-branch-idempotency-fire23"
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


@dataclass
class BranchPair:
    if_condition: str
    if_body: str
    if_start: int
    else_condition: str
    else_body: str
    else_start: int
    end: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_REWARD_CONTEXT_RE = re.compile(
    r"\b(?:claim\w*|harvest\w*|collect\w*|settle\w*|release\w*|"
    r"distribute\w*|reward\w*|pending\w*|claimable\w*|accrued\w*|"
    r"earned\w*|unclaimed\w*|payout\w*|bonus\w*|epoch|round)\b",
    re.IGNORECASE,
)

_IDEMPOTENCY_LHS = (
    r"(?=[A-Za-z_])"
    r"(?=[A-Za-z0-9_]*(?:claimed|processed|consumed|redeemed|"
    r"paid|settled|released|checkpointed|checkpoint|finalized|distributed))"
    r"[A-Za-z_][A-Za-z0-9_]*"
)
_IDEMPOTENCY_UPDATE_RE = re.compile(
    rf"\b{_IDEMPOTENCY_LHS}\b\s*(?:\[[^\]]+\]\s*)*=\s*"
    r"(?:true|1|block\.timestamp|currentEpoch|currentRound|epoch|round|"
    r"period|rewardIndex|accRewardPerShare|rewardPerTokenStored)\b|"
    r"\b_?(?:mark|set|toggle|checkpoint|settle|record)"
    r"[A-Za-z0-9_]*(?:Claim|Claimed|Processed|Reward|Rewards|Checkpoint|"
    r"Paid|Settled|Release|Released|Distributed)[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)
_REWARD_VALUE_EFFECT_RE = re.compile(
    r"\b(?:safeTransfer|safeTransferFrom|safeTransferETH|sendValue|"
    r"transfer|mint|_mint|claimReward|payReward|creditReward|"
    r"releaseReward|distributeReward|_payReward)\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\b(?:pendingRewards?|claimableRewards?|accruedRewards?|earnedRewards?|"
    r"unclaimedRewards?|rewardBalances?|rewards?|rewardEscrow|"
    r"releasedRewards?|distributedRewards?|payouts?)\s*"
    r"(?:\[[^\]]+\]\s*)+(?:=|\+=)\s*[^;]*(?:amount|reward|payout|share|"
    r"claimable|bonus|msg\.value)",
    re.IGNORECASE | re.DOTALL,
)
_SYMMETRIC_HINT_RE = re.compile(
    r"\b(?:markAllBranchesProcessed|checkpointBothBranches|"
    r"settleBothRewardBranches|commonRewardFinalize)\s*\(",
    re.IGNORECASE,
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
    return source[open_brace + 1:close_brace], close_brace + 1


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

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _skip_ws(source: str, pos: int) -> int:
    while pos < len(source) and source[pos].isspace():
        pos += 1
    return pos


def _read_condition(source: str, pos: int) -> tuple[Optional[str], int]:
    pos = _skip_ws(source, pos)
    if pos >= len(source) or source[pos] != "(":
        return None, pos
    close = _find_matching_delimiter(source, pos, "(", ")")
    if close < 0:
        return None, pos
    return source[pos + 1:close], close + 1


def _branch_pairs(body: str) -> list[BranchPair]:
    pairs: list[BranchPair] = []
    pos = 0
    while True:
        if_match = re.search(r"\bif\s*\(", body[pos:])
        if if_match is None:
            break
        if_start = pos + if_match.start()
        cond_start = body.find("(", if_start)
        if_condition, after_condition = _read_condition(body, cond_start)
        if if_condition is None:
            pos = if_start + 2
            continue

        if_block_start = _skip_ws(body, after_condition)
        if if_block_start >= len(body) or body[if_block_start] != "{":
            pos = if_start + 2
            continue
        if_body, after_if = _extract_balanced_block(body, if_block_start)
        if if_body is None:
            pos = if_start + 2
            continue

        else_pos = _skip_ws(body, after_if)
        if not body.startswith("else", else_pos):
            pos = after_if
            continue

        else_condition = "else"
        after_else = _skip_ws(body, else_pos + len("else"))
        if body.startswith("if", after_else) and (
            after_else + 2 == len(body) or not body[after_else + 2].isalnum()
        ):
            else_condition, after_else = _read_condition(body, after_else + 2)
            if else_condition is None:
                pos = after_if
                continue

        else_block_start = _skip_ws(body, after_else)
        if else_block_start >= len(body) or body[else_block_start] != "{":
            pos = after_if
            continue
        else_body, after_else_block = _extract_balanced_block(body, else_block_start)
        if else_body is None:
            pos = after_if
            continue

        pairs.append(
            BranchPair(
                if_condition=if_condition,
                if_body=if_body,
                if_start=if_start,
                else_condition=else_condition,
                else_body=else_body,
                else_start=else_pos,
                end=after_else_block,
            )
        )
        pos = after_if
    return pairs


def _line_for_offset(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, offset))


def _has_common_post_branch_marker(fn: FunctionSlice, pair: BranchPair) -> bool:
    tail = fn.body[pair.end:]
    return bool(_IDEMPOTENCY_UPDATE_RE.search(tail))


def _branch_idempotency_skew(fn: FunctionSlice) -> tuple[int, str] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return None
    if _SYMMETRIC_HINT_RE.search(fn.body):
        return None
    if not (_REWARD_CONTEXT_RE.search(fn.name) or _REWARD_CONTEXT_RE.search(fn.body)):
        return None

    for pair in _branch_pairs(fn.body):
        if_context = f"{pair.if_condition}\n{pair.if_body}"
        else_context = f"{pair.else_condition}\n{pair.else_body}"
        if not (_REWARD_CONTEXT_RE.search(if_context) or _REWARD_CONTEXT_RE.search(else_context)):
            continue

        if_value = _REWARD_VALUE_EFFECT_RE.search(pair.if_body)
        else_value = _REWARD_VALUE_EFFECT_RE.search(pair.else_body)
        if if_value is None or else_value is None:
            continue

        if_marker = _IDEMPOTENCY_UPDATE_RE.search(pair.if_body)
        else_marker = _IDEMPOTENCY_UPDATE_RE.search(pair.else_body)
        if bool(if_marker) == bool(else_marker):
            continue
        if _has_common_post_branch_marker(fn, pair):
            continue

        if if_marker is None:
            return (
                pair.if_start,
                "if branch pays, accrues, or releases reward value without "
                "the idempotency update present in the sibling branch",
            )
        return (
            pair.else_start,
            "else branch pays, accrues, or releases reward value without "
            "the idempotency update present in the sibling branch",
        )

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _branch_idempotency_skew(fn)
        if result is None:
            continue
        offset, reason = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_offset(fn, offset),
                severity=DETECTOR_SEVERITY_DEFAULT,
                message=(
                    f"`{fn.name}` has reward branch idempotency skew: {reason}. "
                    "Reward claim and settlement branches that move value must "
                    "mark the same claimed, processed, paid, or checkpoint state."
                ),
                function=fn.name,
            )
        )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "scan",
]
