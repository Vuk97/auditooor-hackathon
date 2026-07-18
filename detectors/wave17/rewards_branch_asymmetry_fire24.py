"""
rewards-branch-asymmetry-fire24

Solidity same-class recall detector for rewards-distribution-skew misses where
a success or failure branch pays, unlocks, or credits reward value while only
one branch records claimed, processed, paid, or settled state. It also catches
try/catch dispatch flows that mark dispatch failure but still credit the
relayer outside a success gate.

Confirmed sources:
- branch-asymmetric-idempotency-flag-toggled-in-only-one-arm
- bridge-relayer-reward-paid-on-failed-dispatch

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-branch-asymmetry-fire24"
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

_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|relayer\w*|dispatch\w*|refund\w*|bounty\w*|"
    r"claim\w*|settle\w*|release\w*|unlock\w*|payout\w*|"
    r"processed|claimed|settled|paid|finalized|delivered)\b",
    re.IGNORECASE,
)
_SUCCESS_WORD_RE = re.compile(
    r"\b(?:success|succeeded|delivered|dispatched|settled|executed|handled|valid)\b",
    re.IGNORECASE,
)
_FAILURE_WORD_RE = re.compile(
    r"\b(?:fail\w*|revert\w*|undelivered|unsuccessful|invalid|notDelivered)\b",
    re.IGNORECASE,
)
_NEGATED_SUCCESS_RE = re.compile(
    r"!\s*(?:success|succeeded|delivered|dispatched|settled|executed|handled|valid)\b|"
    r"\b(?:success|succeeded|delivered|dispatched|settled|executed|handled|valid)\b"
    r"\s*==\s*false\b|"
    r"\bfalse\s*==\s*(?:success|succeeded|delivered|dispatched|settled|executed|handled|valid)\b",
    re.IGNORECASE,
)

_IDEMPOTENCY_UPDATE_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:Claimed|Processed|Consumed|Redeemed|Paid|"
    r"Settled|Released|Finalized|Delivered|Dispatched|Checkpointed|Checkpoint)"
    r"\b\s*(?:\[[^\]]+\]\s*)*=\s*(?:true|1|block\.timestamp|currentEpoch|"
    r"currentRound|epoch|round|period|rewardIndex|accRewardPerShare|"
    r"rewardPerTokenStored)\b|"
    r"\b(?:claimed|processed|consumed|redeemed|paid|settled|released|"
    r"finalized|delivered|dispatched)\b\s*(?:\[[^\]]+\]\s*)*=\s*"
    r"(?:true|1|block\.timestamp|currentEpoch|currentRound|epoch|round|"
    r"period)\b|"
    r"\b_?(?:mark|set|toggle|checkpoint|settle|record|finalize)"
    r"[A-Za-z0-9_]*(?:Claim|Claimed|Processed|Reward|Rewards|Checkpoint|"
    r"Paid|Settled|Release|Released|Dispatched|Delivered|Finalized)"
    r"[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)
_REWARD_VALUE_EFFECT_RE = re.compile(
    r"\b(?:safeTransfer|safeTransferFrom|safeTransferETH|safeNativeTransfer|"
    r"sendValue|transfer|send|mint|_mint|claimReward|payReward|"
    r"creditReward|releaseReward|unlockReward|distributeReward|"
    r"_payReward)\s*\(|"
    r"\bpayable\s*\([^)]*(?:msg\.sender|relayer|user|recipient|receiver)[^)]*\)"
    r"\s*\.\s*(?:transfer|send)\s*\(|"
    r"\.\s*call\s*\{\s*value\s*:|"
    r"\b(?:relayerRewards?|relayerCredits?|rewardCredits?|gasRefunds?|"
    r"pendingRewards?|claimableRewards?|accruedRewards?|earnedRewards?|"
    r"unclaimedRewards?|rewardBalances?|releasedRewards?|distributedRewards?|"
    r"payouts?|bounties)\s*(?:\[[^\]]+\]\s*)+(?:=|\+=)\s*[^;]*(?:amount|"
    r"reward|refund|bounty|payout|share|claimable|bonus|msg\.value|gas)",
    re.IGNORECASE | re.DOTALL,
)
_SYMMETRIC_HINT_RE = re.compile(
    r"\b(?:markAllBranchesProcessed|checkpointBothBranches|"
    r"settleBothRewardBranches|commonRewardFinalize|_markProcessed|"
    r"_recordFailedDispatch|_recordSuccessfulDispatch)\s*\(",
    re.IGNORECASE,
)

_DISPATCH_FAILURE_RE = re.compile(
    r"\btry\b[\s\S]{0,3200}?\bcatch\b(?:\s*\([^)]*\))?\s*\{"
    r"[\s\S]{0,900}?\b(?P<flag>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*false\b",
    re.IGNORECASE,
)
_CATCH_REVERT_RE = re.compile(
    r"\bcatch\b(?:\s*\([^)]*\))?\s*\{[^{}]*(?:revert\s*\(|"
    r"require\s*\(\s*false\b)",
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


def _condition_is_success(condition: str) -> bool:
    return bool(_SUCCESS_WORD_RE.search(condition)) and not _condition_is_failure(condition)


def _condition_is_failure(condition: str) -> bool:
    return bool(_NEGATED_SUCCESS_RE.search(condition) or _FAILURE_WORD_RE.search(condition))


def _branch_failure_flags(pair: BranchPair) -> tuple[bool, bool]:
    if_failure = _condition_is_failure(pair.if_condition)
    else_failure = _condition_is_failure(pair.else_condition)
    if pair.else_condition == "else" and _condition_is_success(pair.if_condition):
        else_failure = True
    return if_failure, else_failure


def _has_success_failure_context(fn: FunctionSlice, pair: BranchPair) -> bool:
    text = "\n".join(
        (
            fn.name,
            pair.if_condition,
            pair.else_condition,
            pair.if_body[:600],
            pair.else_body[:600],
        )
    )
    return bool(_SUCCESS_WORD_RE.search(text) or _FAILURE_WORD_RE.search(text))


def _has_common_post_branch_marker(fn: FunctionSlice, pair: BranchPair) -> bool:
    return bool(_IDEMPOTENCY_UPDATE_RE.search(fn.body[pair.end:]))


def _branch_reward_asymmetry(fn: FunctionSlice) -> tuple[int, str] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return None
    if _SYMMETRIC_HINT_RE.search(fn.body):
        return None
    if not (_CONTEXT_RE.search(fn.name) or _CONTEXT_RE.search(fn.body)):
        return None

    for pair in _branch_pairs(fn.body):
        if not _has_success_failure_context(fn, pair):
            continue

        if_value = _REWARD_VALUE_EFFECT_RE.search(pair.if_body)
        else_value = _REWARD_VALUE_EFFECT_RE.search(pair.else_body)
        if_marker = _IDEMPOTENCY_UPDATE_RE.search(pair.if_body)
        else_marker = _IDEMPOTENCY_UPDATE_RE.search(pair.else_body)
        common_marker = _has_common_post_branch_marker(fn, pair)
        if_failure, else_failure = _branch_failure_flags(pair)

        if if_failure and if_value and if_marker is None and not common_marker:
            return (
                pair.if_start,
                "failure branch pays or unlocks reward value without marking the message processed",
            )

        if else_failure and else_value and else_marker is None and not common_marker:
            return (
                pair.else_start,
                "failure branch pays or unlocks reward value without marking the message processed",
            )

        if if_value and else_value and bool(if_marker) != bool(else_marker) and not common_marker:
            if if_marker is None:
                return (
                    pair.if_start,
                    "if branch moves reward value without the processed marker present in the sibling branch",
                )
            return (
                pair.else_start,
                "else branch moves reward value without the processed marker present in the sibling branch",
            )

    return None


def _extract_if_blocks(body: str, condition_re: re.Pattern[str]) -> list[tuple[int, int]]:
    blocks: list[tuple[int, int]] = []
    for match in condition_re.finditer(body):
        brace = body.find("{", match.end() - 1)
        if brace < 0:
            continue
        _block, end_pos = _extract_balanced_block(body, brace)
        if end_pos > brace:
            blocks.append((brace, end_pos))
    return blocks


def _inside_blocks(offset: int, blocks: list[tuple[int, int]]) -> bool:
    return any(start < offset < end for start, end in blocks)


def _requires_success_before(body: str, offset: int, flag_name: str) -> bool:
    prefix = body[:offset]
    escaped = re.escape(flag_name)
    guard_re = re.compile(
        rf"\brequire\s*\(\s*{escaped}\b|"
        rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*(?:\{{[^{{}}]*(?:revert|return)"
        rf"[^{{}}]*\}}|(?:revert|return)\b)",
        re.IGNORECASE | re.DOTALL,
    )
    return bool(guard_re.search(prefix))


def _failed_dispatch_relayer_reward(fn: FunctionSlice) -> tuple[int, str] | None:
    failure = _DISPATCH_FAILURE_RE.search(fn.body)
    if failure is None or _CATCH_REVERT_RE.search(fn.body):
        return None

    payout = _REWARD_VALUE_EFFECT_RE.search(fn.body, failure.end())
    if payout is None:
        return None

    flag_name = failure.group("flag")
    success_gate_re = re.compile(
        rf"\bif\s*\(\s*(?:{re.escape(flag_name)}|"
        rf"{re.escape(flag_name)}\s*==\s*true|true\s*==\s*{re.escape(flag_name)})"
        rf"\s*\)\s*\{{",
        re.IGNORECASE,
    )
    if _inside_blocks(payout.start(), _extract_if_blocks(fn.body, success_gate_re)):
        return None
    if _requires_success_before(fn.body, payout.start(), flag_name):
        return None

    return (
        payout.start(),
        "relayer reward or refund is credited after catch marks dispatch unsuccessful",
    )


def _first_reason(fn: FunctionSlice) -> tuple[int, str] | None:
    for check in (
        lambda: _branch_reward_asymmetry(fn),
        lambda: _failed_dispatch_relayer_reward(fn),
    ):
        result = check()
        if result is not None:
            return result
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _first_reason(fn)
        if result is None:
            continue
        offset, reason = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_offset(fn, offset),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` has reward branch asymmetry: {reason}. "
                    "Reward or relayer payouts must be gated on successful "
                    "dispatch or paired with the same claimed, processed, "
                    "paid, or settled state on every value-moving branch."
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
