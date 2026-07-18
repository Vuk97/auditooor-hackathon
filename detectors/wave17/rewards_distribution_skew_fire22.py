"""
rewards-distribution-skew-fire22

Solidity same-class recall detector for a distinct rewards-distribution-skew
subshape: pending reward state is consumed before an unchecked or swallowed
reward payout failure. This catches claim/harvest flows that zero or delete
claimable reward state, then ignore an ERC20 transfer result, ignore a
low-level call success flag, or swallow a failed try/catch payout.

This is intentionally separate from Fire21's branch-asymmetric idempotency,
failed-dispatch relayer payout, and stale totalSupply denominator shapes.
Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-distribution-skew-fire22"
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

_CLAIM_CONTEXT_RE = re.compile(
    r"\b(?:claim\w*|harvest\w*|collect\w*|getReward\w*|withdrawReward\w*|"
    r"settleReward\w*|reward\w*|pending\w*|claimable\w*|accrued\w*|"
    r"earned\w*|unclaimed\w*)\b",
    re.IGNORECASE,
)
_CLAIM_NAME_RE = re.compile(
    r"(?:claim|harvest|collect|getReward|withdrawReward|settleReward)",
    re.IGNORECASE,
)
_PENDING_SLOT = (
    r"(?:pendingRewards?|claimableRewards?|accruedRewards?|earnedRewards?|"
    r"unclaimedRewards?|rewardBalance|rewardBalances|rewards)"
)
_PENDING_CONSUME_RE = re.compile(
    rf"\bdelete\s+(?P<slot>{_PENDING_SLOT})\s*(?:\[[^\]]+\]\s*)+|"
    rf"\b(?P<slot2>{_PENDING_SLOT})\s*(?:\[[^\]]+\]\s*)+\s*=\s*0\s*;|"
    r"\b(?P<slot3>userRewardPerTokenPaid|rewardCheckpoint|lastClaimedRewardIndex)"
    r"\s*(?:\[[^\]]+\]\s*)+\s*=",
    re.IGNORECASE,
)
_SAFE_TRANSFER_RE = re.compile(
    r"\b(?:safeTransfer|safeTransferFrom|SafeERC20|_safeTransferReward)\b",
    re.IGNORECASE,
)
_TRY_PAYOUT_RE = re.compile(
    r"\btry\s+[^{};]*(?:\.transfer|\.call)\s*\([^;{}]*\)\s*"
    r"\{(?P<try_body>[^{}]*)\}\s*catch(?:\s*\([^)]*\))?\s*"
    r"\{(?P<catch_body>[^{}]*)\}",
    re.IGNORECASE | re.DOTALL,
)
_CATCH_REVERT_RE = re.compile(
    r"\bcatch(?:\s*\([^)]*\))?\s*\{[^{}]*(?:revert\s*\(|require\s*\(\s*false\b)",
    re.IGNORECASE | re.DOTALL,
)
_LOW_LEVEL_CALL_RE = re.compile(
    r"\(\s*bool\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*\)\s*=\s*"
    r"[^;{}]*\.\s*call\s*(?:\{[^}]*\})?\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_RAW_TRANSFER_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r"\.transfer\s*\([^;{}]*\)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_REQUIRE_TRANSFER_RE = re.compile(
    r"\brequire\s*\([^;{}]*(?:\.transfer\s*\(|\.send\s*\(|\.call\s*(?:\{|"
    r"\())",
    re.IGNORECASE | re.DOTALL,
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


def _has_success_guard(var_name: str, tail: str) -> bool:
    escaped = re.escape(var_name)
    guard_re = re.compile(
        rf"\brequire\s*\(\s*{escaped}\b|"
        rf"\bif\s*\(\s*!\s*{escaped}\s*\)\s*(?:\{{[^{{}}]*(?:revert|return)"
        rf"[^{{}}]*\}}|(?:revert|return)\b)",
        re.IGNORECASE | re.DOTALL,
    )
    return bool(guard_re.search(tail))


def _pending_reward_consumed_before_unchecked_payout(
    fn: FunctionSlice,
) -> tuple[re.Match[str], str] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return None
    if not (_CLAIM_NAME_RE.search(fn.name) or _CLAIM_CONTEXT_RE.search(fn.body)):
        return None

    consume = _PENDING_CONSUME_RE.search(fn.body)
    if consume is None:
        return None

    tail = fn.body[consume.end():]
    if not _CLAIM_CONTEXT_RE.search(tail):
        return None
    if _SAFE_TRANSFER_RE.search(tail):
        return None

    try_payout = _TRY_PAYOUT_RE.search(tail)
    if try_payout is not None:
        catch_body = try_payout.group("catch_body")
        if re.search(r"\b(?:revert\s*\(|require\s*\(\s*false\b)", catch_body, re.IGNORECASE):
            return None
        return (
            consume,
            "consumes pending reward state before confirming the reward payout; "
            "failed try/catch payout is swallowed",
        )

    low_level = _LOW_LEVEL_CALL_RE.search(tail)
    if low_level is not None:
        after_call = tail[low_level.end():]
        if _has_success_guard(low_level.group("var"), after_call):
            return None
        return (
            consume,
            "consumes pending reward state before confirming the reward payout; "
            "low-level call success flag is not enforced",
        )

    raw_transfer = _RAW_TRANSFER_RE.search(tail)
    if raw_transfer is not None:
        if _REQUIRE_TRANSFER_RE.search(tail) or _CATCH_REVERT_RE.search(tail):
            return None
        return (
            consume,
            "consumes pending reward state before confirming the reward payout; "
            "ERC20 transfer return value is ignored",
        )

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(clean):
        match_and_reason = _pending_reward_consumed_before_unchecked_payout(fn)
        if match_and_reason is None:
            continue
        match, reason = match_and_reason
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                message=reason,
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
