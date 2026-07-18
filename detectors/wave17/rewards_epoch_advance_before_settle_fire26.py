"""
rewards-epoch-advance-before-settle-fire26

Solidity recall-lift detector for rewards-distribution-skew misses where a
public epoch, period, or round transition advances reward accounting before
pending rewards, claim indexes, or pool checkpoints are settled.

Confirmed source:
- reference/patterns.dsl/can-epoch-advance-before-settle.yaml
- patterns/fixtures/can-epoch-advance-before-settle_vuln.sol
- patterns/fixtures/can-epoch-advance-before-settle_clean.sol

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rewards-epoch-advance-before-settle-fire26"
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

_REWARD_EPOCH_CONTEXT_RE = re.compile(
    r"\b(?:reward\w*|bribe\w*|gauge\w*|incentive\w*|emission\w*|"
    r"claim\w*|claimable\w*|pending\w*|accrued\w*|unclaimed\w*|"
    r"checkpoint\w*|settle\w*|pool\w*|epoch\w*|period\w*|round\w*|"
    r"accReward\w*|rewardPer\w*|rewardIndex\w*)\b",
    re.IGNORECASE,
)
_COUNTER_NAME = (
    r"(?:current|active|reward|last|global)?(?:Epoch|Period|Round)(?:Index|Id)?|"
    r"(?:epoch|period|round)(?:Index|Id)?"
)
_COUNTER_ADVANCE_RE = re.compile(
    rf"\b(?P<counter>{_COUNTER_NAME})\s*"
    r"(?:"
    r"\+\+|"
    r"\+=\s*1|"
    r"=\s*(?:"
    r"\(?\s*(?P=counter)\s*\+\s*1\s*\)?(?:\s*%\s*[^;{}]+)?|"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\+\s*1|"
    r"block\.timestamp\s*/\s*[^;{}]+|"
    r"next[A-Za-z_][A-Za-z0-9_]*"
    r")"
    r")",
    re.IGNORECASE | re.DOTALL,
)
_ADVANCE_CALL_RE = re.compile(
    r"\b(?:_?advance(?:Epoch|Period|Round)|_?roll(?:Epoch|Period|Round)|"
    r"_?rotate(?:Epoch|Period|Round)|_?startNext(?:Epoch|Period|Round)|"
    r"_?checkpoint(?:Epoch|Period|Round))\s*\(",
    re.IGNORECASE,
)
_SETTLEMENT_RE = re.compile(
    r"\b(?:_?settle(?:Prev|Previous|Pending|Pool|User|Global|Epoch|Period|Round)?"
    r"Rewards?|_?settle(?:Prev|Previous)?(?:Epoch|Period|Round)|"
    r"_?checkpoint(?:Account|User|Pool|Global|Reward|Rewards|Epoch|Period|Round)?|"
    r"_?updateRewards?|_?updateReward|_?updateRewardPerToken|"
    r"_?accrueRewards?|_?accrueReward|_?syncRewards?|_?syncReward|"
    r"_?flushRewards?|_?materialize(?:Epoch|Period|Round))\s*\(|"
    r"\b(?:rewardsByEpoch|epochRewards|periodRewards|roundRewards|"
    r"claimableByEpoch|pendingByEpoch|poolCheckpoints?)\s*"
    r"\[[^\]]*(?:prev|old|epoch\s*-\s*1|period\s*-\s*1|round\s*-\s*1)"
    r"[^\]]*\]\s*(?:\[[^\]]+\]\s*)*(?:=|\+=)",
    re.IGNORECASE | re.DOTALL,
)
_REWARD_ACCOUNTING_WRITE_RE = re.compile(
    r"\b(?:pendingRewards?|claimableRewards?|accruedRewards?|"
    r"unclaimedRewards?|earnedRewards?|rewards|epochRewards|periodRewards|"
    r"roundRewards|poolRewards|rewardDebt|rewardIndex|rewardIndexes|"
    r"globalRewardIndex|rewardPerTokenStored|accRewardPerShare|"
    r"accRewardPerToken|accRewardPerWeight|userRewardPerTokenPaid|"
    r"lastClaimed(?:Epoch|Period|Round)|claimed(?:Epoch|Period|Round)|"
    r"poolCheckpoint|poolCheckpoints|poolRewardIndex|poolRewardIndexes)"
    r"\s*(?:\[[^\]]+\]\s*)*(?:=|\+=|-=|\+\+|--)|"
    r"\b(?:safeTransfer|transfer|sendValue|_mint|mint)\s*\([^;{}]*"
    r"\b(?:reward|rewards|pending|claimable|amount)\w*\b",
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


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, match.start()))


def _line_prefix(body: str, start: int) -> str:
    line_start = body.rfind("\n", 0, start) + 1
    return body[line_start:start]


def _is_local_declaration(body: str, match: re.Match[str]) -> bool:
    prefix = _line_prefix(body, match.start())
    return bool(re.search(r"\b(?:u?int(?:8|16|32|64|128|256)?|address|bool|bytes\d*|var)\s*$", prefix))


def _advance_anchor(fn: FunctionSlice) -> tuple[re.Match[str], str] | None:
    candidates: list[tuple[re.Match[str], str]] = []
    for match in _COUNTER_ADVANCE_RE.finditer(fn.body):
        if not _is_local_declaration(fn.body, match):
            candidates.append((match, "advances the reward epoch, period, or round counter"))
    call = _ADVANCE_CALL_RE.search(fn.body)
    if call is not None:
        candidates.append((call, "calls a reward epoch, period, or round advance helper"))
    if not candidates:
        return None
    return min(candidates, key=lambda item: item[0].start())


def _first_reason(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _PUBLIC_HEADER_RE.search(fn.header):
        return None
    if not (_REWARD_EPOCH_CONTEXT_RE.search(fn.name) or _REWARD_EPOCH_CONTEXT_RE.search(fn.body)):
        return None

    anchor = _advance_anchor(fn)
    if anchor is None:
        return None
    advance, advance_reason = anchor

    before = fn.body[:advance.start()]
    if _SETTLEMENT_RE.search(before):
        return None

    after = fn.body[advance.end():]
    after_settle = _SETTLEMENT_RE.search(after)
    if after_settle is not None:
        return (
            f"{advance_reason} before settlement or checkpointing; settlement occurs only after the rotation",
            advance,
        )

    if _REWARD_ACCOUNTING_WRITE_RE.search(after):
        return (
            f"{advance_reason} before pending rewards, claim indexes, or pool checkpoints are settled",
            advance,
        )
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _REWARD_EPOCH_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        reason = _first_reason(fn)
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
                    f"`{fn.name}` has reward epoch advance before settle: {message}. "
                    "Settle pending rewards, user claim indexes, and pool checkpoints "
                    "before rotating the epoch, period, or round counter. "
                    "Candidate evidence only."
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
