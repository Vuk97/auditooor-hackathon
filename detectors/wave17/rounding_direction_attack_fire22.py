"""
rounding-direction-attack-fire22

Solidity same-class recall detector for public reward checkpoint functions
that floor a reward-per-share increment to zero and still advance reward
state. This is distinct from Fire21's generic divide-before-scale shape:
the Fire22 subshape requires permissionless timing control plus a durable
state advance with no dust carry or nonzero increment guard.

Detector hits are candidate evidence only. A filing still needs source
existence, real protocol path, negative control, and R40/R76/R80 proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rounding-direction-attack-fire22"
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
    function_line: int


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b")
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_REWARD_ENTRY_RE = re.compile(
    r"(?i)^(?:poke|checkpoint|sync|accrue|update|updateReward|"
    r"notify|distribute|drip|harvest|claim)"
)
_REWARD_CONTEXT_RE = re.compile(
    r"(?is)\b(?:reward|rewards|rewardPerToken|accRewardPerShare|"
    r"rewardPerShare|rewardIndex|index|emission|emissions|bribe|"
    r"staking|staked|totalStaked|totalSupply|supply)\b"
)
_SUPPLY_DENOMINATOR_RE = re.compile(
    r"(?is)\b(?:totalStaked|totalStake|totalSupply|_totalSupply|"
    r"stakedSupply|stakingSupply|supply|sharesSupply|shareSupply)\b"
)
_REWARD_NUMERATOR_RE = re.compile(
    r"(?is)\b(?:reward|rewards|rewardDelta|rewardAmount|newRewards|"
    r"pendingReward|accruedReward|emission|emissions|rewardRate|"
    r"rate|elapsed|duration|bribe)\b"
)
_REWARD_INDEX_RE = re.compile(
    r"(?is)\b(?:rewardPerTokenStored|rewardPerToken|accRewardPerShare|"
    r"rewardPerShare|rewardIndex|globalRewardIndex|index)\b"
)
_STATE_ADVANCE_RE = re.compile(
    r"(?is)\b(?:lastUpdateTime|lastRewardTime|lastAccrual|lastCheckpoint|"
    r"lastPoke|lastSync|updatedAt|checkpointedAt|periodFinish|rewardEnd|"
    r"epoch)\b\s*(?:=|\+=)\s*(?:block\s*\.\s*timestamp|"
    r"block\s*\.\s*number|[^;{}]+)"
)
_DIRECT_INCREMENT_RE = re.compile(
    r"(?is)\b(?P<index>(?:rewardPerTokenStored|rewardPerToken|"
    r"accRewardPerShare|rewardPerShare|rewardIndex|globalRewardIndex|index))"
    r"\s*(?:\[[^\]]+\]\s*)?\+=\s*(?P<expr>[^;{}]{1,220}/[^;{}]{1,220})\s*;"
)
_QUOTIENT_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<delta>[A-Za-z_][A-Za-z0-9_]*(?:PerShare|PerToken|Index|"
    r"Increment|Delta|Accrued|Reward|Share|Slice|Portion)?)\s*=\s*"
    r"(?P<expr>[^;{}]{1,220}/[^;{}]{1,220})\s*;"
)
_SCALE_OR_ROUNDING_RE = re.compile(
    r"(?is)\b(?:ACC_PRECISION|PRECISION|SCALE|WAD|RAY|1e18|1e12|"
    r"1_000_000_000_000_000_000|1_000_000_000_000|mulDiv|"
    r"mulWad|mulRay|ceilDiv|divUp|divCeil|mulDivUp|mulDivCeil|"
    r"mulDivRoundingUp|Rounding\s*\.\s*Up)\b"
)
_ROUND_UP_FORMULA_RE = re.compile(
    r"(?is)(?:\+\s*(?:denominator|totalStaked|totalSupply|_totalSupply|"
    r"PRECISION|ACC_PRECISION|WAD|RAY|SCALE)\s*-\s*1)"
)
_DUST_CARRY_RE = re.compile(
    r"(?is)\b(?:dust|remainder|leftover|carry|undistributed|unallocated|"
    r"residual|queuedReward|rewardDebtCarry|rewardRemainder)\b"
)
_ZERO_INCREMENT_GUARD_RE = re.compile(
    r"(?is)(?:require\s*\([^;{}]*(?:increment|delta|rewardPerShare|"
    r"rewardPerToken|rewardIndex|accRewardPerShare)[^;{}]*(?:>\s*0|"
    r"!=\s*0|>=\s*1)|if\s*\([^;{}]*(?:increment|delta|rewardPerShare|"
    r"rewardPerToken|rewardIndex|accRewardPerShare)[^;{}]*(?:==\s*0|"
    r"<\s*1)[^;{}]*\)\s*(?:return|revert|throw))"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


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
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
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

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            if source[k] == "{":
                depth += 1
            elif source[k] == "}":
                depth -= 1
            k += 1
        if depth != 0:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, function_line=line))
        pos = k
    return out


def _line_for(function_line: int, text: str, match: re.Match[str]) -> int:
    return function_line + text.count("\n", 0, match.start())


def _is_public_reward_entry(fn: FunctionSlice, text: str) -> bool:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return False
    if not (_REWARD_ENTRY_RE.search(fn.name) or _REWARD_CONTEXT_RE.search(text)):
        return False
    return bool(_REWARD_INDEX_RE.search(text) and _SUPPLY_DENOMINATOR_RE.search(text))


def _is_safe_expression(expr: str, window: str) -> bool:
    return bool(
        _SCALE_OR_ROUNDING_RE.search(expr)
        or _SCALE_OR_ROUNDING_RE.search(window)
        or _ROUND_UP_FORMULA_RE.search(window)
        or _DUST_CARRY_RE.search(window)
        or _ZERO_INCREMENT_GUARD_RE.search(window)
    )


def _is_reward_floor_expr(expr: str) -> bool:
    return bool(
        "/" in expr
        and _REWARD_NUMERATOR_RE.search(expr)
        and _SUPPLY_DENOMINATOR_RE.search(expr)
    )


def _tail_uses_delta(text: str, delta: str, start: int) -> bool:
    tail = text[start:start + 900]
    if not _REWARD_INDEX_RE.search(tail):
        return False
    return bool(re.search(rf"(?is)\+=\s*{re.escape(delta)}\b", tail))


def _reward_floor_to_zero_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_public_reward_entry(fn, text):
        return None
    if not _STATE_ADVANCE_RE.search(text):
        return None

    for match in _DIRECT_INCREMENT_RE.finditer(text):
        expr = match.group("expr")
        window = text[max(0, match.start() - 220):min(len(text), match.end() + 420)]
        if _is_reward_floor_expr(expr) and not _is_safe_expression(expr, window):
            return match

    for match in _QUOTIENT_ASSIGN_RE.finditer(text):
        expr = match.group("expr")
        delta = match.group("delta")
        window = text[max(0, match.start() - 220):min(len(text), match.end() + 700)]
        if not _is_reward_floor_expr(expr):
            continue
        if _is_safe_expression(expr, window):
            continue
        if _tail_uses_delta(text, delta, match.end()):
            return match

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        match = _reward_floor_to_zero_match(fn, text)
        if match is None:
            continue
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn.function_line, text, match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` advances reward state with a floor-divided "
                    "reward-per-share increment and no dust carry or nonzero "
                    "increment guard."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
