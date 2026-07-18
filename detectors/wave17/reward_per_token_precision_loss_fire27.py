"""
reward-per-token-precision-loss-fire27

Fire27 Solidity lift for reward-per-token, accumulated-per-share, reward index,
and emission accounting that divides before multiplying by the precision scale.

Source refs:
- reference/patterns.dsl/ec-reward-per-token-precision-loss.yaml
- reference/patterns.dsl/fx-aave-liquidation-fee-rounding-direction.yaml
- reference/patterns.dsl/flashloan-no-fee-charged.yaml

The detector is candidate evidence only. It is NOT_SUBMIT_READY and cannot be
cited as exploit proof without a real in-scope path, negative control, source
existence, and R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "reward-per-token-precision-loss-fire27"
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
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public|internal)\b")
_PURE_VIEW_RE = re.compile(r"(?i)\b(?:pure|view)\b")
_ENTRY_NAME_RE = re.compile(
    r"(?i)^(?:accrue|checkpoint|claim|collect|configure|distribute|"
    r"drip|harvest|notify|poke|settle|sync|update)"
)
_REWARD_WORD_RE = re.compile(
    r"(?is)(?:reward|rewards|emission|emissions|incentive|"
    r"incentives|bribe|bonus|drip)"
)
_INDEX_WORD_RE = re.compile(
    r"(?is)\b(?:rewardPerToken|rewardPerTokenStored|rewardPerShare|"
    r"accRewardPerShare|accumulatedRewardPerShare|accPerShare|"
    r"rewardIndex|globalRewardIndex|emissionIndex|index|perToken|"
    r"perShare)\b"
)
_SUPPLY_WORD_RE = re.compile(
    r"(?is)\b(?:totalStaked|totalStake|totalSupply|_totalSupply|"
    r"stakedSupply|stakingSupply|shareSupply|sharesSupply|supply|"
    r"shares?|stake|staked|balanceOf)\b"
)
_DURATION_WORD_RE = re.compile(
    r"(?is)\b(?:duration|rewardsDuration|period|epochLength|elapsed|"
    r"deltaTime|timeElapsed)\b"
)
_SCALE_WORD_RE = re.compile(
    r"(?is)\b(?:ACC_PRECISION|PRECISION|SCALE|WAD|RAY|BASE|"
    r"1e18|1e12|1_000_000_000_000_000_000|"
    r"1_000_000_000_000|1000000000000000000|1000000000000)\b"
)

_INDEX_TARGET_RE = (
    r"(?:rewardPerTokenStored|rewardPerToken|rewardPerShare|"
    r"accRewardPerShare|accumulatedRewardPerShare|accPerShare|"
    r"rewardIndex|globalRewardIndex|emissionIndex|index)"
)
_EMISSION_TARGET_RE = (
    r"(?:rewardRate|emissionRate|rewardPerSecond|rewardPerBlock|"
    r"emissionsPerSecond|dripRate)"
)
_TEMP_NAME_RE = (
    r"[A-Za-z_][A-Za-z0-9_]*(?:Delta|Increment|PerShare|PerToken|"
    r"Index|Rate|Reward|Rewards|Share|Emission|Debt|Deduction|Offset)"
)

_DIRECT_INDEX_RE = re.compile(
    rf"(?is)\b(?P<target>{_INDEX_TARGET_RE})\s*(?:\[[^\]]+\]\s*)?"
    rf"(?:\+=|=\s*(?P=target)\s*\+)\s*"
    rf"(?P<expr>[^;{{}}]{{1,260}}/[^;{{}}]{{1,260}}\*[^;{{}}]{{0,180}})\s*;"
)
_TEMP_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<var>{_TEMP_NAME_RE})\s*=\s*"
    rf"(?P<expr>[^;{{}}]{{1,260}}/[^;{{}}]{{1,260}}\*[^;{{}}]{{0,180}})\s*;"
)
_EMISSION_ASSIGN_RE = re.compile(
    rf"(?is)\b(?P<target>{_EMISSION_TARGET_RE})\s*(?:\[[^\]]+\]\s*)?"
    rf"(?:=|\+=)\s*"
    rf"(?P<expr>[^;{{}}]{{1,260}}/[^;{{}}]{{1,260}}\*[^;{{}}]{{0,180}})\s*;"
)
_DEBT_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:Debt|Deduction|Offset|Paid|Settled))"
    rf"\s*=\s*(?P<expr>[^;{{}}]{{1,260}}/[^;{{}}]{{1,260}}\*[^;{{}}]{{0,180}})\s*;"
)

_ROUNDING_SAFE_RE = re.compile(
    r"(?is)\b(?:mulDiv|Math\s*\.\s*mulDiv|FullMath\s*\.\s*mulDiv|"
    r"FixedPointMathLib\s*\.\s*mulDiv|mulWad|mulRay|ceilDiv|"
    r"divUp|divCeil|mulDivUp|mulDivCeil|mulDivRoundingUp|"
    r"Rounding\s*\.\s*Up|roundUp|rayDivCeil|mulWadUp)\b"
)
_ROUND_UP_FORMULA_RE = re.compile(
    r"(?is)(?:\+\s*(?:denominator|totalStaked|totalSupply|_totalSupply|"
    r"supply|PRECISION|ACC_PRECISION|WAD|RAY|SCALE)\s*-\s*1)"
)
_DUST_OR_REMAINDER_RE = re.compile(
    r"(?is)\b(?:dust|remainder|leftover|carry|undistributed|unallocated|"
    r"residual|queuedReward|rewardRemainder|emissionRemainder|"
    r"indexRemainder)\b"
)
_NONZERO_INCREMENT_GUARD_RE = re.compile(
    r"(?is)(?:require\s*\([^;{}]*(?:increment|delta|rewardPerShare|"
    r"rewardPerToken|rewardIndex|accRewardPerShare|emissionRate|"
    r"rewardRate)[^;{}]*(?:>\s*0|!=\s*0|>=\s*1)|"
    r"if\s*\([^;{}]*(?:increment|delta|rewardPerShare|rewardPerToken|"
    r"rewardIndex|accRewardPerShare|emissionRate|rewardRate)[^;{}]*"
    r"(?:==\s*0|<\s*1)[^;{}]*\)\s*(?:return|revert|throw))"
)
_PAYOUT_RE = re.compile(
    r"(?is)\b(?:transfer|safeTransfer|_send|_pay|claimable|pending|"
    r"payout|rewards?\s*\[[^\]]*(?:msg\s*\.\s*sender|caller)[^\]]*\])\b"
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


def _window(text: str, start: int, end: int) -> str:
    return text[max(0, start - 260):min(len(text), end + 720)]


def _is_safe_window(text: str, start: int, end: int) -> bool:
    window = _window(text, start, end)
    return bool(
        _ROUNDING_SAFE_RE.search(window)
        or _ROUND_UP_FORMULA_RE.search(window)
        or _DUST_OR_REMAINDER_RE.search(window)
        or _NONZERO_INCREMENT_GUARD_RE.search(window)
    )


def _is_accounting_function(fn: FunctionSlice, text: str) -> bool:
    if not _VISIBILITY_RE.search(fn.header):
        return False
    if _PURE_VIEW_RE.search(fn.header):
        return False
    if not (_ENTRY_NAME_RE.search(fn.name) or _REWARD_WORD_RE.search(text)):
        return False
    return bool(_REWARD_WORD_RE.search(text) and (_INDEX_WORD_RE.search(text) or _SUPPLY_WORD_RE.search(text)))


def _div_before_mul_parts(expr: str) -> tuple[str, str, str] | None:
    slash = expr.find("/")
    if slash < 0:
        return None
    star = expr.find("*", slash + 1)
    if star < 0:
        return None
    return expr[:slash], expr[slash + 1:star], expr[star + 1:]


def _expr_is_reward_index_div_before_scale(expr: str) -> bool:
    parts = _div_before_mul_parts(expr)
    if parts is None:
        return False
    left, denominator, right = parts
    left_ok = bool(_REWARD_WORD_RE.search(left) or _SUPPLY_WORD_RE.search(left))
    denom_ok = bool(_SUPPLY_WORD_RE.search(denominator) or _DURATION_WORD_RE.search(denominator))
    right_ok = bool(_SCALE_WORD_RE.search(right) or _INDEX_WORD_RE.search(right) or _REWARD_WORD_RE.search(right))
    return left_ok and denom_ok and right_ok


def _expr_is_user_debt_div_before_index(expr: str) -> bool:
    parts = _div_before_mul_parts(expr)
    if parts is None:
        return False
    left, denominator, right = parts
    left_ok = bool(_SUPPLY_WORD_RE.search(left) or re.search(r"(?is)\b(?:amount|balance|shares?|stake)\b", left))
    denom_ok = bool(_SUPPLY_WORD_RE.search(denominator))
    right_ok = bool(_INDEX_WORD_RE.search(right) or _REWARD_WORD_RE.search(right))
    return left_ok and denom_ok and right_ok


def _tail_updates_index(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1000]
    return bool(
        re.search(rf"(?is)\b{_INDEX_TARGET_RE}\b\s*(?:\[[^\]]+\]\s*)?\+=\s*{re.escape(var_name)}\b", tail)
        or re.search(rf"(?is)\b{_INDEX_TARGET_RE}\b\s*=\s*\b{_INDEX_TARGET_RE}\b\s*\+\s*{re.escape(var_name)}\b", tail)
    )


def _tail_pays_user_after_subtracting(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1200]
    return bool(
        re.search(rf"(?is)-\s*{re.escape(var_name)}\b", tail)
        and re.search(r"(?is)\bmsg\s*\.\s*sender\b", tail)
        and _PAYOUT_RE.search(tail)
    )


def _direct_index_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_accounting_function(fn, text):
        return None
    for match in _DIRECT_INDEX_RE.finditer(text):
        if _is_safe_window(text, match.start(), match.end()):
            continue
        if _expr_is_reward_index_div_before_scale(match.group("expr")):
            return match
    return None


def _temp_index_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_accounting_function(fn, text):
        return None
    for match in _TEMP_ASSIGN_RE.finditer(text):
        if _is_safe_window(text, match.start(), match.end()):
            continue
        var_name = match.group("var")
        if _expr_is_reward_index_div_before_scale(match.group("expr")) and _tail_updates_index(text, var_name, match.end()):
            return match
    return None


def _emission_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_accounting_function(fn, text):
        return None
    for match in _EMISSION_ASSIGN_RE.finditer(text):
        if _is_safe_window(text, match.start(), match.end()):
            continue
        if _expr_is_reward_index_div_before_scale(match.group("expr")):
            return match
    return None


def _user_favorable_debt_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_accounting_function(fn, text):
        return None
    for match in _DEBT_ASSIGN_RE.finditer(text):
        if _is_safe_window(text, match.start(), match.end()):
            continue
        var_name = match.group("var")
        if _expr_is_user_debt_div_before_index(match.group("expr")) and _tail_pays_user_after_subtracting(text, var_name, match.end()):
            return match
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        branch = "reward index"
        match = _direct_index_match(fn, text)
        if match is None:
            match = _emission_match(fn, text)
            branch = "emission rate"
        if match is None:
            match = _temp_index_match(fn, text)
            branch = "temporary reward index increment"
        if match is None:
            match = _user_favorable_debt_match(fn, text)
            branch = "caller-favorable reward debt"
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
                    f"`{fn.name}` uses divide-before-multiply {branch} math "
                    "in reward, share, supply, or index accounting. Scale "
                    "before dividing or use mulDiv so the remainder is not "
                    "lost in a user-favorable direction."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
