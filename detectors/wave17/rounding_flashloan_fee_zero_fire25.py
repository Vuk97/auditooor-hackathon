"""
rounding-flashloan-fee-zero-fire25

Focused Solidity recall lift for rounding-direction-attack variants where
fee or reward math divides before multiplying by a rate. The dangerous shape
is not generic arithmetic: it must feed a flashloan repayment, protocol fee
accounting, reward accrual, or returned fee quote where small repeated calls
can round the fee or reward to zero.

Detector hits are candidate evidence only. A filing still needs source
existence, a real protocol path, a negative control, and R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rounding-flashloan-fee-zero-fire25"
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

_ENTRY_CONTEXT_RE = re.compile(
    r"(?i)(flash|loan|borrow|fee|premium|bps|rate|reward|rewardPerToken|"
    r"accReward|claim|distribute|notify|accrue|collect|repay|treasury)"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:amount|assets?|balance|bps|BPS|denominator|DENOMINATOR|"
    r"fee|fees|feeBps|feeRate|flash|flashFee|loan|premium|protocolFee|"
    r"rate|reward|rewards|rewardPerToken|accRewardPerShare|scale|SCALE|"
    r"supply|totalSupply|treasury)\b"
)
_RATE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:bps|BPS|basis|denominator|DENOMINATOR|fee|feeBps|feeRate|"
    r"flashFee|premium|rate|reward|rewardRate|scale|SCALE|precision|"
    r"PRECISION|totalSupply|totalStaked|supply)\b|"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:Bps|BPS|Denominator|DENOMINATOR|"
    r"Scale|SCALE|Precision|PRECISION|Rate|RATE)\b"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?is)\b(?:Math\s*\.\s*mulDiv|FullMath\s*\.\s*mulDiv|"
    r"FixedPointMathLib\s*\.\s*mulDiv|mulDiv|mulWad|mulDivUp|"
    r"mulDivRoundingUp|ceilDiv|divUp|roundUp|Rounding\s*\.\s*(?:Up|Ceil)|"
    r"ACC_PRECISION|PRECISION_FACTOR)\b|"
    r"(?:\+\s*(?:[A-Za-z_][A-Za-z0-9_]*(?:DENOMINATOR|Denominator|"
    r"PRECISION|Precision|SCALE|Scale)|10000|1e\d+)\s*-\s*1)"
)
_ZERO_FLOOR_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:minimumFlashFee|minFlashFee|MIN_FLASH_FEE|minFee|MIN_FEE|"
    r"feeFloor|dustFee|ZeroFee|ZeroPremium|ZeroReward)\b|"
    r"Math\s*\.\s*max\s*\(\s*1\s*,|"
    r"require\s*\([^;{}]*(?:fee|premium|protocolFee|flashFee|reward)"
    r"[^;{}]*(?:>\s*0|>=\s*1|!=\s*0)|"
    r"if\s*\([^;{}]*(?:fee|premium|protocolFee|flashFee|reward)"
    r"[^;{}]*(?:==\s*0|<\s*1)[^;{}]*\)\s*(?:revert|return|throw))"
)

_ASSIGN_DIV_FIRST_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*"
    r"(?:Fee|Fees|Premium|Rate|Reward|Rewards|RewardPerToken|Share|Shares)"
    r"|fee|premium|reward|rewardShare|rewardPerToken)\s*=\s*"
    r"(?P<expr>[^;{}]{1,260}/[^;{}]{1,180}\*[^;{}]{1,220})\s*;"
)
_RETURN_DIV_FIRST_RE = re.compile(
    r"(?is)\breturn\s+(?P<expr>[^;{}]{1,260}/[^;{}]{1,180}\*[^;{}]{1,220})\s*;"
)
_QUOTIENT_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    r"(?P<q>[A-Za-z_][A-Za-z0-9_]*(?:Unit|Units|Scaled|Rate|Ratio|Portion|Share|Base))"
    r"\s*=\s*(?P<expr>[^;{}]{1,220}/[^;{}]{1,180})\s*;"
)
_MUL_WITH_QUOTIENT_TEMPLATE = (
    r"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    r"(?P<out>[A-Za-z_][A-Za-z0-9_]*(?:Fee|Fees|Premium|Reward|Rewards|Share|Shares)"
    r"|fee|premium|reward|rewardShare)\s*=\s*"
    r"(?:[^;{{}}]{{0,180}}\b{q}\b[^;{{}}]{{0,180}}\*|"
    r"[^;{{}}]{{0,180}}\*\s*[^;{{}}]{{0,180}}\b{q}\b)"
    r"[^;{{}}]{{0,180}};"
)

_FEE_SINK_TEMPLATE = (
    r"(?is)(?:"
    r"\bamount\s*\+\s*{var}\b|\b{var}\s*\+\s*amount\b|"
    r"transferFrom\s*\([^;{{}}]*(?:amount\s*\+\s*{var}|{var}\s*\+\s*amount)|"
    r"\b(?:protocolFees|collectedFees|treasuryFees|feeRevenue|feesAccrued)"
    r"\s*(?:\[[^\]]*\])?\s*(?:\+=|=)[^;{{}}]*\b{var}\b|"
    r"\b(?:requiredRepayment|repayAmount|repayment|owed)\s*=\s*[^;{{}}]*\b{var}\b)"
)
_REWARD_SINK_TEMPLATE = (
    r"(?is)(?:"
    r"\b(?:rewardPerTokenStored|accRewardPerShare|rewardPerToken)"
    r"\s*(?:\+=|=)[^;{{}}]*\b{var}\b|"
    r"\b(?:claimable|pendingReward|rewards)\s*(?:\[[^\]]*\])?\s*(?:\+=|=)"
    r"[^;{{}}]*\b{var}\b|"
    r"(?:safeTransfer|transfer)\s*\([^;{{}}]*\b{var}\b\)"
    r")"
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
    return text[max(0, start - 320):min(len(text), end + 900)]


def _safe_near(text: str, start: int, end: int) -> bool:
    window = _window(text, start, end)
    return bool(_SAFE_ROUNDING_RE.search(window) or _ZERO_FLOOR_GUARD_RE.search(window))


def _is_public_value_entry(fn: FunctionSlice, text: str) -> bool:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return False
    return bool(_ENTRY_CONTEXT_RE.search(fn.name) or _VALUE_CONTEXT_RE.search(text))


def _has_load_bearing_sink(text: str, var_name: str, start: int) -> str | None:
    tail = text[start:start + 1300]
    escaped = re.escape(var_name)
    if re.search(_FEE_SINK_TEMPLATE.format(var=escaped), tail):
        return "fee"
    if re.search(_REWARD_SINK_TEMPLATE.format(var=escaped), tail):
        return "reward"
    return None


def _expr_has_div_before_mul(expr: str) -> bool:
    return bool("/" in expr and "*" in expr and expr.find("/") < expr.find("*"))


def _classify_assignment(text: str, match: re.Match[str]) -> tuple[str, str] | None:
    var_name = match.group("var")
    expr = match.group("expr")
    if not _expr_has_div_before_mul(expr):
        return None
    if not _RATE_CONTEXT_RE.search(expr):
        return None
    if _safe_near(text, match.start(), match.end()):
        return None
    kind = _has_load_bearing_sink(text, var_name, match.end())
    if kind is None:
        return None
    return kind, var_name


def _classify_return(text: str, match: re.Match[str], fn_name: str) -> tuple[str, str] | None:
    expr = match.group("expr")
    if not _expr_has_div_before_mul(expr):
        return None
    if not _RATE_CONTEXT_RE.search(expr):
        return None
    if not re.search(r"(?i)(flashFee|fee|premium|quote)", fn_name):
        return None
    if _safe_near(text, match.start(), match.end()):
        return None
    return "fee", "return value"


def _classify_split_quotient(text: str) -> tuple[re.Match[str], str, str] | None:
    for match in _QUOTIENT_ASSIGN_RE.finditer(text):
        quotient = match.group("q")
        expr = match.group("expr")
        if not _RATE_CONTEXT_RE.search(expr):
            continue
        if _safe_near(text, match.start(), match.end()):
            continue
        tail = text[match.end():match.end() + 900]
        mul_re = re.compile(_MUL_WITH_QUOTIENT_TEMPLATE.format(q=re.escape(quotient)))
        multiplied = mul_re.search(tail)
        if multiplied is None:
            continue
        out = multiplied.group("out")
        if _safe_near(text, match.end() + multiplied.start(), match.end() + multiplied.end()):
            continue
        kind = _has_load_bearing_sink(text, out, match.end() + multiplied.end())
        if kind is None:
            continue
        return match, kind, out
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        if not _is_public_value_entry(fn, text):
            continue
        if _SAFE_ROUNDING_RE.search(text) and _ZERO_FLOOR_GUARD_RE.search(text):
            continue

        for match in _ASSIGN_DIV_FIRST_RE.finditer(text):
            classified = _classify_assignment(text, match)
            if classified is None:
                continue
            kind, value_name = classified
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, match),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` computes {kind} value `{value_name}` "
                        "with division before multiplication, allowing small "
                        "amounts to round the collected fee or accrued reward to zero."
                    ),
                )
            )
            break
        else:
            returned = None
            for match in _RETURN_DIV_FIRST_RE.finditer(text):
                returned = _classify_return(text, match, fn.name)
                if returned is not None:
                    findings.append(
                        Finding(
                            detector=DETECTOR_NAME,
                            file=file_path,
                            line=_line_for(fn.function_line, text, match),
                            severity=DETECTOR_SEVERITY_DEFAULT,
                            function=fn.name,
                            message=(
                                f"`{fn.name}` returns a fee quote with division "
                                "before multiplication, so small flashloan amounts "
                                "can quote a zero fee."
                            ),
                        )
                    )
                    break
            if returned is not None:
                continue

            split = _classify_split_quotient(text)
            if split is not None:
                split_match, kind, value_name = split
                findings.append(
                    Finding(
                        detector=DETECTOR_NAME,
                        file=file_path,
                        line=_line_for(fn.function_line, text, split_match),
                        severity=DETECTOR_SEVERITY_DEFAULT,
                        function=fn.name,
                        message=(
                            f"`{fn.name}` floors an intermediate quotient before "
                            f"multiplying it into {kind} value `{value_name}`, "
                            "allowing repeated calls to zero or understate value."
                        ),
                    )
                )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
