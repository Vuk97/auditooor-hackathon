"""
integer-overflow-fee-underflow-fire24

Focused Solidity recall lift for integer-overflow-clamp misses in protocol fee
arithmetic. The detector looks for fee math that can underflow, wrap, or floor
to zero before a fee floor, cap, or solvency guard is enforced:

1. A fee is computed from amount * rate / denominator and then subtracted from
   a value-bearing amount without proving fee <= amount.
2. A fee is computed with floor division and then used as a protocol charge or
   repayment component without a nonzero fee floor or protocol-favorable
   rounding.
3. A basis-point range such as maxSurgeFee - staticFee is subtracted without a
   max >= static guard before interpolation.

Detector hits are candidate evidence only. A filing still needs source
existence, a real protocol path, a negative control, and R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-overflow-fee-underflow-fire24"
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

_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:amount|assets|balance|baseFee|basis|bps|BPS|borrow|cap|"
    r"fee|fees|feeAmount|feeBps|feeRate|flash|flashFee|flashloan|"
    r"gross|loan|maxFee|minFee|premium|protocolFee|repay|repayment|"
    r"staticFee|surge|swapFee)\b"
)
_ENTRY_FN_RE = re.compile(
    r"(?i)^(?:borrow|charge|claim|collect|compute|execute|flash|flashBorrow|"
    r"flashFee|flashLoan|get|liquidate|pay|quote|repay|settle|swap|take|"
    r"withdraw)"
)

_FEE_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    r"(?P<var>fee|feeAmount|flashFee|flashFeeAmount|premium|"
    r"premiumAmount|protocolFee|protocolFeeAmount|borrowFee|openFee|"
    r"closeFee|surgeFee|chargedFee|netFee)\s*=\s*"
    r"(?P<expr>[^;{}]{1,260}\*[^;{}]{0,220}/[^;{}]{1,180})\s*;"
)
_FEE_ASSIGN_ALT_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    r"(?P<var>fee|feeAmount|flashFee|flashFeeAmount|premium|"
    r"premiumAmount|protocolFee|protocolFeeAmount|surgeFee|chargedFee|"
    r"netFee)\s*=\s*(?P<expr>[^;{}]{1,260}/[^;{}]{0,180}\*[^;{}]{0,180})\s*;"
)

_VALUE_NAMES = (
    "amount",
    "assets",
    "balance",
    "borrowed",
    "cash",
    "grossAmount",
    "inputAmount",
    "liquidity",
    "notional",
    "principal",
    "repayAmount",
    "repayRequired",
    "withdrawAmount",
)
_VALUE_NAME_RE = "|".join(re.escape(name) for name in _VALUE_NAMES)

_SAFE_ARITH_RE = re.compile(
    r"(?is)\b(?:Math\s*\.\s*mulDiv|FullMath\s*\.\s*mulDiv|"
    r"FixedPointMathLib\s*\.\s*mulDiv|mulDivUp|mulDivRoundingUp|"
    r"mulWadUp|ceilDiv|divUp|roundUp|Rounding\s*\.\s*(?:Up|Ceil)|"
    r"SafeCast|saturat)\b"
)
_FEE_CAP_GUARD_RE = re.compile(
    rf"(?is)(?:"
    rf"require\s*\([^;{{}}]*(?:fee|feeAmount|premium|protocolFee|flashFee)"
    rf"[^;{{}}]*(?:<=|<)[^;{{}}]*(?:{_VALUE_NAME_RE})|"
    rf"require\s*\([^;{{}}]*(?:{_VALUE_NAME_RE})[^;{{}}]*(?:>=|>)"
    rf"[^;{{}}]*(?:fee|feeAmount|premium|protocolFee|flashFee)|"
    rf"if\s*\([^;{{}}]*(?:fee|feeAmount|premium|protocolFee|flashFee)"
    rf"[^;{{}}]*>\s*(?:{_VALUE_NAME_RE})[^;{{}}]*\)\s*(?:revert|return)|"
    rf"(?:fee|feeAmount|premium|protocolFee|flashFee)\s*=\s*(?:Math\s*\.)?min\s*\(|"
    rf"(?:boundedFee|checkedFee|capFee|_capFee|_boundFee)\s*\()"
)
_FEE_FLOOR_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:minFee|MIN_FEE|minimumFee|feeFloor|dustFee|FeeRoundsToZero|"
    r"ZeroFee|ZeroPremium)\b|"
    r"Math\s*\.\s*max\s*\(\s*1\s*,|"
    r"if\s*\([^;{}]*(?:fee|feeAmount|premium|protocolFee|flashFee)"
    r"[^;{}]*(?:==\s*0|<\s*1)[^;{}]*\)\s*(?:revert|throw|return)|"
    r"require\s*\([^;{}]*(?:fee|feeAmount|premium|protocolFee|flashFee)"
    r"[^;{}]*(?:>\s*0|>=\s*1|!=\s*0))"
)
_REPAY_OR_FEE_CREDIT_RE = re.compile(
    r"(?is)\b(?:amount\s*\+\s*{var}|{var}\s*\+\s*amount|"
    r"repay(?:Amount|Required)?\s*=\s*[^;{{}}]*{var}|"
    r"(?:protocolFees|collectedFees|treasuryFees|feeCollector|feeRevenue)"
    r"\s*(?:\[[^\]]*\])?\s*(?:\+=|=)[^;{{}}]*{var}|"
    r"transferFrom\s*\([^;{{}}]*(?:amount\s*\+\s*{var}|{var}\s*\+\s*amount))"
)

_RANGE_SUB_RE = re.compile(
    r"(?is)(?P<left>max[A-Za-z0-9_]*(?:Fee|Surge|Bps|Percentage)|"
    r"feeCap|surgeMax|capFee|maxFeePercentage|maxSurgeFeePercentage)"
    r"\s*-\s*(?P<right>static[A-Za-z0-9_]*(?:Fee|Bps|Percentage)|"
    r"baseFee|floorFee|minFee|feeFloor|staticFeePercentage|"
    r"staticSwapFeePercentage)"
)
_RANGE_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:max[A-Za-z0-9_]*(?:Fee|Surge|Bps|Percentage)|feeCap|surgeMax|"
    r"capFee|maxFeePercentage|maxSurgeFeePercentage)\s*<\s*"
    r"(?:static[A-Za-z0-9_]*(?:Fee|Bps|Percentage)|baseFee|floorFee|minFee|"
    r"feeFloor|staticFeePercentage|staticSwapFeePercentage)|"
    r"(?:static[A-Za-z0-9_]*(?:Fee|Bps|Percentage)|baseFee|floorFee|minFee|"
    r"feeFloor|staticFeePercentage|staticSwapFeePercentage)\s*>\s*"
    r"(?:max[A-Za-z0-9_]*(?:Fee|Surge|Bps|Percentage)|feeCap|surgeMax|"
    r"capFee|maxFeePercentage|maxSurgeFeePercentage)|"
    r"Math\s*\.\s*max\s*\(|max\s*\(|saturat)"
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


def _is_fee_entry(fn: FunctionSlice, text: str) -> bool:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return False
    return bool(_ENTRY_FN_RE.search(fn.name) or _FEE_CONTEXT_RE.search(text))


def _fee_assignments(text: str) -> list[re.Match[str]]:
    return list(_FEE_ASSIGN_RE.finditer(text)) + list(_FEE_ASSIGN_ALT_RE.finditer(text))


def _has_fee_subtraction(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1200]
    var = re.escape(var_name)
    return bool(
        re.search(rf"(?is)\b(?:{_VALUE_NAME_RE})\s*-\s*{var}\b", tail)
        or re.search(rf"(?is)\b\w+\s*=\s*[^;{{}}]*(?:{_VALUE_NAME_RE})[^;{{}}]*-\s*{var}\b", tail)
        or re.search(rf"(?is)\b(?:{_VALUE_NAME_RE})\s*-=\s*{var}\b", tail)
    )


def _has_fee_credit_or_repay(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1200]
    pattern = _REPAY_OR_FEE_CREDIT_RE.pattern.format(var=re.escape(var_name))
    return bool(re.search(pattern, tail, flags=re.I | re.S))


def _fee_subtraction_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_fee_entry(fn, text):
        return None
    if _SAFE_ARITH_RE.search(text) and _FEE_CAP_GUARD_RE.search(text):
        return None

    for match in _fee_assignments(text):
        var_name = match.group("var")
        if not _has_fee_subtraction(text, var_name, match.end()):
            continue
        if _FEE_CAP_GUARD_RE.search(text):
            continue
        return match
    return None


def _zero_fee_floor_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_fee_entry(fn, text):
        return None
    if _SAFE_ARITH_RE.search(text) or _FEE_FLOOR_GUARD_RE.search(text):
        return None

    for match in _fee_assignments(text):
        var_name = match.group("var")
        if _has_fee_credit_or_repay(text, var_name, match.end()):
            return match
    return None


def _range_underflow_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_fee_entry(fn, text):
        return None
    if not re.search(r"(?is)(?:surge|fee|bps|basis|cap|floor|static|max)", text):
        return None
    match = _RANGE_SUB_RE.search(text)
    if match is None:
        return None
    if _RANGE_GUARD_RE.search(text):
        return None
    return match


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        fee_sub = _fee_subtraction_match(fn, text)
        if fee_sub:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, fee_sub),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` computes a protocol fee and subtracts "
                        "it from value-bearing amount without proving "
                        "fee <= amount first."
                    ),
                )
            )
            continue

        zero_fee = _zero_fee_floor_match(fn, text)
        if zero_fee:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, zero_fee),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` floors protocol fee math before using "
                        "the fee in repayment or fee accounting, with no "
                        "nonzero fee floor or round-up path."
                    ),
                )
            )
            continue

        range_sub = _range_underflow_match(fn, text)
        if range_sub:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, range_sub),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` subtracts a static or floor fee from a "
                        "maximum fee before proving the maximum is at least "
                        "the floor."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
