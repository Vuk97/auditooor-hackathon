"""
rounding-direction-fee-loss-fire24

Focused Solidity recall lift for rounding-direction-attack variants where a
fee-like value is rounded in the caller's favor and the operation can be
replayed or split. The detector generalizes Fire23 misses around:

1. flashloan or protocol fee math that floors to zero for small amounts,
2. reward-debt or reward-deduction math that floors before caller payout,
3. liquidation or penalty fee math that floors before liquidator credit,
4. borrow or debt fee math that floors before debt accounting.

The detector intentionally keys on load-bearing use after the rounded value.
It is not a generic arithmetic detector. Detector hits are candidate evidence
only and still need source existence, real protocol path, fixture honesty, and
R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rounding-direction-fee-loss-fire24"
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

_ENTRY_NAME_RE = re.compile(
    r"(?i)^(?:borrow|claim|collect|distribute|execute|flash|flashBorrow|"
    r"flashFee|flashLoan|harvest|liquidate|pay|repay|settle|take|"
    r"update|withdraw)"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:amount|assets?|balance|borrow|bps|BPS|collateral|debt|"
    r"fee|fees|flash|flashloan|flashLoan|liquidat|penalty|premium|"
    r"protocolFee|rate|rebate|repay|reward|rewardDebt|shares?|"
    r"treasury)\b"
)

_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<var>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:Fee|Fees|Premium|Penalty|Debt|"
    r"Deduction|Deducted|Share|Charge))|"
    r"fee|fees|premium|penalty|protocolShare|rewardDebt"
    r")\s*=\s*(?P<expr>[^;{}]{1,320})\s*;"
)

_RAW_FLOOR_EXPR_RE = re.compile(r"(?is)(?:\*[^;{}]{0,180}/|/[^;{}]{0,180}\*)")
_DOWN_HELPER_EXPR_RE = re.compile(
    r"(?is)\b(?:mulDivDown|mulWadDown|divWadDown|floorDiv|floorMulDiv|"
    r"FixedPointMathLib\s*\.\s*mulDivDown|"
    r"FullMath\s*\.\s*mulDiv|"
    r"Math\s*\.\s*mulDiv\s*\([^;{}]{1,260}\)|"
    r"Rounding\s*\.\s*Down)\b"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?is)\b(?:ceilDiv|divUp|divCeil|mulDivUp|mulDivCeil|mulWadUp|"
    r"mulDivRoundingUp|rayDivCeil|roundUp|roundingUp|"
    r"Rounding\s*\.\s*Up|"
    r"Math\s*\.\s*mulDiv\s*\([^;{}]{1,280}Rounding\s*\.\s*Up|"
    r"FullMath\s*\.\s*mulDivRoundingUp|"
    r"FixedPointMathLib\s*\.\s*mulDivUp)\b"
)
_ROUND_UP_FORMULA_RE = re.compile(
    r"(?is)(?:\+\s*(?:BPS|BASIS_POINTS|DENOMINATOR|FEE_DENOMINATOR|"
    r"WAD|RAY|SCALE|PRECISION|ACC_PRECISION|denominator)\s*-\s*1|"
    r"-\s*1\s*\)\s*/)"
)
_MIN_OR_DUST_GUARD_RE = re.compile(
    r"(?is)\b(?:minFee|MIN_FEE|minimumFee|minimumPremium|feeFloor|"
    r"dustFee|dustRemainder|feeRemainder|premiumRemainder|carryFee|"
    r"feeAccumulator|remainderAccumulator)\b|"
    r"Math\s*\.\s*max\s*\(\s*1\s*,|"
    r"if\s*\([^;{}]*(?:fee|premium|protocolFee|liquidationFee|penalty)"
    r"[^;{}]*(?:==\s*0|<\s*1|<\s*minimum)[^;{}]*\)\s*"
    r"(?:revert|throw|return|[A-Za-z_][A-Za-z0-9_]*\s*=)|"
    r"require\s*\([^;{}]*(?:fee|premium|protocolFee|liquidationFee|"
    r"penalty)[^;{}]*(?:>\s*0|>=\s*1|!=\s*0)"
)

_FEE_VAR_RE = re.compile(r"(?i)(?:fee|fees|premium|penalty|charge|protocolShare)")
_REWARD_DEBT_VAR_RE = re.compile(r"(?i)(?:rewardDebt|Debt|Deduction|Deducted)")
_LIQUIDATION_VAR_RE = re.compile(r"(?i)(?:liquidation|protocolFee|penalty)")

_REPAYMENT_USE_TEMPLATE = (
    r"(?is)(?:\bamount\s*\+\s*{var}\b|\b{var}\s*\+\s*amount\b|"
    r"\b(?:owed|repay|repayment|payback|debt|borrowBalance)\b"
    r"[^;{{}}]*\b{var}\b|"
    r"\b(?:protocolFees|treasuryFees|feeCollector|collectedFees|"
    r"accruedFees|feesAccrued)\b[^;{{}}]*(?:\+=|=)[^;{{}}]*\b{var}\b)"
)
_TRANSFER_FEE_TEMPLATE = (
    r"(?is)(?:safeTransfer|transfer|_pay|_send)\s*\([^;{{}}]*\b{var}\b"
)
_SUBTRACT_TEMPLATE = r"(?is)-\s*{var}\b"
_CALLER_CREDIT_RE = re.compile(
    r"(?is)\b(?:msg\s*\.\s*sender|caller|receiver|liquidator|"
    r"liquidatorShare|collateralCredit|seizedCollateral|claimable|"
    r"pendingReward|payout|rewardToken\s*\.\s*transfer)\b"
)
_DEBT_INCREASE_TEMPLATE = (
    r"(?is)\b(?:debt|debts|borrowBalance|borrowed|principal)"
    r"\w*\s*(?:\[.*?\])?\s*(?:\+=|=)[^;{{}}]*\b{var}\b"
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


def _is_public_value_entry(fn: FunctionSlice, text: str) -> bool:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return False
    return bool(_ENTRY_NAME_RE.search(fn.name) or _VALUE_CONTEXT_RE.search(text))


def _window(text: str, start: int, end: int) -> str:
    return text[max(0, start - 300):min(len(text), end + 760)]


def _safe_near(text: str, start: int, end: int) -> bool:
    window = _window(text, start, end)
    return bool(
        _SAFE_ROUNDING_RE.search(window)
        or _ROUND_UP_FORMULA_RE.search(window)
        or _MIN_OR_DUST_GUARD_RE.search(window)
    )


def _is_floor_expr(expr: str) -> bool:
    return bool(_RAW_FLOOR_EXPR_RE.search(expr) or _DOWN_HELPER_EXPR_RE.search(expr))


def _has_repayment_or_fee_credit(tail: str, var_name: str) -> bool:
    escaped = re.escape(var_name)
    return bool(
        re.search(_REPAYMENT_USE_TEMPLATE.format(var=escaped), tail)
        or re.search(_TRANSFER_FEE_TEMPLATE.format(var=escaped), tail)
        or re.search(_DEBT_INCREASE_TEMPLATE.format(var=escaped), tail)
    )


def _has_liquidation_remainder_credit(tail: str, var_name: str) -> bool:
    if not re.search(_SUBTRACT_TEMPLATE.format(var=re.escape(var_name)), tail):
        return False
    return bool(_CALLER_CREDIT_RE.search(tail))


def _has_reward_payout_subtraction(tail: str, var_name: str) -> bool:
    if not re.search(_SUBTRACT_TEMPLATE.format(var=re.escape(var_name)), tail):
        return False
    return bool(_CALLER_CREDIT_RE.search(tail))


def _classify_match(text: str, match: re.Match[str]) -> str | None:
    var_name = match.group("var")
    expr = match.group("expr")
    if not _is_floor_expr(expr):
        return None
    if _safe_near(text, match.start(), match.end()):
        return None

    tail = text[match.end():match.end() + 1200]
    if _REWARD_DEBT_VAR_RE.search(var_name) and _has_reward_payout_subtraction(tail, var_name):
        return "reward-debt"
    if _LIQUIDATION_VAR_RE.search(var_name) and _has_liquidation_remainder_credit(tail, var_name):
        return "liquidation-fee"
    if _FEE_VAR_RE.search(var_name) and (
        _has_repayment_or_fee_credit(tail, var_name)
        or _has_liquidation_remainder_credit(tail, var_name)
    ):
        return "fee-replay"
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        if not _is_public_value_entry(fn, text):
            continue
        if not _VALUE_CONTEXT_RE.search(text):
            continue

        for match in _ASSIGN_RE.finditer(text):
            kind = _classify_match(text, match)
            if kind is None:
                continue
            if kind == "reward-debt":
                message = (
                    f"`{fn.name}` floors reward debt or a reward deduction "
                    "before subtracting it from a caller payout, increasing "
                    "the caller's claimable amount."
                )
            elif kind == "liquidation-fee":
                message = (
                    f"`{fn.name}` floors liquidation or protocol fee math "
                    "before crediting the remainder to the liquidator, "
                    "underpaying the protocol share."
                )
            else:
                message = (
                    f"`{fn.name}` floors fee or premium math before repayment, "
                    "debt, or protocol fee accounting, allowing small repeated "
                    "operations to underpay or zero out the fee."
                )

            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, match),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=message,
                )
            )
            break

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
