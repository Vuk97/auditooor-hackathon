"""
rounding-direction-fee-reward-fire23

Focused Solidity recall lift for rounding-direction-attack misses in fee,
reward-debt, and liquidation math.

The detector only emits when the rounded value is load-bearing in an
attacker-favorable direction:
1. a flashloan or protocol fee floors toward zero and is included in borrower
   repayment or protocol fee accounting,
2. a reward debt or deduction floors down before a caller payout, increasing
   the caller's claimable amount,
3. a liquidation protocol fee floors down and the remainder is credited to the
   liquidator or caller.

Detector hits are candidate evidence only. A filing still needs source
existence, real protocol path, negative control, and R40/R76/R80 proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rounding-direction-fee-reward-fire23"
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

_VALUE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:amount|asset|assets|balance|borrow|bps|BPS|collateral|"
    r"debt|discount|fee|fees|flash|flashloan|flashLoan|liquidat|"
    r"premium|protocolFee|rebate|repay|reward|rewardDebt|shares?|"
    r"totalSupply|treasury)\b"
)
_ENTRY_FN_RE = re.compile(
    r"(?i)^(?:borrow|claim|collect|distribute|execute|flash|flashBorrow|"
    r"flashFee|flashLoan|harvest|liquidate|pay|repay|reward|settle|"
    r"take|update|withdraw)"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?is)\b(?:ceilDiv|divUp|divCeil|mulDivUp|mulDivCeil|mulWadUp|"
    r"mulDivRoundingUp|rayDivCeil|roundUp|roundingUp|"
    r"Rounding\s*\.\s*Up|Math\s*\.\s*mulDiv\s*\([^;{}]*"
    r"Rounding\s*\.\s*Up|FullMath\s*\.\s*mulDivRoundingUp|"
    r"FixedPointMathLib\s*\.\s*mulDivUp)\b"
)
_ROUND_UP_FORMULA_RE = re.compile(
    r"(?is)(?:\+\s*(?:BPS|DENOMINATOR|FEE_DENOMINATOR|WAD|RAY|SCALE|"
    r"PRECISION|denominator)\s*-\s*1|-\s*1\s*\)\s*/)"
)
_MIN_FEE_GUARD_RE = re.compile(
    r"(?is)(?:\b(?:minFee|MIN_FEE|minimumFee|feeFloor|dustFee)\b|"
    r"Math\s*\.\s*max\s*\(\s*1\s*,|"
    r"require\s*\([^;{}]*(?:fee|premium|protocolFee|liquidationFee)"
    r"[^;{}]*(?:>\s*0|>=\s*1|!=\s*0)|"
    r"if\s*\([^;{}]*(?:fee|premium|protocolFee|liquidationFee)"
    r"[^;{}]*(?:==\s*0|<\s*1)[^;{}]*\)\s*(?:revert|throw|return))"
)

_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:fee|fees|flash|flashloan|flashLoan|premium|protocolFee|"
    r"repay|repayment|borrow|loan|treasury|feeCollector)\b"
)
_FEE_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<var>fee|feeAmount|flashFee|flashFeeAmount|premium|"
    r"premiumAmount|protocolFee|protocolFeeAmount|borrowFee|openFee|"
    r"closeFee)\s*=\s*(?P<expr>[^;{}]{1,240}(?:/[^;{}]*\*|"
    r"\*[^;{}]*/)[^;{}]{0,180})\s*;"
)
_ZERO_FEE_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?\s+)?(?P<var>fee|flashFee|premium)"
    r"\s*=\s*0\s*;"
)

_REWARD_CONTEXT_RE = re.compile(
    r"(?is)\b(?:claim|harvest|reward|rewards|rewardDebt|rewardIndex|"
    r"accRewardPerShare|pending|payout|shares?|staked|totalSupply)\b"
)
_REWARD_DEBT_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:Debt|Offset|Deduction|"
    r"Deducted|Settled|Checkpoint|Paid))\s*=\s*"
    r"(?P<expr>[^;{}]{1,240}/[^;{}]{1,160}\*[^;{}]{0,160})\s*;"
)
_REWARD_PAYOUT_RE = re.compile(
    r"(?is)\b(?:transfer|safeTransfer|_send|_pay|credit|claimable|"
    r"pending|payout|rewards?\s*\[[^\]]*(?:msg\s*\.\s*sender|caller)"
    r"[^\]]*\])\b"
)

_LIQUIDATION_CONTEXT_RE = re.compile(
    r"(?is)\b(?:liquidat|seize|collateral|debt|closeFactor|bonus|"
    r"penalty|protocolFee|liquidationFee|healthFactor)\b"
)
_LIQUIDATION_FEE_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<var>protocolFee|protocolFeeAmount|liquidationFee|"
    r"liquidationProtocolFee|penalty|fee)\s*=\s*"
    r"(?P<expr>[^;{}]{1,240}(?:/[^;{}]*\*|\*[^;{}]*/)"
    r"[^;{}]{0,180})\s*;"
)
_LIQUIDATOR_CREDIT_RE = re.compile(
    r"(?is)\b(?:msg\s*\.\s*sender|liquidator|caller|receiver|toLiquidator|"
    r"liquidatorShare|collateralCredit|seizedCollateral)\b"
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
    return bool(_ENTRY_FN_RE.search(fn.name) or _VALUE_CONTEXT_RE.search(text))


def _window(text: str, start: int, end: int) -> str:
    return text[max(0, start - 240):min(len(text), end + 620)]


def _safe_near(text: str, start: int, end: int) -> bool:
    window = _window(text, start, end)
    return bool(
        _SAFE_ROUNDING_RE.search(window)
        or _ROUND_UP_FORMULA_RE.search(window)
        or _MIN_FEE_GUARD_RE.search(window)
    )


def _tail_mentions_fee_use(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 900]
    patterns = [
        rf"\bamount\s*\+\s*{re.escape(var_name)}\b",
        rf"\b{re.escape(var_name)}\s*\+\s*amount\b",
        rf"\b(?:owed|repay|repayment|payback|debt)\b[^;{{}}]*{re.escape(var_name)}\b",
        rf"\b(?:protocolFees|treasuryFees|feeCollector|collectedFees)\b[^;{{}}]*{re.escape(var_name)}\b",
    ]
    return any(re.search(pattern, tail, flags=re.I | re.S) for pattern in patterns)


def _fee_floor_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_public_value_entry(fn, text):
        return None
    if not (_FEE_CONTEXT_RE.search(fn.name) or _FEE_CONTEXT_RE.search(text)):
        return None

    for match in _FEE_ASSIGN_RE.finditer(text):
        if _safe_near(text, match.start(), match.end()):
            continue
        if _tail_mentions_fee_use(text, match.group("var"), match.end()):
            return match

    for match in _ZERO_FEE_ASSIGN_RE.finditer(text):
        if _safe_near(text, match.start(), match.end()):
            continue
        if re.search(r"(?is)\b(?:flash|flashloan|flashLoan|premium)\b", text):
            return match
    return None


def _tail_subtracts_var(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1000]
    return bool(re.search(rf"(?is)-\s*{re.escape(var_name)}\b", tail))


def _reward_debt_floor_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_public_value_entry(fn, text):
        return None
    if not (_REWARD_CONTEXT_RE.search(fn.name) or _REWARD_CONTEXT_RE.search(text)):
        return None

    for match in _REWARD_DEBT_ASSIGN_RE.finditer(text):
        if _safe_near(text, match.start(), match.end()):
            continue
        var_name = match.group("var")
        tail = text[match.end():match.end() + 1100]
        if not _tail_subtracts_var(text, var_name, match.end()):
            continue
        if _REWARD_PAYOUT_RE.search(tail) and re.search(r"(?is)\bmsg\s*\.\s*sender\b", tail):
            return match
    return None


def _liquidation_fee_floor_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_public_value_entry(fn, text):
        return None
    if not (_LIQUIDATION_CONTEXT_RE.search(fn.name) or _LIQUIDATION_CONTEXT_RE.search(text)):
        return None

    for match in _LIQUIDATION_FEE_ASSIGN_RE.finditer(text):
        if _safe_near(text, match.start(), match.end()):
            continue
        var_name = match.group("var")
        tail = text[match.end():match.end() + 1000]
        if not _tail_subtracts_var(text, var_name, match.end()):
            continue
        if _LIQUIDATOR_CREDIT_RE.search(tail):
            return match
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        fee_floor = _fee_floor_match(fn, text)
        reward_debt = _reward_debt_floor_match(fn, text)
        liquidation_fee = _liquidation_fee_floor_match(fn, text)

        if fee_floor:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, fee_floor),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` floors fee or premium math before a "
                        "borrower repayment or protocol fee credit, which "
                        "undercharges the protocol when the division has a "
                        "remainder."
                    ),
                )
            )

        if reward_debt:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, reward_debt),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` floors reward debt before subtracting "
                        "it from a caller payout, increasing claimable "
                        "rewards in the caller's favor."
                    ),
                )
            )

        if liquidation_fee:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, liquidation_fee),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` floors the liquidation protocol fee "
                        "before crediting the remainder to the liquidator, "
                        "rounding collateral in the caller's favor."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
