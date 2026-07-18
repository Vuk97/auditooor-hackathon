"""
flashloan-fee-underflow-or-missing-fire27

Solidity recall lift for the flashloan-fee-underflow-or-missing family.
Source refs:
- reference/patterns.dsl/flashloan-fee-underflow-or-missing.yaml
- reference/patterns.dsl/fx-balancer-surge-fee-underflow.yaml
- reference/patterns.dsl/fx-silo-irm-overflow-returns-zero-k.yaml

The detector looks only inside repayment or fee contexts. It catches four
candidate shapes:
1. Fee math is subtracted from amount without proving fee <= amount.
2. Negative fee deltas are clamped to zero instead of reverting or returning
   the fee floor.
3. Fee math divides before multiplying and then feeds repayment or fee
   accounting.
4. Flashloan or borrow paths advertise a fee knob but repay only principal or
   pass zero premium to the callback.

Detector hits are candidate evidence only. A filing still needs source
existence, a real protocol path, a negative control, and R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "flashloan-fee-underflow-or-missing-fire27"
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

_FEE_VAR_RE = (
    r"[A-Za-z_][A-Za-z0-9_]*(?:fee|Fee|fees|Fees|premium|Premium|"
    r"surge|Surge|utilization|Utilization|utilisation|Utilisation|"
    r"interest|Interest|range|Range)[A-Za-z0-9_]*"
)
_VALUE_RE = (
    r"amount|assets?|balance|balanceBefore|borrowed|cash|debt|grossAmount|"
    r"inputAmount|liquidity|notional|principal|repayAmount|repayRequired|"
    r"repayment|shares|withdrawAmount"
)
_VALUE_NAME_RE = re.compile(rf"(?is)\b(?:{_VALUE_RE})\b")

_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:amount|assets?|balanceBefore|borrow|borrower|borrowFee|"
    r"cash|debt|fee|fees|feeAmount|feeBps|feeRate|flash|flashFee|"
    r"flashloan|flashLoan|loan|premium|protocolFee|repay|repayment|"
    r"surge|surgeFee|surgeFeePercentage|maxSurgeFeePercentage|"
    r"staticFee|staticFeePercentage|swapFee|utilization|utilisation|interestRate|"
    r"borrowRate|treasury|protocolFees|collectedFees|feeCollector|feeRange|BPS|"
    r"basis|denominator)\b"
)
_FEE_PATH_FN_RE = re.compile(
    r"(?i)(flash|borrow|loan|repay|repayment|fee|premium|surge|"
    r"utilization|utilisation|interest|quote|compute|calculate|calc|"
    r"collect|charge|swap|accrue)"
)
_REPAY_OR_FEE_SINK_RE = re.compile(
    r"(?is)\b(?:repay|repayment|requiredRepayment|transferFrom|"
    r"balanceBefore|balanceAfter|protocolFees|collectedFees|treasuryFees|"
    r"feeRevenue|feesAccrued|feeCollector|premium|flashFee|borrowFee|"
    r"surgeFee|staticFee|swapFee|utilizationFee|utilisationFee|feeRange|"
    r"onFlashLoan|executeOperation|receiveFlashLoan)\b"
)
_SOURCE_FEE_KNOB_RE = re.compile(
    r"(?is)\b(?:flashFee|flashloanFee|flashLoanFee|flashLoanRate|"
    r"flashFeeBps|FLASHLOAN_PREMIUM|premiumRate|borrowFee|borrowFeeBps|"
    r"feeRate|feeBps|protocolFeeBps|utilizationFeeBps)\b"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?is)\b(?:Math\s*\.\s*mulDiv|FullMath\s*\.\s*mulDiv|"
    r"FixedPointMathLib\s*\.\s*mulDiv|mulDivUp|mulDivRoundingUp|"
    r"mulWadUp|ceilDiv|divUp|roundUp|Rounding\s*\.\s*(?:Up|Ceil)|"
    r"SafeCast|saturat)\b"
)
_FEE_CAP_GUARD_RE = re.compile(
    rf"(?is)(?:"
    rf"require\s*\([^;{{}}]*(?:{_FEE_VAR_RE})[^;{{}}]*(?:<=|<)"
    rf"[^;{{}}]*(?:{_VALUE_RE})|"
    rf"require\s*\([^;{{}}]*(?:{_VALUE_RE})[^;{{}}]*(?:>=|>)"
    rf"[^;{{}}]*(?:{_FEE_VAR_RE})|"
    rf"if\s*\([^;{{}}]*(?:{_FEE_VAR_RE})[^;{{}}]*>\s*(?:{_VALUE_RE})"
    rf"[^;{{}}]*\)\s*(?:revert|return|throw)|"
    rf"(?:{_FEE_VAR_RE})\s*=\s*(?:Math\s*\.)?min\s*\(|"
    rf"(?:boundedFee|checkedFee|capFee|_capFee|_boundFee)\s*\()"
)
_FEE_FLOOR_GUARD_RE = re.compile(
    rf"(?is)(?:"
    rf"\b(?:minFee|MIN_FEE|minimumFee|minimumFlashFee|minFlashFee|"
    rf"MIN_FLASH_FEE|feeFloor|dustFee|FeeRoundsToZero|ZeroFee|"
    rf"ZeroPremium)\b|"
    rf"Math\s*\.\s*max\s*\(\s*1\s*,|"
    rf"if\s*\([^;{{}}]*(?:{_FEE_VAR_RE})[^;{{}}]*(?:==\s*0|<\s*1)"
    rf"[^;{{}}]*\)\s*(?:revert|throw|return)|"
    rf"require\s*\([^;{{}}]*(?:{_FEE_VAR_RE})[^;{{}}]*(?:>\s*0|>=\s*1|!=\s*0))"
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
    r"return\s+(?:static[A-Za-z0-9_]*(?:Fee|Bps|Percentage)|baseFee|"
    r"floorFee|minFee|feeFloor|staticFeePercentage|staticSwapFeePercentage)\s*;|"
    r"Math\s*\.\s*max\s*\(|max\s*\(|saturat)"
)

_FEE_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<var>{_FEE_VAR_RE})\s*=\s*"
    rf"(?P<expr>[^;{{}}]{{1,300}}(?:\*|/|-)[^;{{}}]{{1,260}})\s*;"
)
_FEE_SUB_FROM_AMOUNT_RE = re.compile(
    rf"(?is)(?:"
    rf"\b(?:{_VALUE_RE})\s*-\s*{{var}}\b|"
    rf"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;{{}}]*(?:{_VALUE_RE})"
    rf"[^;{{}}]*-\s*{{var}}\b|"
    rf"\b(?:{_VALUE_RE})\s*-=\s*{{var}}\b)"
)
_FEE_CREDIT_OR_REPAY_TEMPLATE = (
    rf"(?is)(?:"
    rf"\b(?:{_VALUE_RE})\s*\+\s*{{var}}\b|"
    rf"\b{{var}}\s*\+\s*(?:{_VALUE_RE})\b|"
    rf"\b(?:repayAmount|repayRequired|requiredRepayment|repayment|owed)"
    rf"\s*=\s*[^;{{}}]*{{var}}\b|"
    rf"(?:protocolFees|collectedFees|treasuryFees|feeRevenue|feesAccrued)"
    rf"\s*(?:\[[^\]]*\])?\s*(?:\+=|=)[^;{{}}]*{{var}}\b|"
    rf"transferFrom\s*\([^;{{}}]*(?:(?:{_VALUE_RE})\s*\+\s*{{var}}|"
    rf"{{var}}\s*\+\s*(?:{_VALUE_RE})))"
)

_DIV_FIRST_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    rf"(?P<var>{_FEE_VAR_RE})\s*=\s*"
    rf"(?P<expr>[^;{{}}]{{1,260}}/[^;{{}}]{{1,180}}\*[^;{{}}]{{1,220}})\s*;"
)
_QUOTIENT_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    r"(?P<q>[A-Za-z_][A-Za-z0-9_]*(?:Unit|Units|Scaled|Rate|Ratio|"
    r"Portion|Share|Base|Utilization))\s*=\s*"
    r"(?P<expr>[^;{}]{1,220}/[^;{}]{1,180})\s*;"
)
_MUL_WITH_QUOTIENT_TEMPLATE = (
    rf"(?is)\b(?:uint(?:256|128|64)?|var)?\s*"
    rf"(?P<out>{_FEE_VAR_RE})\s*=\s*"
    rf"(?:[^;{{}}]{{0,180}}\b{{q}}\b[^;{{}}]{{0,180}}\*|"
    rf"[^;{{}}]{{0,180}}\*\s*[^;{{}}]{{0,180}}\b{{q}}\b)"
    rf"[^;{{}}]{{0,180}};"
)

_ZERO_TERNARY_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<var>{_FEE_VAR_RE})\s*=\s*"
    rf"(?P<cond>[^;{{}}?]{{1,240}}(?:<|>)[^;{{}}?]{{1,240}})\?"
    rf"(?P<nonzero>[^;{{}}:]{{1,260}}-[^;{{}}:]{{1,260}}):\s*"
    rf"(?:0|uint256\s*\(\s*0\s*\)|int256\s*\(\s*0\s*\))\s*;"
)
_ZERO_TERNARY_REVERSED_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<var>{_FEE_VAR_RE})\s*=\s*"
    rf"(?P<cond>[^;{{}}?]{{1,240}}(?:<|>)[^;{{}}?]{{1,240}})\?\s*"
    rf"(?:0|uint256\s*\(\s*0\s*\)|int256\s*\(\s*0\s*\))\s*:"
    rf"(?P<nonzero>[^;{{}}:]{{1,260}}-[^;{{}}:]{{1,260}})\s*;"
)
_SIGNED_ZERO_RETURN_RE = re.compile(
    rf"(?is)if\s*\([^;{{}}]*(?:{_FEE_VAR_RE})[^;{{}}]*<\s*0[^;{{}}]*\)"
    rf"\s*(?:return\s+0\s*;|\{{[^{{}}]{{0,180}}return\s+0\s*;[^{{}}]*\}})"
)
_ZERO_ASSIGN_AFTER_BAD_FEE_RE = re.compile(
    rf"(?is)if\s*\([^;{{}}]*(?:{_FEE_VAR_RE})[^;{{}}]*(?:>|<)"
    rf"[^;{{}}]*(?:{_VALUE_RE}|0)[^;{{}}]*\)\s*"
    rf"(?:\{{[^{{}}]{{0,180}}(?:{_FEE_VAR_RE})\s*=\s*0\s*;[^{{}}]*\}}|"
    rf"(?:{_FEE_VAR_RE})\s*=\s*0\s*;)"
)

_FLASH_OR_BORROW_ENTRY_RE = re.compile(
    r"(?i)^(?:flashLoan|flashBorrow|executeFlashLoan|doFlashLoan|"
    r"borrow|borrowFlash|flash)\w*$"
)
_FLASH_FLOW_RE = re.compile(
    r"(?is)\b(?:onFlashLoan|executeOperation|receiveFlashLoan|"
    r"flashLoanCall|flashBorrow|transferFrom|safeTransfer|transfer)\s*\("
)
_CALLBACK_ZERO_PREMIUM_RE = re.compile(
    r"(?is)\b(?:onFlashLoan|executeOperation|receiveFlashLoan|"
    r"flashLoanCall)\s*\([^;{}]{1,260},\s*0\s*(?:,|\))"
)
_EXACT_PRINCIPAL_REPAY_RE = re.compile(
    r"(?is)(?:"
    r"transferFrom\s*\([^;{}]*(?:amount|assets|principal|borrowed)"
    r"\s*(?:,|\))|"
    r"repay(?:Amount|Required)?\s*=\s*(?:amount|assets|principal|borrowed)\s*;|"
    r"require\s*\([^;{}]*(?:balanceAfter|postBalance)[^;{}]*(?:>=|>)"
    r"[^;{}]*(?:balanceBefore|preBalance)\s*\))"
)
_PREMIUM_INCLUDED_RE = re.compile(
    rf"(?is)(?:"
    rf"(?:amount|assets|principal|borrowed|balanceBefore|preBalance)"
    rf"\s*\+\s*(?:{_FEE_VAR_RE})|"
    rf"(?:{_FEE_VAR_RE})\s*\+\s*(?:amount|assets|principal|borrowed)|"
    rf"\b(?:flashFee|_flashFee)\s*\(|"
    rf"\b(?:premium|feeAmount|flashFeeAmount|chargedFee)\s*=|"
    rf"require\s*\([^;{{}}]*(?:balanceAfter|postBalance)[^;{{}}]*(?:>=|>)"
    rf"[^;{{}}]*(?:balanceBefore|preBalance)[^;{{}}]*\+\s*(?:{_FEE_VAR_RE}))"
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
    return text[max(0, start - 420):min(len(text), end + 1100)]


def _is_fee_path(fn: FunctionSlice, text: str) -> bool:
    return bool(
        (_FEE_PATH_FN_RE.search(fn.name) or _FEE_CONTEXT_RE.search(text))
        and _FEE_CONTEXT_RE.search(text)
        and _REPAY_OR_FEE_SINK_RE.search(text)
    )


def _has_fee_context_around(text: str, match: re.Match[str]) -> bool:
    window = _window(text, match.start(), match.end())
    return bool(_FEE_CONTEXT_RE.search(window) and _REPAY_OR_FEE_SINK_RE.search(window))


def _has_fee_subtraction(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1300]
    pattern = _FEE_SUB_FROM_AMOUNT_RE.pattern.replace("{var}", re.escape(var_name))
    return bool(re.search(pattern, tail, flags=re.I | re.S))


def _has_fee_credit_or_repay(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1400]
    pattern = _FEE_CREDIT_OR_REPAY_TEMPLATE.replace("{var}", re.escape(var_name))
    return bool(re.search(pattern, tail, flags=re.I | re.S))


def _fee_subtraction_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_fee_path(fn, text):
        return None
    if _FEE_CAP_GUARD_RE.search(text):
        return None
    for match in _FEE_ASSIGN_RE.finditer(text):
        expr = match.group("expr")
        if not re.search(r"(?is)(?:fee|premium|bps|rate|BPS|denominator|amount|asset)", expr):
            continue
        var_name = match.group("var")
        if _has_fee_subtraction(text, var_name, match.end()):
            return match
    return None


def _zero_clamp_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_fee_path(fn, text):
        return None
    if _RANGE_GUARD_RE.search(text) or _FEE_FLOOR_GUARD_RE.search(text):
        return None
    for pattern in (
        _ZERO_TERNARY_RE,
        _ZERO_TERNARY_REVERSED_RE,
        _SIGNED_ZERO_RETURN_RE,
        _ZERO_ASSIGN_AFTER_BAD_FEE_RE,
    ):
        match = pattern.search(text)
        if match and _has_fee_context_around(text, match):
            return match
    return None


def _expr_has_div_before_mul(expr: str) -> bool:
    return bool("/" in expr and "*" in expr and expr.find("/") < expr.find("*"))


def _div_first_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_fee_path(fn, text):
        return None
    if _SAFE_ROUNDING_RE.search(text) or _FEE_FLOOR_GUARD_RE.search(text):
        return None
    for match in _DIV_FIRST_ASSIGN_RE.finditer(text):
        expr = match.group("expr")
        if not _expr_has_div_before_mul(expr):
            continue
        if not re.search(r"(?is)(?:fee|premium|bps|BPS|rate|denominator|scale|precision)", expr):
            continue
        if _has_fee_credit_or_repay(text, match.group("var"), match.end()):
            return match

    for match in _QUOTIENT_ASSIGN_RE.finditer(text):
        expr = match.group("expr")
        if not re.search(r"(?is)(?:amount|asset|utilization|utilisation|BPS|denominator|scale|precision)", expr):
            continue
        tail = text[match.end():match.end() + 1000]
        mul_re = re.compile(_MUL_WITH_QUOTIENT_TEMPLATE.format(q=re.escape(match.group("q"))))
        multiplied = mul_re.search(tail)
        if multiplied is None:
            continue
        out = multiplied.group("out")
        if _has_fee_credit_or_repay(text, out, match.end() + multiplied.end()):
            return match
    return None


def _missing_premium_match(
    fn: FunctionSlice,
    text: str,
    source_has_fee_knob: bool,
) -> re.Match[str] | None:
    if not source_has_fee_knob:
        return None
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _FLASH_OR_BORROW_ENTRY_RE.search(fn.name):
        return None
    if not _FLASH_FLOW_RE.search(text):
        return None
    if _PREMIUM_INCLUDED_RE.search(text):
        return None

    callback_zero = _CALLBACK_ZERO_PREMIUM_RE.search(text)
    if callback_zero:
        return callback_zero
    return _EXACT_PRINCIPAL_REPAY_RE.search(text)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    source_has_fee_knob = bool(_SOURCE_FEE_KNOB_RE.search(stripped))
    findings: list[Finding] = []

    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        missing = _missing_premium_match(fn, text, source_has_fee_knob)
        if missing:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, missing),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` advertises fee-bearing flashloan or "
                        "borrow context but repays only principal or passes "
                        "zero premium to the callback."
                    ),
                )
            )
            continue

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
                        f"`{fn.name}` computes a fee and subtracts it from "
                        "amount without proving fee <= amount first."
                    ),
                )
            )
            continue

        zero_clamp = _zero_clamp_match(fn, text)
        if zero_clamp:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, zero_clamp),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` clamps a negative or inverted fee delta "
                        "to zero instead of enforcing a floor or reverting."
                    ),
                )
            )
            continue

        div_first = _div_first_match(fn, text)
        if div_first:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, div_first),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` divides before multiplying fee math and "
                        "then uses the result in repayment or fee accounting."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
