"""
integer-clamp-supply-or-fee-truncation-fire17

Detects a same-class Solidity integer clamp recall shape where boundary
arithmetic changes a fee, debt, supply, or minted amount:

1. AMM protocol fees still use a rounded generic split when the LP fee is zero.
2. Debt decay subtracts below zero instead of saturating at zero.
3. Bonding curve or mint code multiplies user input in unchecked arithmetic
   before minting or crediting supply.

This is detector evidence only. A finding still needs a real protocol path,
negative control, and R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-clamp-supply-or-fee-truncation-fire17"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b")

_AMOUNT_TOKEN = (
    r"(?:msg\.value|\b(?:amount|amountIn|amountOut|value|desired|desiredTokens|"
    r"requested|requestedTokens|requestedShares|tokensOut|tokensIn|tokenAmount|"
    r"shares|qty|quantity|cost|toMint|mintAmount|buyAmount|depositAmount|"
    r"inputAmount|baseAmount)\b)"
)
_CURVE_TOKEN = (
    r"\b(?:scale|theta|k|slope|coefficient|curveK|step|factor|priceFactor|"
    r"reserve|virtualReserve|unitPrice|price|rate|multiplier|emissionMultiplier|"
    r"curveMultiplier|pricePerToken|curveRate|weight|scalar)\b"
)

_FEE_FUNCTION_RE = re.compile(
    r"(?i)^(?:quote|swap|_swap|computeSwap|swapStep|takeFee|protocolFee)\w*$"
)
_FEE_CONTEXT_RE = re.compile(
    r"(?is)\bprotocolFee\b[\s\S]*\b(?:lpFee|swapFee|feeAmount|PIPS_DENOMINATOR)\b|"
    r"\b(?:lpFee|swapFee|feeAmount|PIPS_DENOMINATOR)\b[\s\S]*\bprotocolFee\b"
)
_FEE_SPLIT_RE = re.compile(
    r"(?is)(?:"
    r"(?:\b(?:amountIn|step\.amountIn)\s*\+\s*(?:feeAmount|step\.feeAmount)\b)"
    r"[^;{}]*\*\s*protocolFee\s*/\s*"
    r"(?:PIPS|PIPS_DENOMINATOR|1_?000_?000|1e6)|"
    r"protocolFee\s*\*\s*(?:\(\s*)?"
    r"(?:\b(?:amountIn|step\.amountIn)\s*\+\s*(?:feeAmount|step\.feeAmount)\b)"
    r"[^;{}]*/\s*(?:PIPS|PIPS_DENOMINATOR|1_?000_?000|1e6)"
    r")"
)
_FEE_SAFETY_RE = re.compile(
    r"(?is)swapFee\s*==\s*protocolFee|protocolFee\s*==\s*swapFee|"
    r"lpFee\s*==\s*0|0\s*==\s*lpFee|"
    r"\?\s*(?:feeAmount|step\.feeAmount)\s*:"
)

_DEBT_FUNCTION_RE = re.compile(
    r"(?i)^(?:debtDecay|_currentDebt|_decayDebt|marketPrice|_marketPrice|"
    r"findMarketFor|_updateDebt|totalDebt|decayDebt)\w*$"
)
_DEBT_CONTEXT_RE = re.compile(
    r"(?is)\b(?:totalDebt|lastDebt|debt|decay|bond|market)\b"
)
_DEBT_SUB_RE = re.compile(
    r"(?is)\b(?:lastDebt|debt|totalDebt|market\.totalDebt)\s*-\s*decay\b|"
    r"\b(?:totalDebt|market\.totalDebt)\s*-=\s*decay\b"
)
_DEBT_SAFETY_RE = re.compile(
    r"(?is)(?:decay\s*>\s*(?:lastDebt|debt|totalDebt|market\.totalDebt)\s*\?|"
    r"(?:lastDebt|debt|totalDebt|market\.totalDebt)\s*<\s*decay\s*\?|"
    r"(?:Math|ClampMath)\.min\s*\(|\bmin\s*\(|saturat|"
    r"if\s*\([^)]*decay\s*>?=\s*(?:lastDebt|debt|totalDebt|market\.totalDebt)|"
    r"if\s*\([^)]*(?:lastDebt|debt|totalDebt|market\.totalDebt)\s*>=\s*decay)"
)

_CURVE_FUNCTION_RE = re.compile(
    r"(?i)^(?:buy|purchase|mint|deposit|swap|invest|enter)\w*$"
)
_CURVE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:bondingCurve|BondingCurve|NLAMM|LinearCurve|virtualReserve|"
    r"reserveBase|theta|slope|step|priceFactor|coefficient|curveK|"
    r"curveMultiplier|unitPrice|emissionMultiplier|pricePerToken|curveRate)\b"
)
_SUPPLY_EFFECT_RE = re.compile(
    r"(?is)\b(?:_mint|mint|totalSupply|supply|tokensMinted|sharesMinted|"
    r"minted|creditShares|_credit|balanceOf)\b"
)
_UNCHECKED_CURVE_MUL_RE = re.compile(
    r"(?is)unchecked\s*\{[^{}]*(?:"
    + _AMOUNT_TOKEN
    + r"\s*\*\s*"
    + _CURVE_TOKEN
    + r"|"
    + _CURVE_TOKEN
    + r"\s*\*\s*"
    + _AMOUNT_TOKEN
    + r")[^{}]*\}"
)
_CURVE_SAFETY_RE = re.compile(
    r"(?is)require\s*\([^;{}]*(?:msg\.value|\b(?:desired|requested|amount|"
    r"amountIn|amountOut|value|quantity|qty|buyAmount|depositAmount|inputAmount|"
    r"tokensOut|tokensIn|tokenAmount|shares)\b)\s*<=?\s*"
    r"(?:MAX|maxBuy|maxAmount|maxInput|MAX_BUY|MAX_AMOUNT|type\s*\(\s*uint\d*\s*\)"
    r"\.max|2\s*\*\*\s*\d+|[^;]*/\s*"
    + _CURVE_TOKEN
    + r")|"
    r"(?:FullMath|FixedPointMathLib|Math)\.mulDiv(?:Down|Up)?\s*\(|"
    r"\bmulDiv(?:Down|Up)?\s*\(|SafeMath\.mul\s*\("
)


def _split_functions(source: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
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

        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, line))
        pos = k
    return out


def _fee_boundary_match(function_name: str, text: str) -> re.Match[str] | None:
    if not _FEE_FUNCTION_RE.search(function_name) and "feeAmount" not in text:
        return None
    if not _FEE_CONTEXT_RE.search(text):
        return None
    if _FEE_SAFETY_RE.search(text):
        return None
    return _FEE_SPLIT_RE.search(text)


def _debt_decay_match(function_name: str, text: str) -> re.Match[str] | None:
    if not _DEBT_FUNCTION_RE.search(function_name) and "decay" not in text:
        return None
    if not _DEBT_CONTEXT_RE.search(text):
        return None
    if _DEBT_SAFETY_RE.search(text):
        return None
    return _DEBT_SUB_RE.search(text)


def _curve_supply_match(header: str, function_name: str, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(header):
        return None
    if not _CURVE_FUNCTION_RE.search(function_name):
        return None
    if not _CURVE_CONTEXT_RE.search(text):
        return None
    if not _SUPPLY_EFFECT_RE.search(text):
        return None
    if _CURVE_SAFETY_RE.search(text):
        return None
    return _UNCHECKED_CURVE_MUL_RE.search(text)


def _line_for(function_line: int, text: str, match: re.Match[str]) -> int:
    return function_line + text.count("\n", 0, match.start())


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    for function_name, header, body, function_line in _split_functions(source):
        text = f"{header}\n{body}"

        fee_match = _fee_boundary_match(function_name, text)
        if fee_match:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(function_line, text, fee_match),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=function_name,
                    message=(
                        f"`{function_name}` computes protocol fee with a "
                        "rounded generic split while the all-protocol-fee "
                        "boundary has no explicit branch."
                    ),
                )
            )

        debt_match = _debt_decay_match(function_name, text)
        if debt_match:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(function_line, text, debt_match),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=function_name,
                    message=(
                        f"`{function_name}` subtracts decay from debt without "
                        "a zero-floor clamp, so the value can underflow or "
                        "revert at the debt boundary."
                    ),
                )
            )

        curve_match = _curve_supply_match(header, function_name, text)
        if curve_match:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(function_line, text, curve_match),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=function_name,
                    message=(
                        f"`{function_name}` multiplies user input by a curve "
                        "coefficient inside unchecked arithmetic before "
                        "minting or crediting supply."
                    ),
                )
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
