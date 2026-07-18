"""
integer-clamp-fee-or-supply-companion-fire16

Detects a narrow Solidity integer clamp recall shape:

1. AMM fee split code routes the all-protocol-fee boundary through a rounded
   generic formula instead of assigning the full fee amount to the protocol.
2. Bonding-curve buy or mint code multiplies a user input by a curve
   coefficient inside unchecked arithmetic, then mints or credits supply
   without a max-input clamp or mulDiv-style checked intermediate.

This is candidate evidence only. It does not prove exploitability or filing
readiness without a real protocol path, negative control, and R40/R76/R80
evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "integer-clamp-fee-or-supply-companion-fire16"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:external|public)\b")
_FEE_FUNCTION_RE = re.compile(
    r"(?i)^(?:quote|swap|_swap|computeSwap|swapStep|takeFee|protocolFee)\w*$"
)
_CURVE_FUNCTION_RE = re.compile(
    r"(?i)^(?:buy|purchase|mint|deposit|swap|invest|enter)\w*$"
)
_AMOUNT_TOKEN = (
    r"(?:msg\.value|\b(?:amount|amountIn|amountOut|value|desired|desiredTokens|"
    r"requested|requestedTokens|requestedShares|tokensOut|tokensIn|tokenAmount|"
    r"shares|qty|quantity|cost|toMint|mintAmount|buyAmount|depositAmount|"
    r"inputAmount|baseAmount)\b)"
)
_CURVE_TOKEN = (
    r"\b(?:scale|theta|k|slope|coefficient|curveK|step|factor|priceFactor|"
    r"reserve|virtualReserve|unitPrice|price|rate|multiplier|"
    r"emissionMultiplier|curveMultiplier|pricePerToken|curveRate|weight|"
    r"scalar)\b"
)
_FEE_SPLIT_RE = re.compile(
    r"(?is)(?:"
    r"(?:\b(?:amountIn|step\.amountIn)\s*\+\s*(?:feeAmount|step\.feeAmount)\b)"
    r"[^;{}]*\*\s*protocolFee\s*/\s*"
    r"(?:PIPS|PIPS_DENOMINATOR|1_?000_?000|1e6)|"
    r"protocolFee\s*\*\s*"
    r"(?:\(\s*)?(?:\b(?:amountIn|step\.amountIn)\s*\+\s*"
    r"(?:feeAmount|step\.feeAmount)\b)[^;{}]*\s*/\s*"
    r"(?:PIPS|PIPS_DENOMINATOR|1_?000_?000|1e6)"
    r")"
)
_FEE_CONTEXT_RE = re.compile(
    r"(?is)\bprotocolFee\b[\s\S]*\b(?:lpFee|swapFee|feeAmount|PIPS_DENOMINATOR)\b|"
    r"\b(?:lpFee|swapFee|feeAmount|PIPS_DENOMINATOR)\b[\s\S]*\bprotocolFee\b"
)
_FEE_BOUNDARY_GUARD_RE = re.compile(
    r"(?is)swapFee\s*==\s*protocolFee|protocolFee\s*==\s*swapFee|"
    r"lpFee\s*==\s*0|0\s*==\s*lpFee|"
    r"if\s*\([^)]*(?:swapFee\s*==\s*protocolFee|lpFee\s*==\s*0)|"
    r"\?\s*(?:feeAmount|step\.feeAmount)\s*:"
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
_SUPPLY_EFFECT_RE = re.compile(
    r"(?is)\b(?:_mint|mint|totalSupply|supply|tokensMinted|sharesMinted|"
    r"minted|creditShares|_credit|balanceOf)\b"
)
_CURVE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:bondingCurve|BondingCurve|NLAMM|LinearCurve|virtualReserve|"
    r"reserveBase|theta|slope|step|priceFactor|coefficient|curveK|"
    r"curveMultiplier|unitPrice|emissionMultiplier|pricePerToken|curveRate)\b"
)
_CURVE_BOUNDARY_GUARD_RE = re.compile(
    r"(?is)require\s*\([^;{}]*(?:desired|requested|amount|value|quantity|qty|"
    r"buyAmount|depositAmount|inputAmount|tokensOut|tokensIn|tokenAmount|"
    r"shares)\s*<=?\s*(?:MAX|maxBuy|maxAmount|maxInput|MAX_BUY|MAX_AMOUNT|"
    r"type\s*\(\s*uint\d*\s*\)\.max|2\s*\*\*\s*\d+|[^;]*/\s*"
    r"(?:scale|theta|k|slope|coefficient|curveK|step|factor|priceFactor|"
    r"reserve|virtualReserve|unitPrice|price|rate|multiplier|"
    r"emissionMultiplier|curveMultiplier|pricePerToken|curveRate|weight|"
    r"scalar))|"
    r"(?:FullMath|FixedPointMathLib|Math)\.mulDiv(?:Down|Up)?\s*\(|"
    r"\bmulDiv(?:Down|Up)?\s*\(|SafeMath\.mul\s*\("
)


def _split_functions(source: str) -> List[tuple[str, str, str, int]]:
    out: List[tuple[str, str, str, int]] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
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

        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            char = source[k]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            k += 1
        header = source[match.start():body_start]
        body = source[body_start + 1:k - 1]
        function_line = source.count("\n", 0, match.start()) + 1
        out.append((name, header, body, function_line))
        pos = k
    return out


def _fee_boundary_match(function_name: str, text: str) -> re.Match[str] | None:
    if not _FEE_FUNCTION_RE.search(function_name) and "feeAmount" not in text:
        return None
    if not _FEE_CONTEXT_RE.search(text):
        return None
    match = _FEE_SPLIT_RE.search(text)
    if not match:
        return None
    if _FEE_BOUNDARY_GUARD_RE.search(text):
        return None
    return match


def _supply_curve_match(header: str, function_name: str, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(header):
        return None
    if not _CURVE_FUNCTION_RE.search(function_name):
        return None
    if not _CURVE_CONTEXT_RE.search(text):
        return None
    if not _SUPPLY_EFFECT_RE.search(text):
        return None
    match = _UNCHECKED_CURVE_MUL_RE.search(text)
    if not match:
        return None
    if _CURVE_BOUNDARY_GUARD_RE.search(text):
        return None
    return match


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    for function_name, header, body, function_line in _split_functions(source):
        text = f"{header}\n{body}"
        fee_match = _fee_boundary_match(function_name, text)
        if fee_match:
            line = function_line + text.count("\n", 0, fee_match.start())
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=function_name,
                    message=(
                        f"`{function_name}` sends the all-protocol-fee boundary "
                        "through a rounded generic split. Add an explicit "
                        "`swapFee == protocolFee` or `lpFee == 0` branch that "
                        "assigns the full fee amount to protocol fees."
                    ),
                )
            )
            continue

        curve_match = _supply_curve_match(header, function_name, text)
        if curve_match:
            line = function_line + text.count("\n", 0, curve_match.start())
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=function_name,
                    message=(
                        f"`{function_name}` multiplies user input by a curve "
                        "coefficient inside unchecked arithmetic before minting "
                        "or crediting supply. Add a max-input clamp, remove "
                        "unchecked arithmetic, or use a checked mulDiv "
                        "intermediate."
                    ),
                )
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
