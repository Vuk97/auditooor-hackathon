"""
rounding-direction-attack-fire21

Solidity recall lift for rounding-direction-attack misses from Fire20.

Flags only confirmed value-bearing shapes:
1. reward, liquidation, or exchange math divides before scaling,
2. flashloan or fee math floors a fee to zero without a nonzero guard,
3. liquidation fee or collateral-seize math floors in the user-favoring
   direction without round-up protection,
4. swap or exchange calls pass zero or unbounded minimum output.

Detector hits are candidate evidence only. A filing still needs source
existence, real protocol path, negative control, and R40/R76/R80 proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "rounding-direction-attack-fire21"
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

_VALUE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:amount|asset|assets|balance|balances|borrow|bps|BPS|"
    r"collateral|debt|exchange|fee|fees|flash|flashloan|flashLoan|"
    r"liquidat|minOut|minAmountOut|minReturn|amountOutMin|"
    r"amountOutMinimum|oraclePrice|payout|penalty|premium|price|quote|"
    r"reward|rewardPerToken|rewardIndex|shares?|swap|supply|token|"
    r"totalSupply|treasury|withdraw)\b"
)
_ENTRY_FN_RE = re.compile(
    r"(?i)^(?:accrue|claim|collect|deposit|distribute|exchange|"
    r"execute|flash|flashBorrow|flashLoan|harvest|liquidate|mint|"
    r"notify|preview|quote|redeem|repay|reward|settle|swap|update|withdraw)"
)
_DIV_BEFORE_SCALE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:reward|rewardPerToken|rewardIndex|accReward|perShare|"
    r"collateral|debt|liquidat|exchange|quote|amountOut|price|shares?|"
    r"assets?|supply|totalSupply|fee|premium)\b"
)
_DIRECT_DIV_BEFORE_MUL_RE = re.compile(
    r"(?P<expr>\(?\s*[A-Za-z_][A-Za-z0-9_\.\[\]\(\)]*\s*/\s*"
    r"[A-Za-z_][A-Za-z0-9_\.\[\]\(\)]*\s*\)?\s*\*\s*"
    r"[A-Za-z_][A-Za-z0-9_\.\[\]\(\)]*)"
)
_QUOTIENT_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<q>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>[^;{}]{1,180}/[^;{}]{1,180})\s*;"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?is)\b(?:ceilDiv|divUp|divCeil|mulDivUp|mulDivCeil|mulWadUp|"
    r"mulDivRoundingUp|roundUp|roundingUp|Rounding\s*\.\s*Up|"
    r"Math\s*\.\s*mulDiv\s*\([^;{}]*Rounding\s*\.\s*Up|"
    r"FullMath\s*\.\s*mulDivRoundingUp|unsafeDivUp)\b"
)
_ROUND_UP_FORMULA_RE = re.compile(
    r"(?is)(?:\+\s*(?:BPS|DENOMINATOR|WAD|RAY|SCALE|PRECISION)\s*-\s*1|"
    r"-\s*1\s*\)\s*/)"
)
_NONZERO_GUARD_RE = re.compile(
    r"(?is)(?:require\s*\([^;{}]*(?:fee|premium|amountOut|minOut|"
    r"amountOutMinimum|amountOutMin|minReturn|liquidationFee)[^;{}]*"
    r"(?:>\s*0|!=\s*0|>=\s*1)|"
    r"if\s*\([^;{}]*(?:fee|premium|amountOut|minOut|amountOutMinimum|"
    r"amountOutMin|minReturn|liquidationFee)[^;{}]*(?:==\s*0|<\s*1)"
    r"[^;{}]*\)\s*(?:revert|throw))"
)

_FLASH_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:flash|flashloan|flashLoan|flashFee|premium|receiver|"
    r"borrower|callback|onFlashLoan)\b"
)
_FEE_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?\s+)?"
    r"(?P<fee>fee|feeAmount|flashFee|flashFeeAmount|premium|premiumAmount)"
    r"\s*=\s*(?P<expr>[^;{}]*(?:feeBps|feeRate|premiumBps|premiumRate|"
    r"BPS|DENOMINATOR)[^;{}]*/[^;{}]*);"
)

_LIQUIDATION_CONTEXT_RE = re.compile(
    r"(?is)\b(?:liquidat|seize|collateral|debt|closeFactor|healthFactor|"
    r"bonus|penalty|liquidationFee|oraclePrice)\b"
)
_LIQUIDATION_FLOOR_RE = re.compile(
    r"(?is)\b(?:liquidationFee|fee|penalty|bonus|collateralToSeize|"
    r"seizeAmount|seizedCollateral)\s*=\s*[^;{}]*(?:/[^;{}]*\*|\*[^;{}]*/)"
)

_SWAP_CONTEXT_RE = re.compile(
    r"(?is)\b(?:swap|exchange|router|amountOut|amountIn|minOut|minReturn|"
    r"amountOutMin|amountOutMinimum|slippage|quote)\b"
)
_SWAP_CALL_RE = re.compile(
    r"(?is)\b_?(?:swap|exchange|exactInput|exactOutput|routerSwap|"
    r"swapExactTokensForTokens|swapExactETHForTokens)\s*\([^;{}]*\)"
)
_ZERO_MIN_OUT_RE = re.compile(
    r"(?is)(?:\b(?:minOut|minReturn|minAmountOut|amountOutMin|"
    r"amountOutMinimum)\s*[:=]\s*0\b|,\s*0\s*[,)]|"
    r"\b(?:None|type\s*\(\s*uint256\s*\)\s*\.\s*min)\b)"
)
_USER_MIN_OUT_RE = re.compile(
    r"(?is)\b(?:userMinOut|callerMinOut|minOut|minReturn|minAmountOut|"
    r"amountOutMin|amountOutMinimum)\b"
)
_MIN_OUT_GUARD_RE = re.compile(
    r"(?is)\brequire\s*\([^;{}]*(?:userMinOut|callerMinOut|minOut|"
    r"minReturn|minAmountOut|amountOutMin|amountOutMinimum)[^;{}]*"
    r"(?:>\s*0|!=\s*0|>=\s*1)"
)


def _strip_comments(source: str) -> str:
    without_line = re.sub(r"//[^\n]*", "", source)
    return re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        without_line,
        flags=re.S,
    )


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
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


def _has_public_value_entry(fn: FunctionSlice, text: str) -> bool:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return False
    return bool(_ENTRY_FN_RE.search(fn.name) or _VALUE_CONTEXT_RE.search(text))


def _safe_near(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 180):min(len(text), end + 260)]
    return bool(_SAFE_ROUNDING_RE.search(window) or _ROUND_UP_FORMULA_RE.search(window))


def _division_before_scaling_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _has_public_value_entry(fn, text):
        return None
    if not _DIV_BEFORE_SCALE_CONTEXT_RE.search(text):
        return None

    for match in _DIRECT_DIV_BEFORE_MUL_RE.finditer(text):
        if _safe_near(text, match.start(), match.end()):
            continue
        expr = match.group("expr")
        if _DIV_BEFORE_SCALE_CONTEXT_RE.search(expr) or _DIV_BEFORE_SCALE_CONTEXT_RE.search(text):
            return match

    for match in _QUOTIENT_ASSIGN_RE.finditer(text):
        quotient = match.group("q")
        expr = match.group("expr")
        if not (
            _DIV_BEFORE_SCALE_CONTEXT_RE.search(quotient)
            or _DIV_BEFORE_SCALE_CONTEXT_RE.search(expr)
            or _DIV_BEFORE_SCALE_CONTEXT_RE.search(text)
        ):
            continue
        tail = text[match.end():match.end() + 700]
        if re.search(rf"(?is)\b{re.escape(quotient)}\b[^;{{}}]*\*", tail):
            if not _safe_near(text, match.start(), match.end()):
                return match
    return None


def _flash_fee_zero_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _has_public_value_entry(fn, text):
        return None
    if not _FLASH_FEE_CONTEXT_RE.search(fn.name) and not _FLASH_FEE_CONTEXT_RE.search(text):
        return None
    if _NONZERO_GUARD_RE.search(text):
        return None
    for match in _FEE_ASSIGN_RE.finditer(text):
        expr = match.group("expr")
        if _safe_near(text, match.start(), match.end()):
            continue
        if re.search(r"(?is)\*", expr) and re.search(r"(?is)/", expr):
            return match
    return None


def _liquidation_floor_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _has_public_value_entry(fn, text):
        return None
    if not _LIQUIDATION_CONTEXT_RE.search(fn.name) and not _LIQUIDATION_CONTEXT_RE.search(text):
        return None
    if _SAFE_ROUNDING_RE.search(text) or _ROUND_UP_FORMULA_RE.search(text):
        return None
    for match in _LIQUIDATION_FLOOR_RE.finditer(text):
        if _safe_near(text, match.start(), match.end()):
            continue
        return match
    return None


def _zero_min_out_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _has_public_value_entry(fn, text):
        return None
    if not _SWAP_CONTEXT_RE.search(fn.name) and not _SWAP_CONTEXT_RE.search(text):
        return None
    if _MIN_OUT_GUARD_RE.search(text) and _USER_MIN_OUT_RE.search(text):
        return None
    for match in _SWAP_CALL_RE.finditer(text):
        call_text = match.group(0)
        if _USER_MIN_OUT_RE.search(call_text) and _MIN_OUT_GUARD_RE.search(text):
            continue
        if _ZERO_MIN_OUT_RE.search(call_text):
            return match
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        div_before_scale = _division_before_scaling_match(fn, text)
        flash_fee = _flash_fee_zero_match(fn, text)
        liquidation = _liquidation_floor_match(fn, text)
        zero_min_out = _zero_min_out_match(fn, text)

        if div_before_scale and liquidation is None:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, div_before_scale),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` divides before scaling in value-bearing "
                        "reward, liquidation, or exchange math."
                    ),
                )
            )

        if flash_fee:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, flash_fee),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` floors flashloan fee math without a "
                        "nonzero fee guard, permitting zero-fee value flow."
                    ),
                )
            )

        if liquidation:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, liquidation),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` floors liquidation fee or collateral "
                        "math without round-up protection."
                    ),
                )
            )

        if zero_min_out:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, zero_min_out),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` routes value through a swap or exchange "
                        "call with zero or unbounded minimum output."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
