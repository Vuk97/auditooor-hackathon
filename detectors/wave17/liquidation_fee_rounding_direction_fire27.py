"""
liquidation-fee-rounding-direction-fire27

Solidity recall-lift detector for liquidation and repay fee math where the
rounding direction favors the liquidator or borrower. It targets two shapes:

1. liquidation or protocol fee math divides before multiplying by a fee,
   bonus, or close-factor rate,
2. fee-like values are floor-rounded to zero and then used for protocol-fee,
   repayment, debt, or liquidator-credit accounting.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a4dc5fcabec4193
- context_pack_hash: 5a4dc5fcabec419385f40cc3f83d3a24f63a01e0d5c301ab1ef08763094a3fe5
- source ref: reference/patterns.dsl/fx-aave-liquidation-fee-rounding-direction.yaml
- source ref: reference/patterns.dsl/ec-reward-per-token-precision-loss.yaml
- source ref: reference/patterns.dsl/flashloan-no-fee-charged.yaml
- attack_class: rounding-direction-attack

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "liquidation-fee-rounding-direction-fire27"
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
_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b")
_SAFE_HELPER_HEADER_RE = re.compile(
    r"(?i)^_?(?:ceil|ceilDiv|divUp|mulDivUp|roundUp|safe|bound|clamp|min|max)"
)

_REQUIRED_CONTEXT_RE = re.compile(
    r"(?is)\b(?:liquidat|liquidator|borrower|repay|repayment|debtToCover|"
    r"closeFactor|close\s*factor|seize|seized|collateralToSeize|"
    r"liquidationBonus|bonus|protocolFee|protocol\s*fee|"
    r"liquidationProtocolFee|feeBps|premium|penalty)\b"
)
_FEE_OR_BONUS_CONTEXT_RE = re.compile(
    r"(?is)\b(?:(?:fee|fees|bonus|premium|penalty|bps|rate)[A-Za-z0-9_]*|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:fee|fees|bonus|premium|"
    r"penalty|bps|rate)[A-Za-z0-9_]*|fee|protocolFee|protocol\s*fee|"
    r"liquidationProtocolFee|liquidationFee|bonus|liquidationBonus|"
    r"premium|penalty|bps|BPS|rate|closeFactor|close\s*factor)\b"
)

_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<var>"
    r"(?:[A-Za-z_][A-Za-z0-9_]*(?:Fee|Fees|Premium|Penalty|Bonus|"
    r"Charge|ProtocolShare|LiquidatorShare|Seized|SeizedCollateral|"
    r"CollateralToSeize))|"
    r"fee|fees|premium|penalty|bonus|protocolShare|liquidatorShare|"
    r"seizedCollateral|collateralToSeize"
    r")\s*=\s*(?P<expr>[^;{}]{1,360})\s*;"
)
_ASSIGN_OP_RE = re.compile(
    r"(?is)\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\+=|=)\s*(?P<expr>[^;{}]{1,360})\s*;"
)

_DIV_BEFORE_MULT_RE = re.compile(r"(?is)/[^;{}]{0,180}\*")
_FLOOR_EXPR_RE = re.compile(
    r"(?is)(?:\*[^;{}]{0,220}/|/[^;{}]{0,180}\*|"
    r"\b(?:mulDivDown|mulWadDown|divWadDown|floorDiv|floorMulDiv|"
    r"rayDivFloor|rayDiv\b|wadDivDown|toSharesDown|toAssetsDown)\b|"
    r"\bMath\s*\.\s*mulDiv\s*\([^;{}]{1,300}\))"
)
_RATE_OR_FEE_FACTOR_RE = re.compile(
    r"(?is)\b(?:(?:fee|fees|bonus|premium|penalty|bps|rate)[A-Za-z0-9_]*|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:fee|fees|bonus|premium|"
    r"penalty|bps|rate)[A-Za-z0-9_]*|fee|fees|protocolFee|protocol\s*fee|"
    r"liquidationProtocolFee|liquidationFee|bonus|liquidationBonus|"
    r"premium|penalty|bps|BPS|BASIS_POINTS|rate|closeFactor|"
    r"close\s*factor|FACTOR|DENOMINATOR)\b"
)

_SAFE_ROUNDING_RE = re.compile(
    r"(?is)\b(?:ceilDiv|divUp|divCeil|mulDivUp|mulDivCeil|mulWadUp|"
    r"mulDivRoundingUp|rayDivCeil|wadDivUp|roundUp|roundingUp|"
    r"toSharesUp|toAssetsUp|Rounding\s*\.\s*Up|"
    r"Math\s*\.\s*mulDiv\s*\([^;{}]{1,320}Rounding\s*\.\s*Up|"
    r"FullMath\s*\.\s*mulDivRoundingUp|"
    r"FixedPointMathLib\s*\.\s*mulDivUp)\b"
)
_ROUND_UP_FORMULA_RE = re.compile(
    r"(?is)(?:\+\s*(?:BPS|BASIS_POINTS|DENOMINATOR|FEE_DENOMINATOR|"
    r"WAD|RAY|SCALE|PRECISION|denominator)\s*-\s*1|-\s*1\s*\)\s*/)"
)
_MIN_OR_NONZERO_GUARD_RE = re.compile(
    r"(?is)\b(?:minFee|MIN_FEE|minimumFee|minimumPremium|minimumProtocolFee|"
    r"feeFloor|dustFee|dustRemainder|feeRemainder|premiumRemainder|"
    r"carryFee|feeAccumulator|remainderAccumulator)\b|"
    r"Math\s*\.\s*max\s*\(\s*1\s*,|"
    r"if\s*\([^;{}]*(?:fee|premium|protocolFee|liquidationFee|bonus|"
    r"penalty)[^;{}]*(?:==\s*0|<\s*1|<\s*minimum)[^;{}]*\)\s*"
    r"(?:revert|throw|return|[A-Za-z_][A-Za-z0-9_]*\s*=)|"
    r"require\s*\([^;{}]*(?:fee|premium|protocolFee|liquidationFee|bonus|"
    r"penalty)[^;{}]*(?:>\s*0|>=\s*1|!=\s*0)"
)

_PROTOCOL_FEE_USE_RE = re.compile(
    r"(?is)\b(?:protocolFees|treasuryFees|feeCollector|collectedFees|"
    r"accruedFees|feesAccrued|reserveFees|protocolShare|treasury)"
)
_BORROWER_OR_REPAY_USE_RE = re.compile(
    r"(?is)\b(?:owed|repay|repayment|payback|debt|borrowBalance|"
    r"liability|closeAmount|closeFactor)\b"
)
_LIQUIDATOR_CREDIT_RE = re.compile(
    r"(?is)\b(?:msg\s*\.\s*sender|liquidator|liquidatorShare|"
    r"seizedCollateral|collateralCredit|collateralToSeize|receiver|"
    r"claimable|payout)\b"
)
_SUBTRACT_VAR_TEMPLATE = r"(?is)-\s*{var}\b"
_ADD_VAR_TEMPLATE = r"(?is)(?:\+\s*{var}\b|\b{var}\s*\+)"
_VAR_USE_TEMPLATE = r"(?is)\b{var}\b"


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


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


def _is_candidate_function(fn: FunctionSlice, text: str) -> bool:
    if _SAFE_HELPER_HEADER_RE.search(fn.name):
        return False
    if _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return bool(_REQUIRED_CONTEXT_RE.search(text) and _FEE_OR_BONUS_CONTEXT_RE.search(text))
    return bool(_REQUIRED_CONTEXT_RE.search(fn.name) and _FEE_OR_BONUS_CONTEXT_RE.search(text))


def _safe_near(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 320):min(len(text), end + 780)]
    return bool(
        _SAFE_ROUNDING_RE.search(window)
        or _ROUND_UP_FORMULA_RE.search(window)
        or _MIN_OR_NONZERO_GUARD_RE.search(window)
    )


def _is_floor_expr(expr: str) -> bool:
    if not _FLOOR_EXPR_RE.search(expr):
        return False
    return bool(_RATE_OR_FEE_FACTOR_RE.search(expr))


def _is_div_before_mult_expr(expr: str) -> bool:
    return bool(_DIV_BEFORE_MULT_RE.search(expr) and _RATE_OR_FEE_FACTOR_RE.search(expr))


def _tail_uses_rounded_value(tail: str, var_name: str) -> bool:
    escaped = re.escape(var_name)
    if _PROTOCOL_FEE_USE_RE.search(tail) and re.search(_VAR_USE_TEMPLATE.format(var=escaped), tail):
        return True
    if _BORROWER_OR_REPAY_USE_RE.search(tail) and re.search(_ADD_VAR_TEMPLATE.format(var=escaped), tail):
        return True
    if _LIQUIDATOR_CREDIT_RE.search(tail) and re.search(_SUBTRACT_VAR_TEMPLATE.format(var=escaped), tail):
        return True
    if re.search(rf"(?is)\b{escaped}\b\s*(?:==|<|<=)\s*0", tail):
        return True
    return False


def _classify_match(text: str, match: re.Match[str]) -> str | None:
    var_name = match.group("var")
    expr = match.group("expr")
    if not (_is_div_before_mult_expr(expr) or _is_floor_expr(expr)):
        return None
    if _safe_near(text, match.start(), match.end()):
        return None

    tail = text[match.end():match.end() + 1300]
    if not _tail_uses_rounded_value(tail, var_name):
        return None
    if _is_div_before_mult_expr(expr):
        return "division-before-rate"
    return "floor-to-zero"


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        if not _is_candidate_function(fn, text):
            continue

        for pattern in (_ASSIGN_RE, _ASSIGN_OP_RE):
            for match in pattern.finditer(text):
                kind = _classify_match(text, match)
                if kind is None:
                    continue
                if kind == "division-before-rate":
                    message = (
                        f"`{fn.name}` divides liquidation or repay value before applying "
                        "fee, bonus, or close-factor math, so integer flooring can favor "
                        "the liquidator or borrower before protocol accounting. "
                        "NOT_SUBMIT_READY."
                    )
                else:
                    message = (
                        f"`{fn.name}` floor-rounds liquidation or repay fee math to zero "
                        "without an upward rounding, minimum-fee, or nonzero guard, "
                        "favoring the liquidator or borrower. NOT_SUBMIT_READY."
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
            else:
                continue
            break

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
