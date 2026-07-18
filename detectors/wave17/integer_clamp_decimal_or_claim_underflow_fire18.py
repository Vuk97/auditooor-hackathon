"""
integer-clamp-decimal-or-claim-underflow-fire18

Detects a same-class Solidity integer clamp recall shape beyond the Fire17
fee, debt, and unchecked supply detector:

1. Claim paths compute remaining tokens as raw total minus claimed value.
2. Decimal normalization assumes decimals are at most 18.
3. Price ratio checks divide two price values before applying precision.

This is detector evidence only. A finding still needs a real protocol path,
negative control, and R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-clamp-decimal-or-claim-underflow-fire18"
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

_CLAIM_FUNCTION_RE = re.compile(
    r"(?i)^(?:claim|_claim|claimTokens|claimRewards|getClaim|claimable|"
    r"withdrawClaim|redeemClaim)\w*$"
)
_CLAIM_STATE_RE = re.compile(
    r"(?i)\b(?:claimed|alreadyClaimed|totalClaimed|claimedAmount|"
    r"userClaimed|claimedTokens|claimedRewards)\b"
)
_CLAIM_RAW_SUB_RE = re.compile(
    r"(?is)\b(?:total\w*|vested\w*|available\w*|claimable\w*|"
    r"allocation\w*|entitled\w*|amount\w*)\b\s*-\s*"
    r"(?:\w*claimed\w*(?:\s*\[[^\]]+\])?|\bclaimed\b(?:\s*\[[^\]]+\])?)"
)
_CLAIM_SAFETY_RE = re.compile(
    r"(?is)(?:"
    r"(?:if|require)\s*\([^)]*(?:total\w*|vested\w*|available\w*|"
    r"claimable\w*|allocation\w*|entitled\w*|amount\w*)[^)]*(?:>=|>)"
    r"[^)]*(?:claimed|Claimed)|"
    r"(?:if|require)\s*\([^)]*(?:claimed|Claimed)[^)]*(?:<=|<)"
    r"[^)]*(?:total\w*|vested\w*|available\w*|claimable\w*|"
    r"allocation\w*|entitled\w*|amount\w*)|"
    r"\?\s*(?:total\w*|vested\w*|available\w*|claimable\w*|"
    r"allocation\w*|entitled\w*|amount\w*)[^?:;{}]*-\s*[^?:;{}]*(?:claimed|Claimed)"
    r"\s*:\s*0|"
    r"(?:Math|SafeMath|ClampMath)\.(?:min|max|sub)\s*\(|"
    r"\bsaturat\w*\s*\("
    r")"
)

_DECIMAL_FUNCTION_RE = re.compile(
    r"(?i)^(?:deposit|depositFor|withdraw|withdrawTo|convert|convertToAssets|"
    r"convertToShares|normalize|normalizeAmount|scale|scaleAmount|"
    r"handleDeposit|handleWithdraw|toBase|fromBase|_deposit|_withdraw|"
    r"_scale|_normalize|previewDeposit|previewWithdraw)\w*$"
)
_DECIMALS_CONTEXT_RE = re.compile(
    r"(?is)(?:\bdecimals\s*\(|\bIERC20Metadata\b|\btokenDecimals\b|"
    r"\bassetDecimals\b|\bunderlyingDecimals\b|\bquoteDecimals\b|"
    r"\bbaseDecimals\b)"
)
_DECIMAL_SCALE_RE = re.compile(
    r"(?is)10\s*\*\*\s*\(\s*(?:18|DECIMALS|WAD_DECIMALS)\s*-\s*"
    r"(?P<dec>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)

_PRICE_FUNCTION_RE = re.compile(
    r"(?i)^(?:_?checkPrice|_?checkRatio|_?checkPriceRatio|_?validatePrice|"
    r"_?validateRatio|_?validateOracle|_?computePrice|_?computeRatio|"
    r"_?getRatio|_?getPriceRatio|_?priceRatio|_?swap|_?quote|"
    r"_?executeSwap|_?settle|_?rebalance|_?updatePrice|fromPriceToAmount|"
    r"convertPrice)\w*$"
)
_PRICE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:PriceOracle|Oracle|Router|Pricing|priceChangeLimit|"
    r"maxChange|threshold|fromPrice|toPrice|exchangeRate|getPrice|"
    r"priceFrom|priceTo|ratio)\b"
)
_PRICE_RATIO_DIV_RE = re.compile(
    r"(?is)\b(?:[A-Za-z_][A-Za-z0-9_]*[Pp]rice|fromPrice|priceFrom)"
    r"\s*/\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*[Pp]rice|toPrice|priceTo)\b"
)
_PRICE_SAFETY_RE = re.compile(
    r"(?is)(?:"
    r"(?:FullMath|Math)\.mulDiv(?:Down|Up)?\s*\(|"
    r"\bmulDiv(?:Down|Up)?\s*\(|"
    r"\bwadDiv\s*\(|\brayDiv\s*\(|"
    r"(?:fromPrice|priceFrom|[A-Za-z_][A-Za-z0-9_]*[Pp]rice)"
    r"\s*\*\s*(?:PRECISION|WAD|RAY|1e\d+)\s*/|"
    r"(?:PRECISION|WAD|RAY|1e\d+)\s*\*\s*"
    r"(?:fromPrice|priceFrom|[A-Za-z_][A-Za-z0-9_]*[Pp]rice)\s*/"
    r")"
)


def _strip_comments(source: str) -> str:
    source = re.sub(r"//[^\n]*", "", source)
    return re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        source,
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


def _decimal_safety(text: str, decimal_var: str) -> bool:
    var = re.escape(decimal_var)
    safety = re.compile(
        r"(?is)(?:"
        r"require\s*\([^)]*" + var + r"\s*<=\s*18|"
        r"require\s*\([^)]*18\s*>=\s*" + var + r"|"
        r"if\s*\([^)]*" + var + r"\s*>\s*18|"
        r"if\s*\([^)]*" + var + r"\s*>=\s*18|"
        r"if\s*\([^)]*18\s*<\s*" + var + r"|"
        r"if\s*\([^)]*18\s*<=\s*" + var + r"|"
        r"decimals\s*<=\s*18|"
        r"decimals\s*>\s*18"
        r")"
    )
    return bool(safety.search(text))


def _claim_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _CLAIM_FUNCTION_RE.search(fn.name):
        return None
    if not _CLAIM_STATE_RE.search(text):
        return None
    if _CLAIM_SAFETY_RE.search(text):
        return None
    return _CLAIM_RAW_SUB_RE.search(text)


def _decimal_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _DECIMAL_FUNCTION_RE.search(fn.name):
        return None
    if not _DECIMALS_CONTEXT_RE.search(text):
        return None
    match = _DECIMAL_SCALE_RE.search(text)
    if not match:
        return None
    if _decimal_safety(text, match.group("dec")):
        return None
    return match


def _price_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _PRICE_FUNCTION_RE.search(fn.name):
        return None
    if not _PRICE_CONTEXT_RE.search(text):
        return None
    if _PRICE_SAFETY_RE.search(text):
        return None
    return _PRICE_RATIO_DIV_RE.search(text)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        claim = _claim_match(fn, text)
        if claim:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, claim),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` computes claimable value with raw "
                        "total minus claimed subtraction and no saturating "
                        "claim boundary."
                    ),
                )
            )

        decimal = _decimal_match(fn, text)
        if decimal:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, decimal),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` scales by `10 ** (18 - decimals)` "
                        "without a decimals greater than 18 branch."
                    ),
                )
            )

        price = _price_match(fn, text)
        if price:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, price),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` divides price values before precision "
                        "scaling, so the threshold check can truncate."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
