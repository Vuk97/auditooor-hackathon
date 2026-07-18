"""
integer-overflow-clamp-fire22

Detects a Solidity integer-overflow-clamp recall shape beyond Fire21:
ERC6909 claim mint or burn normalizes the caller supplied id to a 160-bit
currency for delta accounting, then uses the raw uint256 id for token
accounting. The upper 96 bits can separate the debit key from the claim id.

Confirmed source: auditooor-R71-fixdiff-mined-uniswap-v4-d8f7a4d8,
also recorded as `erc6909-mint-id-asymmetric-with-delta-accounting`.

This is detector evidence only. A finding still needs a real protocol path,
negative control, and R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-overflow-clamp-fire22"
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
    r"(?i)^(?:mint|burn|mintClaim|burnClaim|mintClaims|burnClaims|"
    r"claim|redeemClaim|settleClaim)\w*$"
)
_ID_PARAM_RE = re.compile(
    r"(?is)\buint256\s+(?:id|tokenId|currencyId|assetId)\b|"
    r"\b(?:id|tokenId|currencyId|assetId)\s*,"
)
_ID_NAME_RE = r"(?:id|tokenId|currencyId|assetId)"

_NORMALIZED_CURRENCY_RE = re.compile(
    r"(?is)(?:"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\.\s*fromId\s*\(\s*" + _ID_NAME_RE + r"\s*\)|"
    r"Currency\s*\.\s*wrap\s*\(\s*address\s*\(\s*uint160\s*\(\s*"
    + _ID_NAME_RE + r"\s*\)\s*\)\s*\)|"
    r"address\s*\(\s*uint160\s*\(\s*" + _ID_NAME_RE + r"\s*\)\s*\)"
    r")"
)
_DELTA_ACCOUNTING_RE = re.compile(
    r"(?is)(?:"
    r"_accountDelta\s*\(|"
    r"accountDelta\s*\(|"
    r"(?:deltaByCurrency|currencyDelta|currencyDeltas|reservesDelta|"
    r"balanceDelta)\s*(?:\[|\.|=|\+=|-=)"
    r")"
)
_RAW_ID_TOKEN_ACCOUNTING_RE = re.compile(
    r"(?is)(?:"
    r"_(?:mint|burn|burnFrom)\s*\([^;{}]*\b" + _ID_NAME_RE + r"\b[^;{}]*\)|"
    r"(?:balanceOf|balances|totalSupplyById|totalSupply)\s*"
    r"(?:\[[^\]]*\b" + _ID_NAME_RE + r"\b[^\]]*\]){1,2}\s*(?:\+=|-=|=)"
    r")"
)
_NORMALIZATION_SAFETY_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:normalizedId|canonicalId|normalizedTokenId|canonicalTokenId)\b|"
    r"\.toId\s*\(\s*\)|"
    r"CurrencyLibrary\s*\.\s*toId\s*\(|"
    r"require\s*\([^;{}]*\b" + _ID_NAME_RE
    + r"\b\s*(?:==|<=)\s*(?:uint256\s*\(\s*)?uint160\s*\(\s*\b"
    + _ID_NAME_RE + r"\b\s*\)|"
    r"require\s*\([^;{}]*(?:uint160\s*\(\s*\b" + _ID_NAME_RE
    + r"\b\s*\)|type\s*\(\s*uint160\s*\)\s*\.\s*max)[^;{}]*(?:==|>=)\s*\b"
    + _ID_NAME_RE + r"\b|"
    r"require\s*\([^;{}]*\b" + _ID_NAME_RE
    + r"\b\s*<=\s*type\s*\(\s*uint160\s*\)\s*\.\s*max|"
    r"\b" + _ID_NAME_RE + r"\s*>>\s*160\s*==\s*0|"
    r"InvalidId|InvalidCurrencyId|NonCanonicalId"
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


def _raw_id_mismatch_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _CLAIM_FUNCTION_RE.search(fn.name):
        return None
    if not _ID_PARAM_RE.search(fn.header):
        return None
    if not _NORMALIZED_CURRENCY_RE.search(text):
        return None
    if not _DELTA_ACCOUNTING_RE.search(text):
        return None
    if _NORMALIZATION_SAFETY_RE.search(text):
        return None
    return _RAW_ID_TOKEN_ACCOUNTING_RE.search(text)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        raw_id = _raw_id_mismatch_match(fn, text)
        if raw_id:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, raw_id),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` normalizes an ERC6909 id for currency "
                        "delta accounting but uses the raw id for token "
                        "accounting."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
