"""
integer-overflow-clamp-fire21

Detects confirmed Solidity same-class recall shapes where vote, token id,
amount delta, or fee math is narrowed, clamped, wrapped, or underflows before
the resulting value is used for voting power, minting, or fee collection.

This is detector evidence only. A finding still needs a real protocol path,
negative control, and R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-overflow-clamp-fire21"
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


_SMALL_UINT = r"uint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128)"

_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b")

_SMALL_CAST_RE = re.compile(
    r"(?is)\b"
    + _SMALL_UINT
    + r"\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
    + _SMALL_UINT
    + r"\s*\([^;{}]+\)"
)
_DIRECT_SMALL_CAST_RE = re.compile(r"(?is)\b" + _SMALL_UINT + r"\s*\([^;{}]+\)")
_CLAMP_RE = re.compile(
    r"(?is)(?:"
    r"\?\s*type\s*\(\s*" + _SMALL_UINT + r"\s*\)\s*\.\s*max\s*:\s*"
    + _SMALL_UINT + r"\s*\(|"
    r"(?:Math|SignedMath|ClampMath)\.min\s*\([^;{}]*type\s*\(\s*"
    + _SMALL_UINT + r"\s*\)\s*\.\s*max|"
    r"type\s*\(\s*" + _SMALL_UINT + r"\s*\)\s*\.\s*max\s*<\s*"
    r"[A-Za-z_][A-Za-z0-9_]*"
    r")"
)
_UNDERFLOW_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_\[\]\.]*\s*-\s*"
    r"[A-Za-z_][A-Za-z0-9_\[\]\.]*"
)

_MAX_BOUND_RE = re.compile(
    r"(?is)(?:"
    r"require\s*\([^;{}]*(?:<=|<)\s*(?:type\s*\(\s*" + _SMALL_UINT
    + r"\s*\)\s*\.\s*max|MAX_UINT\d+)|"
    r"require\s*\([^;{}]*(?:type\s*\(\s*" + _SMALL_UINT
    + r"\s*\)\s*\.\s*max|MAX_UINT\d+)\s*(?:>=|>)|"
    r"\bSafeCast\b|\btoUint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128)\s*\("
    r")"
)
_SUB_BOUND_RE = re.compile(
    r"(?is)(?:"
    r"require\s*\([^;{}]*[A-Za-z_][A-Za-z0-9_\[\]\.]*\s*>=\s*"
    r"[A-Za-z_][A-Za-z0-9_\[\]\.]*|"
    r"require\s*\([^;{}]*[A-Za-z_][A-Za-z0-9_\[\]\.]*\s*<=\s*"
    r"[A-Za-z_][A-Za-z0-9_\[\]\.]*|"
    r"if\s*\([^;{}]*[A-Za-z_][A-Za-z0-9_\[\]\.]*\s*<\s*"
    r"[A-Za-z_][A-Za-z0-9_\[\]\.]*\)\s*(?:revert|return)|"
    r"if\s*\([^;{}]*[A-Za-z_][A-Za-z0-9_\[\]\.]*\s*>\s*"
    r"[A-Za-z_][A-Za-z0-9_\[\]\.]*\)\s*(?:revert|return)"
    r")"
)

_VOTE_FUNCTION_RE = re.compile(
    r"(?i)^(?:delegate|delegateBySig|moveDelegates|_moveDelegates|"
    r"writeCheckpoint|_writeCheckpoint|checkpoint|castVote|vote|"
    r"updateVotes|increaseVotes|mintVotes|delegateClamped)\w*$"
)
_VOTE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:delegat|vote|votingPower|votePower|checkpoint|checkpoints|"
    r"numCheckpoints|proposal|quorum)\b"
)
_VOTE_EFFECT_RE = re.compile(
    r"(?is)\b(?:delegatedVotes|votePower|votingPower|votes|"
    r"checkpoints|numCheckpoints)\s*(?:\[|\.push|=|\+=)"
)

_ID_FUNCTION_RE = re.compile(
    r"(?i)^(?:mint|_mint|migrate|migrateId|convertId|rolloverId|"
    r"moveId|swapId|mergeId|splitId|reclassify|mintClampedId)\w*$"
)
_ID_CONTEXT_RE = re.compile(
    r"(?is)\b(?:ERC6909|IERC6909|tokenId|assetId|oldId|newId|rawId|"
    r"fromId|toId|targetId|sourceId|totalSupplyById|balanceOf)\b"
)
_ID_EFFECT_RE = re.compile(
    r"(?is)(?:\b_?mint\s*\([^;{}]*\b(?:id|Id|tokenId|assetId)[^;{}]*\)|"
    r"(?:balanceOf|balances)\s*\[[^\]]+\]\s*\[[^\]]*(?:id|Id|tokenId|assetId)[^\]]*\]\s*\+=|"
    r"totalSupplyById\s*\[[^\]]*(?:id|Id|tokenId|assetId)[^\]]*\]\s*\+=)"
)

_DELTA_FUNCTION_RE = re.compile(
    r"(?i)^(?:mint|_mint|credit|creditShares|settle|settleDelta|"
    r"applyDelta|mintRemaining|claim|redeem)\w*$"
)
_DELTA_CONTEXT_RE = re.compile(
    r"(?is)\b(?:amount|delta|remaining|already|minted|claim|credit|"
    r"balance|supply|shares)\b"
)
_DELTA_EFFECT_RE = re.compile(
    r"(?is)(?:\b_?mint\s*\(|\bcredit(?:Shares|Balance)?\s*\(|"
    r"(?:balanceOf|balances|minted|totalSupply|supply)\s*(?:\[|=|\+=))"
)

_FEE_FUNCTION_RE = re.compile(
    r"(?i)^(?:collectFee|takeFee|chargeFee|settleFee|flashLoan|"
    r"flashBorrow|executeFlashLoan|swap|quote|collect)\w*$"
)
_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:fee|fees|feeBps|feeRate|flashFee|flashLoanFee|"
    r"collectedFees|protocolFees|feeCollector|feeRecipient|BPS)\b"
)
_FEE_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"(?:collectedFees|protocolFees|feeBalance|feesAccrued)\s*(?:\[[^\]]+\])?\s*\+=|"
    r"\b(?:_pullFee|_collectFee|collectProtocolFee)\s*\(|"
    r"(?:safeTransfer|transfer)\s*\([^;{}]*(?:feeRecipient|feeCollector)[^;{}]*"
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


def _first_hazard(text: str) -> re.Match[str] | None:
    for pattern in (_CLAMP_RE, _SMALL_CAST_RE, _DIRECT_SMALL_CAST_RE, _UNDERFLOW_RE):
        match = pattern.search(text)
        if match:
            return match
    return None


def _narrow_or_clamp_match(text: str) -> re.Match[str] | None:
    clamp = _CLAMP_RE.search(text)
    if clamp:
        return clamp
    if _MAX_BOUND_RE.search(text):
        return None
    return _SMALL_CAST_RE.search(text) or _DIRECT_SMALL_CAST_RE.search(text)


def _underflow_match(text: str) -> re.Match[str] | None:
    if _SUB_BOUND_RE.search(text):
        return None
    return _UNDERFLOW_RE.search(text)


def _vote_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _VOTE_FUNCTION_RE.search(fn.name):
        return None
    if not _VOTE_CONTEXT_RE.search(text):
        return None
    if not _VOTE_EFFECT_RE.search(text):
        return None
    return _narrow_or_clamp_match(text)


def _id_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _ID_FUNCTION_RE.search(fn.name):
        return None
    if not _ID_CONTEXT_RE.search(text):
        return None
    if not _ID_EFFECT_RE.search(text):
        return None
    return _narrow_or_clamp_match(text)


def _delta_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _DELTA_FUNCTION_RE.search(fn.name):
        return None
    if not _DELTA_CONTEXT_RE.search(text):
        return None
    if not _DELTA_EFFECT_RE.search(text):
        return None
    underflow = _underflow_match(text)
    if underflow:
        return underflow
    return _narrow_or_clamp_match(text)


def _fee_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _FEE_FUNCTION_RE.search(fn.name):
        return None
    if not _FEE_CONTEXT_RE.search(text):
        return None
    if not _FEE_EFFECT_RE.search(text):
        return None
    underflow = _underflow_match(text)
    if underflow:
        return underflow
    return _narrow_or_clamp_match(text)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        vote = _vote_match(fn, text)
        if vote:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, vote),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` narrows or clamps vote math before "
                        "crediting voting power."
                    ),
                )
            )
            continue

        token_id = _id_match(fn, text)
        if token_id:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, token_id),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` narrows or clamps a token id before "
                        "minting or id accounting."
                    ),
                )
            )
            continue

        delta = _delta_match(fn, text)
        if delta:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, delta),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` narrows or underflows an amount delta "
                        "before minting or balance credit."
                    ),
                )
            )
            continue

        fee = _fee_match(fn, text)
        if fee:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, fee),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` narrows or underflows fee math before "
                        "fee collection."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
