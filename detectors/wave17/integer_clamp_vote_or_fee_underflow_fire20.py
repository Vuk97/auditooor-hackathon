"""
integer-clamp-vote-or-fee-underflow-fire20

Detects same-class Solidity integer clamp recall shapes that were still
missed after the Fire19 pass:

1. Vote or checkpoint accounting narrows vote weight to uint96 without an
   explicit range guard.
2. ERC6909-style id migration credits a new id ledger without debiting the
   old id ledger.
3. Flashloan fee paths subtract fee from principal or repay only principal
   without passing and collecting the computed fee.

This is detector evidence only. A finding still needs a real protocol path,
negative control, and R40/R76/R80 proof before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "integer-clamp-vote-or-fee-underflow-fire20"
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

_VOTE_FUNCTION_RE = re.compile(
    r"(?i)^(?:delegate|delegateBySig|moveDelegates|_moveDelegates|"
    r"writeCheckpoint|_writeCheckpoint|mint|_mint|checkpoint|"
    r"updateVotes|increaseVotes)\w*$"
)
_VOTE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:delegat|vote|votingPower|votePower|checkpoint|checkpoints|"
    r"numCheckpoints|proposal|quorum)\b"
)
_UINT96_NARROW_RE = re.compile(
    r"(?is)(?:uint96\s+[A-Za-z_][A-Za-z0-9_]*\s*=|uint96\s*\(|"
    r"unsafe96\s*\(|_add96\s*\()"
)
_VOTE_EFFECT_RE = re.compile(
    r"(?is)(?:\b(?:delegatedVotes|votePower|votingPower|votes|"
    r"checkpoints|numCheckpoints)\s*(?:\[|\.push|=)|"
    r"\+=\s*(?:uint96\s*\(|[A-Za-z_][A-Za-z0-9_]*Votes\b|votes\b))"
)
_UINT96_SAFETY_RE = re.compile(
    r"(?is)(?:SafeCast|safeCast|toUint96\s*\(|MAX_UINT96|"
    r"type\s*\(\s*uint96\s*\)\s*\.\s*max|_checkMaxSupply|"
    r"maxTotalSupply|require\s*\([^;{}]*(?:<=|<)\s*"
    r"(?:type\s*\(\s*uint96\s*\)\s*\.\s*max|MAX_UINT96|2\s*\*\*\s*96))"
)

_ERC6909_FUNCTION_RE = re.compile(
    r"(?i)^(?:migrate|migrateId|convertId|rolloverId|reclassify|"
    r"moveId|swapId|mergeId|splitId|mint|burn|transfer)\w*$"
)
_ERC6909_CONTEXT_RE = re.compile(
    r"(?is)\b(?:ERC6909|IERC6909|tokenId|assetId|oldId|newId|id|ids|"
    r"balanceOf|balances|totalSupply|totalSupplyById|delta)\b"
)
_OLD_NEW_ID_RE = re.compile(r"(?is)\b(?:oldId|fromId|sourceId)\b[\s\S]*\b(?:newId|toId|targetId)\b")
_NEW_ID_CREDIT_RE = re.compile(
    r"(?is)(?:"
    r"(?:balances|balanceOf)\s*\[[^\]]+\]\s*\[\s*(?:newId|toId|targetId)\s*\]\s*\+=|"
    r"(?:totalSupply|totalSupplyById)\s*\[\s*(?:newId|toId|targetId)\s*\]\s*\+=|"
    r"(?:_mint|mint)\s*\([^;{}]*(?:newId|toId|targetId)[^;{}]*\))"
)
_OLD_ID_DEBIT_RE = re.compile(
    r"(?is)(?:"
    r"(?:balances|balanceOf)\s*\[[^\]]+\]\s*\[\s*(?:oldId|fromId|sourceId)\s*\]\s*-=|"
    r"(?:totalSupply|totalSupplyById)\s*\[\s*(?:oldId|fromId|sourceId)\s*\]\s*-=|"
    r"(?:_burn|burn)\s*\([^;{}]*(?:oldId|fromId|sourceId)[^;{}]*\)|"
    r"require\s*\([^;{}]*(?:balances|balanceOf)\s*\[[^\]]+\]\s*"
    r"\[\s*(?:oldId|fromId|sourceId)\s*\]\s*>=)"
)

_FLASH_FUNCTION_RE = re.compile(
    r"(?i)^(?:flashLoan|flashBorrow|executeFlashLoan|doFlashLoan|"
    r"_flashLoan|onFlashLoan)\w*$"
)
_FLASH_CONTEXT_RE = re.compile(
    r"(?is)\b(?:flashFee|flashloanFee|flashLoanFee|flashFeeBps|"
    r"flashLoanRate|feeRate|feeBps|onFlashLoan|flashBorrower)\b"
)
_FLASH_FEE_BIND_RE = re.compile(
    r"(?is)\b(?:fee|feeAmount|flashFeeAmount)\s*=\s*[^;{}]*"
    r"(?:flashFee|flashloanFee|flashLoanFee|flashFeeBps|"
    r"flashLoanRate|feeRate|feeBps|_flashFee)"
)
_FLASH_UNDERFLOW_RE = re.compile(
    r"(?is)\b(?:amount|principal|assets|borrowAmount)\s*-\s*"
    r"(?:fee|feeAmount|flashFeeAmount)\b"
)
_FLASH_PRINCIPAL_ONLY_REPAY_RE = re.compile(
    r"(?is)(?:"
    r"onFlashLoan\s*\([^;{}]*(?:,\s*0\s*[,)]|amount\s*,\s*0)|"
    r"(?:transferFrom|safeTransferFrom)\s*\([^;{}]*(?:amount|principal|assets|borrowAmount)\s*\)|"
    r"balance(?:Of)?\s*\([^;{}]*\)\s*>=\s*(?:preBalance|balanceBefore)\s*\+\s*"
    r"(?:amount|principal|assets|borrowAmount))"
)
_FLASH_SAFETY_RE = re.compile(
    r"(?is)(?:"
    r"(?:amount|principal|assets|borrowAmount)\s*\+\s*(?:fee|feeAmount|flashFeeAmount)|"
    r"(?:fee|feeAmount|flashFeeAmount)\s*\+\s*(?:amount|principal|assets|borrowAmount)|"
    r"require\s*\([^;{}]*(?:fee|feeAmount|flashFeeAmount)\s*>\s*0|"
    r"require\s*\([^;{}]*(?:amount|principal|assets|borrowAmount)\s*>=\s*"
    r"(?:fee|feeAmount|flashFeeAmount)|"
    r"onFlashLoan\s*\([^;{}]*(?:fee|feeAmount|flashFeeAmount)|"
    r"_flashFee\s*\(|flashFee\s*\([^;{}]*(?:token|asset)[^;{}]*"
    r")"
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


def _vote_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _VOTE_FUNCTION_RE.search(fn.name):
        return None
    if not _VOTE_CONTEXT_RE.search(text):
        return None
    if not _VOTE_EFFECT_RE.search(text):
        return None
    if _UINT96_SAFETY_RE.search(text):
        return None
    return _UINT96_NARROW_RE.search(text)


def _erc6909_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _ERC6909_FUNCTION_RE.search(fn.name):
        return None
    if not _ERC6909_CONTEXT_RE.search(text):
        return None
    if not _OLD_NEW_ID_RE.search(text):
        return None
    if _OLD_ID_DEBIT_RE.search(text):
        return None
    return _NEW_ID_CREDIT_RE.search(text)


def _flash_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if not _FLASH_FUNCTION_RE.search(fn.name):
        return None
    if not _FLASH_CONTEXT_RE.search(text):
        return None
    if _FLASH_SAFETY_RE.search(text):
        return None
    underflow = _FLASH_UNDERFLOW_RE.search(text)
    if underflow and _FLASH_FEE_BIND_RE.search(text):
        return underflow
    if _FLASH_FEE_BIND_RE.search(text):
        return _FLASH_PRINCIPAL_ONLY_REPAY_RE.search(text)
    return None


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
                        f"`{fn.name}` narrows vote or checkpoint accounting "
                        "to uint96 without a range guard before crediting "
                        "vote state."
                    ),
                )
            )

        erc6909 = _erc6909_match(fn, text)
        if erc6909:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, erc6909),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` credits the new ERC6909 id accounting "
                        "ledger without debiting the old id ledger."
                    ),
                )
            )

        flash = _flash_match(fn, text)
        if flash:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, flash),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` computes a flashloan fee but subtracts "
                        "it from principal or collects only principal."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
