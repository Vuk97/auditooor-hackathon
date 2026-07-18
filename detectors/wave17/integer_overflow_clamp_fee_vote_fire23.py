"""
integer-overflow-clamp-fee-vote-fire23

Detects one Solidity integer-overflow-clamp recall gap across three measured
miss families:

1. Governance vote arithmetic multiplies or adds a vote amount, then narrows it
   into uint96 without SafeCast or an explicit type(uint96).max bound.
2. Fee arithmetic computes a fee from amount * rate, then subtracts it from the
   enforced amount in an unchecked or unbounded path.
3. Surge fee arithmetic computes maxSurgeFee - staticFee without first proving
   maxSurgeFee >= staticFee.

This detector is candidate evidence only. A returned finding is not filing
proof without a real source path, negative control, and R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "integer-overflow-clamp-fee-vote-fire23"
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
_VISIBLE_RE = re.compile(r"\b(?:external|public|internal)\b")

_VOTE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:votes?|votingPower|delegate(?:d|s)?Votes?|checkpoints?|"
    r"proposalVotes?|quorum|weight|power)\b"
)
_UINT96_NARROW_RE = re.compile(
    r"(?is)(?:"
    r"\buint96\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:uint96\s*\(|\([^;]*[+*][^;]*;)|"
    r"\buint96\s*\(\s*[^;]*(?:[+*]|balanceOf|getVotes|totalSupply)[^;]*\)|"
    r"\(\s*uint96\s*\)\s*[^;]*(?:[+*]|balanceOf|getVotes|totalSupply)"
    r")"
)
_UINT96_GUARD_RE = re.compile(
    r"(?is)(?:SafeCast|safeCast|toUint96|type\s*\(\s*uint96\s*\)\s*\.max|"
    r"MAX_UINT96|_checkMaxSupply|maxTotalSupply|"
    r"require\s*\([^;{}]*(?:<=|<)[^;{}]*(?:uint96|MAX_UINT96|maxTotalSupply|maxSupply))"
)

_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:flashLoan|flashBorrow|loan|borrow|fee|premium|surge|swapFee|"
    r"protocolFee|feeBps|feeRate|flashFee|premiumRate|BPS|BASIS_POINTS)\b"
)
_FEE_MUL_RE = re.compile(
    r"(?is)\b(?:fee|feeAmount|premium|charge|surgeFee|protocolFee|flashFee)"
    r"[A-Za-z0-9_]*\b\s*=\s*[^;]*(?:amount|principal|assets|balance|notional)"
    r"[^;]*\*[^;]*(?:fee|premium|rate|bps|BPS|BASIS_POINTS|surge)[^;]*;"
)
_FEE_SUB_RE = re.compile(
    r"(?is)(?:"
    r"(?:amount|principal|assets|balance|notional|repayAmount|grossAmount)"
    r"\s*-\s*(?:fee|feeAmount|premium|charge|surgeFee|protocolFee|flashFee)"
    r"[A-Za-z0-9_]*|"
    r"(?:repayRequired|netAmount|amountAfterFee|payout|postFeeAmount)"
    r"\s*=\s*[^;]*(?:amount|principal|assets|balance|notional|grossAmount)"
    r"[^;]*-\s*(?:fee|feeAmount|premium|charge|surgeFee|protocolFee|flashFee)"
    r"[A-Za-z0-9_]*)"
)
_FEE_SUB_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"require\s*\([^;{}]*(?:fee|feeAmount|premium|charge|surgeFee|protocolFee|flashFee)"
    r"[^;{}]*(?:<=|<)[^;{}]*(?:amount|principal|assets|balance|notional|grossAmount)|"
    r"(?:fee|feeAmount|premium|charge|surgeFee|protocolFee|flashFee)[A-Za-z0-9_]*"
    r"\s*=\s*(?:Math\.)?min\s*\(|"
    r"if\s*\([^;{}]*(?:fee|feeAmount|premium|charge|surgeFee|protocolFee|flashFee)"
    r"[^;{}]*>\s*(?:amount|principal|assets|balance|notional|grossAmount)|"
    r"checkedFee|boundedFee|capFee|_capFee)"
)

_SURGE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:surgeFee|computeSurge|calcSurge|getSurge|surgeFeeData|"
    r"maxSurgeFeePercentage|staticFeePercentage|maxSurgeFee|staticSwapFee)\b"
)
_SURGE_SUB_RE = re.compile(
    r"(?is)(?:maxSurgeFeePercentage|maxSurgeFee|maxFee|surgeMax)"
    r"\s*-\s*(?:staticFeePercentage|staticSwapFeePercentage|staticFee|baseFee)"
)
_SURGE_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"(?:maxSurgeFeePercentage|maxSurgeFee|maxFee|surgeMax)"
    r"\s*<\s*(?:staticFeePercentage|staticSwapFeePercentage|staticFee|baseFee)|"
    r"(?:staticFeePercentage|staticSwapFeePercentage|staticFee|baseFee)"
    r"\s*>\s*(?:maxSurgeFeePercentage|maxSurgeFee|maxFee|surgeMax)|"
    r"Math\.max\s*\(|max\s*\()"
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


def _vote_narrow_match(function_name: str, text: str) -> re.Match[str] | None:
    if not _VOTE_CONTEXT_RE.search(text) and "vote" not in function_name.lower():
        return None
    match = _UINT96_NARROW_RE.search(text)
    if not match:
        return None
    if _UINT96_GUARD_RE.search(text):
        return None
    return match


def _fee_subtraction_match(function_name: str, text: str) -> re.Match[str] | None:
    if not _FEE_CONTEXT_RE.search(text) and "fee" not in function_name.lower():
        return None
    if not _FEE_MUL_RE.search(text):
        return None
    match = _FEE_SUB_RE.search(text)
    if not match:
        return None
    if "unchecked" not in text and _FEE_SUB_GUARD_RE.search(text):
        return None
    if _FEE_SUB_GUARD_RE.search(text):
        return None
    return match


def _surge_underflow_match(function_name: str, text: str) -> re.Match[str] | None:
    if not _SURGE_CONTEXT_RE.search(text) and "surge" not in function_name.lower():
        return None
    match = _SURGE_SUB_RE.search(text)
    if not match:
        return None
    if _SURGE_GUARD_RE.search(text):
        return None
    return match


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    for function_name, header, body, function_line in _split_functions(source):
        if not _VISIBLE_RE.search(header):
            continue
        text = f"{header}\n{body}"

        vote_match = _vote_narrow_match(function_name, text)
        if vote_match:
            line = function_line + text.count("\n", 0, vote_match.start())
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=function_name,
                    message=(
                        f"`{function_name}` narrows computed vote weight into "
                        "uint96 without a SafeCast or type(uint96).max bound."
                    ),
                )
            )
            continue

        fee_match = _fee_subtraction_match(function_name, text)
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
                        f"`{function_name}` subtracts a multiplied fee from "
                        "the enforced amount without proving fee <= amount."
                    ),
                )
            )
            continue

        surge_match = _surge_underflow_match(function_name, text)
        if surge_match:
            line = function_line + text.count("\n", 0, surge_match.start())
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=function_name,
                    message=(
                        f"`{function_name}` subtracts static fee from max surge "
                        "fee without a max >= static guard."
                    ),
                )
            )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
