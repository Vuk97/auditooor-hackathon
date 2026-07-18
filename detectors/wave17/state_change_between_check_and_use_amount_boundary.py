"""
state-change-between-check-and-use-amount-boundary.

Regex API detector for the narrow FoT / balance-delta recall gap inside the
state-change-between-check-and-use class. It reports AMM-style functions that
price or validate value from a nominal `amountIn` before or across a token
balance boundary, then read the contract's post-effect balance without deriving
the actual received delta.

This intentionally does not model generic CEI. It requires all of:
  - an `amountIn`-style nominal input;
  - reserve or pool balance math;
  - a self `balanceOf(address(this))` read after the nominal amount math;
  - a value transfer or invariant check tied to the post-effect balance;
  - no actual-received / balance-delta derivation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "state-change-between-check-and-use-amount-boundary"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_AMOUNT_IN_RE = re.compile(r"(?i)\bamount[01]?In\b")
_RESERVE_RE = re.compile(r"(?i)\b(?:reserve[01]?|getReserves|kInvariant|constantProduct)\b")
_SELF_BALANCE_RE = re.compile(
    r"(?i)\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
)
_TRANSFER_RE = re.compile(
    r"(?i)\b(?:safeTransferFrom|transferFrom|safeTransfer|transfer)\s*\("
)
_NOMINAL_AMOUNT_MATH_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:amount[01]?Out[A-Za-z0-9_]*|quoted[A-Za-z0-9_]*|output[A-Za-z0-9_]*)"
    r"\s*=\s*[^;]*\bamount[01]?In\b[^;]*(?:reserve|balance)|"
    r"\bamount[01]?In\b\s*[*\/]\s*[^;]*(?:reserve|balance)|"
    r"\b(?:reserve|balance)[A-Za-z0-9_]*\b\s*[*\/]\s*\bamount[01]?In\b"
    r")"
)
_POST_BALANCE_CHECK_RE = re.compile(
    r"(?is)"
    r"\brequire\s*\([^;]*(?:newBal[01]?|balance[01]?)[^;]*"
    r"(?:reserve[01]?|kInvariant|constantProduct)[^;]*\)"
)
_FRESH_DELTA_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:actualReceived|receivedDelta|deltaIn|balanceDelta|netReceived|"
    r"supportingFeeOnTransfer|feeOnTransfer|balanceAfter|balanceBefore)\b|"
    r"\bamount[01]?In\b\s*=\s*[^;]*(?:balance|newBal)[A-Za-z0-9_]*\s*(?:>|-)|"
    r"\b(?:received|credited)\b\s*=\s*[^;]*(?:balance|newBal)[A-Za-z0-9_]*\s*-"
    r")"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _split_functions(source: str) -> List[tuple[str, str, int]]:
    out: List[tuple[str, str, int]] = []
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

        body = source[body_start + 1:k - 1]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append((name, body, body_line))
        pos = k
    return out


def _has_stale_nominal_amount_boundary(body: str) -> tuple[bool, int]:
    stripped = _strip_comments_and_strings(body)
    if not _AMOUNT_IN_RE.search(stripped):
        return False, 0
    if not _RESERVE_RE.search(stripped):
        return False, 0
    if not _SELF_BALANCE_RE.search(stripped):
        return False, 0
    if not _TRANSFER_RE.search(stripped):
        return False, 0
    if _FRESH_DELTA_RE.search(stripped):
        return False, 0

    nominal = _NOMINAL_AMOUNT_MATH_RE.search(stripped)
    if not nominal:
        return False, 0

    later = stripped[nominal.end():]
    has_post_balance = _SELF_BALANCE_RE.search(later) is not None
    has_post_check = _POST_BALANCE_CHECK_RE.search(later) is not None
    if not (has_post_balance or has_post_check):
        return False, 0

    return True, body.count("\n", 0, nominal.start())


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    if "amount" not in source or "balanceOf" not in source:
        return findings

    for function_name, body, body_line in _split_functions(source):
        matched, line_offset = _has_stale_nominal_amount_boundary(body)
        if not matched:
            continue
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=body_line + line_offset,
                severity="Medium",
                function=function_name,
                message=(
                    f"`{function_name}` uses a nominal amountIn value in reserve "
                    "or output math, crosses a token balance boundary, and then "
                    "reads post-effect balances without deriving actual received "
                    "delta. This is the FoT-style state-change-between-check-and-use "
                    "amount boundary."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME"]
