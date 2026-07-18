"""
flashloan-fee-underflow-floor-fire30

Focused Solidity recall lift for integer-overflow-clamp misses where
flashloan, fee, repayment, or spread math subtracts a discount, rebate,
credit, or repayment before bounding the result. The post-subtraction bound
does not protect Solidity 0.8 paths from reverting, and pre-0.8 or unchecked
paths can wrap before the clamp. A zero clamp can also silently waive the fee.

Source refs:
- reports/detector_lift_fire29_20260605/post_priorities_solidity.md
- reference/patterns.dsl/flashloan-fee-underflow-or-missing.yaml
- reference/patterns.dsl/fund-loss-value-math-external-transfer-fire10.yaml
- reference/patterns.dsl.r74_mined_cs/bad-debt-rounding-can-be-exploited-to-pay.yaml

Detector hits are candidate evidence only. A filing still needs source
existence, a real protocol path, a negative control, and R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "flashloan-fee-underflow-floor-fire30"
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
_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_CONTEXT_RE = re.compile(
    r"(?is)\b(?:amount|borrow|borrower|bps|BPS|cap|ceiling|charge|credit|"
    r"discount|fee|fees|flash|flashLoan|flashloan|floor|loan|maxFee|minFee|"
    r"notional|owed|premium|principal|rebate|repay|repayment|spread|surge|"
    r"waiver)\b"
)
_ENTRY_NAME_RE = re.compile(
    r"(?i)(?:borrow|charge|compute|discount|fee|flash|floor|loan|premium|"
    r"quote|rebate|repay|repayment|spread|surge)"
)
_SUBTRACTOR_STEM_RE = (
    r"discount|Discount|rebate|Rebate|credit|Credit|repay|Repay|"
    r"repayment|Repayment|waiver|Waiver|offset|Offset|refund|Refund|"
    r"coupon|Coupon|paid|Paid"
)
_SUBTRACTOR_NAME_RE = (
    rf"(?:[A-Za-z_][A-Za-z0-9_]*(?:{_SUBTRACTOR_STEM_RE})[A-Za-z0-9_]*|"
    rf"(?:{_SUBTRACTOR_STEM_RE})[A-Za-z0-9_]*)"
)
_SUBTRACTOR_CONTEXT_RE = re.compile(rf"(?is)\b(?:{_SUBTRACTOR_NAME_RE})\b")
_OUT_NAME_RE = (
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Fee|fee|Premium|premium|Spread|spread|Owed|"
    r"owed|Due|due|Repay|repay|Charge|charge|Net|net)[A-Za-z0-9_]*|"
    r"fee|premium|spread|owed|amountDue|repayRequired|requiredRepayment|"
    r"netAmount|netFee|effectiveFee|effectiveSpread)"
)
_BASE_CONTEXT_RE = (
    r"amount|base|borrow|BPS|bps|fee|flash|gross|loan|max|min|notional|"
    r"owed|premium|principal|rate|repay|spread|surge"
)

_SUBTRACT_ASSIGN_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<out>{_OUT_NAME_RE})\s*=\s*"
    rf"(?P<expr>[^;{{}}]{{0,360}}-\s*"
    rf"(?P<sub>{_SUBTRACTOR_NAME_RE})[^;{{}}]{{0,180}})\s*;"
)
_ZERO_CLAMP_RE = re.compile(
    rf"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    rf"(?P<out>{_OUT_NAME_RE})\s*=\s*"
    rf"(?P<expr>[^;{{}}?]{{1,260}}\?\s*[^;{{}}:]{{0,220}}-\s*"
    rf"(?P<sub>{_SUBTRACTOR_NAME_RE})[^;{{}}:]{{0,120}}:\s*"
    rf"(?:0|uint256\s*\(\s*0\s*\)|int256\s*\(\s*0\s*\))|"
    rf"[^;{{}}?]{{1,260}}\?\s*(?:0|uint256\s*\(\s*0\s*\)|"
    rf"int256\s*\(\s*0\s*\))\s*:\s*[^;{{}}:]{{0,220}}-\s*"
    rf"(?P<sub2>{_SUBTRACTOR_NAME_RE})[^;{{}}:]{{0,120}})\s*;"
)

_SAFE_ARITH_RE = re.compile(
    r"(?is)\b(?:Math\s*\.\s*mulDiv|FullMath\s*\.\s*mulDiv|"
    r"FixedPointMathLib\s*\.\s*mulDiv|mulDivUp|mulDivRoundingUp|"
    r"ceilDiv|divUp|roundUp|Rounding\s*\.\s*(?:Up|Ceil)|saturat)\b"
)
_FLOOR_GUARD_RE = re.compile(
    r"(?is)\b(?:MIN_[A-Za-z0-9_]*|minimum[A-Za-z0-9_]*|min[A-Za-z0-9_]*|"
    r"feeFloor|spreadFloor|dustFee|Math\s*\.\s*max\s*\(|max\s*\(\s*1\s*,|"
    r"ZeroFee|ZeroPremium|ZeroSpread)\b|"
    r"require\s*\([^;{}]*(?:fee|premium|spread)[^;{}]*(?:>\s*0|>=\s*1|!=\s*0)"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


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


def _window(text: str, start: int, end: int) -> str:
    return text[max(0, start - 620):min(len(text), end + 1000)]


def _is_fee_or_spread_path(fn: FunctionSlice, text: str) -> bool:
    return bool(
        (_ENTRY_NAME_RE.search(fn.name) or _CONTEXT_RE.search(text))
        and _CONTEXT_RE.search(text)
        and _SUBTRACTOR_CONTEXT_RE.search(text)
    )


def _has_pre_guard(text: str, sub_name: str, match_start: int) -> bool:
    before = text[:match_start]
    sub = re.escape(sub_name)
    context = _BASE_CONTEXT_RE
    require_left = re.search(
        rf"(?is)require\s*\([^;{{}}]*\b{sub}\b[^;{{}}]*(?:<=|<)"
        rf"[^;{{}}]*(?:{context}|maxCredit|raw|gross|base)",
        before,
    )
    require_right = re.search(
        rf"(?is)require\s*\([^;{{}}]*(?:{context}|maxCredit|raw|gross|base)"
        rf"[^;{{}}]*(?:>=|>)\s*\b{sub}\b",
        before,
    )
    revert_guard = re.search(
        rf"(?is)if\s*\([^;{{}}]*(?:\b{sub}\b[^;{{}}]*(?:>|>=)|"
        rf"(?:{context}|raw|gross|base)[^;{{}}]*(?:<|<=)\s*\b{sub}\b)"
        rf"[^;{{}}]*\)\s*(?:\{{[^{{}}]{{0,180}}revert\b|revert\b)",
        before,
    )
    floor_return = re.search(
        rf"(?is)if\s*\([^;{{}}]*(?:\b{sub}\b[^;{{}}]*(?:>|>=)|"
        rf"(?:{context}|raw|gross|base)[^;{{}}]*(?:<|<=)\s*\b{sub}\b)"
        rf"[^;{{}}]*\)\s*(?:\{{[^{{}}]{{0,220}}return[^;{{}}]*"
        rf"(?:MIN_|minimum|min|Floor|floor)|return[^;{{}}]*(?:MIN_|minimum|min|Floor|floor))",
        before,
    )
    min_bound = re.search(
        rf"(?is)(?:Math\s*\.\s*)?min\s*\(\s*\b{sub}\b\s*,|"
        rf"\b{sub}\b\s*=\s*(?:Math\s*\.\s*)?min\s*\(",
        before,
    )
    return bool(require_left or require_right or revert_guard or floor_return or min_bound)


def _has_post_bound(text: str, out_name: str, start: int) -> bool:
    tail = text[start:start + 1100]
    out = re.escape(out_name)
    return bool(
        re.search(
            rf"(?is)if\s*\([^;{{}}]*\b{out}\b[^;{{}}]*(?:<|>|<=|>=)"
            rf"[^;{{}}]*(?:min|max|floor|cap|limit|amount|principal|spread|fee)"
            rf"[^;{{}}]*\)\s*(?:\{{[^{{}}]{{0,220}}\b{out}\b\s*=|\b{out}\b\s*=)",
            tail,
        )
        or re.search(rf"(?is)\b{out}\b\s*=\s*(?:Math\s*\.\s*)?(?:min|max)\s*\(", tail)
    )


def _expr_has_context(expr: str) -> bool:
    return bool(
        re.search(
            r"(?is)(?:amount|base|borrow|BPS|bps|fee|Fee|flash|gross|loan|"
            r"max|min|notional|owed|premium|principal|rate|repay|spread|"
            r"Spread|surge)",
            expr,
        )
    )


def _subtract_before_bound_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_fee_or_spread_path(fn, text):
        return None

    for match in _SUBTRACT_ASSIGN_RE.finditer(text):
        expr = match.group("expr")
        sub_name = match.group("sub")
        out_name = match.group("out")
        if not _expr_has_context(expr):
            continue
        if _has_pre_guard(text, sub_name, match.start()):
            continue
        if _SAFE_ARITH_RE.search(_window(text, match.start(), match.end())):
            continue
        if not _has_post_bound(text, out_name, match.end()):
            continue
        return match
    return None


def _zero_clamp_match(fn: FunctionSlice, text: str) -> re.Match[str] | None:
    if not _is_fee_or_spread_path(fn, text):
        return None
    if _FLOOR_GUARD_RE.search(text):
        return None
    for match in _ZERO_CLAMP_RE.finditer(text):
        sub_name = match.group("sub") or match.group("sub2")
        if not sub_name:
            continue
        if _has_pre_guard(text, sub_name, match.start()):
            continue
        if not _CONTEXT_RE.search(_window(text, match.start(), match.end())):
            continue
        return match
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []

    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"

        zero_clamp = _zero_clamp_match(fn, text)
        if zero_clamp:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, zero_clamp),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` discounts fee or spread math to zero "
                        "instead of enforcing a nonzero floor or reverting."
                    ),
                )
            )
            continue

        subtract_before_bound = _subtract_before_bound_match(fn, text)
        if subtract_before_bound:
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(fn.function_line, text, subtract_before_bound),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` subtracts a discount, rebate, credit, "
                        "or repayment before bounding the fee, spread, or "
                        "repayment result."
                    ),
                )
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
