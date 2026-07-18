"""
balancer-surge-fee-underflow-fire27

Fire27 Solidity detector for Balancer-style surge fee, dynamic fee, and pool
imbalance math where inverted subtraction or zero-clamp branches can suppress
fees during stress.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a4dc5fcabec4193
- context_pack_hash: 5a4dc5fcabec419385f40cc3f83d3a24f63a01e0d5c301ab1ef08763094a3fe5
- source ref: reference/patterns.dsl/fx-balancer-surge-fee-underflow.yaml
- source ref: reference/patterns.dsl/flashloan-fee-underflow-or-missing.yaml
- source ref: reference/patterns.dsl/fx-euler-irm-kink-type-truncation.yaml
- attack_class: integer-overflow-clamp

The detector requires pool, fee, and surge or imbalance vocabulary. Hits are
candidate evidence only. They are NOT_SUBMIT_READY and cannot be cited as
exploit proof without a real in-scope path, source existence, a negative
control, and R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "balancer-surge-fee-underflow-fire27"
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


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")

_POOL_WORD_RE = re.compile(
    r"(?is)(?:balancer|pool|vault|stable|weighted|liquidity|reserve|"
    r"balance|token|invariant|bpt|amp)"
)
_FEE_WORD_RE = re.compile(
    r"(?is)(?:fee|fees|swapFee|staticFee|staticSwapFee|baseFee|"
    r"dynamicFee|surgeFee|protocolFee|feeBps|feeRate|feeDelta|"
    r"feeRange|surgeRange|maxSurgeFee|staticSwapFeePercentage|"
    r"staticFeePercentage)"
)
_STRESS_WORD_RE = re.compile(
    r"(?is)(?:surge|imbalance|target|ratio|deviation|stress|threshold|"
    r"utilization|utilisation|outOfBalance|balanceDelta)"
)
_STRESS_BRANCH_WORD_RE = re.compile(
    r"(?is)(?:imbalance|deviation|ratio|current|actual|pool|balance|"
    r"reserve|surge|stress|utilization|utilisation)"
)
_TARGET_WORD_RE = re.compile(
    r"(?is)(?:target|ideal|balanced|expected|threshold|safe|peg)"
)
_CURRENT_WORD_RE = re.compile(
    r"(?is)(?:current|actual|pool|balance|reserve|observed|measured|"
    r"live|imbalanced|deviation|imbalance)"
)
_MAX_FEE_WORD_RE = re.compile(
    r"(?is)\b(?:max[A-Za-z0-9_]*(?:Fee|Surge|Bps|Percentage)|feeCap|"
    r"surgeMax|maxDynamicFee|maxSwapFee|maxSurgeFeePercentage)\b"
)
_STATIC_FEE_WORD_RE = re.compile(
    r"(?is)\b(?:static[A-Za-z0-9_]*(?:Fee|Bps|Percentage)|"
    r"staticSwapFeePercentage|base[A-Za-z0-9_]*(?:Fee|Bps|Percentage)|"
    r"min[A-Za-z0-9_]*(?:Fee|Bps|Percentage)|feeFloor|floorFee)\b"
)
_LOW_FEE_RETURN_RE = re.compile(
    r"(?is)\b(?:return\s+(?:0|base\w*Fee\w*|static\w*Fee\w*|"
    r"staticSwapFeePercentage|min\w*Fee\w*|feeFloor)\s*;|"
    r"(?:dynamicFee|surgeFee|feeDelta|feeRange|surgeRange)\w*\s*=\s*0\s*;)"
)
_SAFE_FORM_RE = re.compile(
    r"(?is)\b(?:Math\s*\.\s*mulDiv|FullMath\s*\.\s*mulDiv|"
    r"FixedPointMathLib\s*\.\s*mulDiv|mulDivUp|mulDivRoundingUp|"
    r"Rounding\s*\.\s*Up|ceilDiv|divUp|roundUp|absDiff|absoluteDelta|"
    r"Math\s*\.\s*max\s*\(|Math\s*\.\s*min\s*\(|saturat)\b"
)
_EXPLICIT_MAX_STATIC_GUARD_RE = re.compile(
    r"(?is)(?:"
    r"require\s*\([^;{}]*(?:max\w*Fee\w*|maxSurgeFee\w*|feeCap)"
    r"[^;{}]*(?:>=|>)\s*(?:static\w*Fee\w*|staticSwapFeePercentage|"
    r"base\w*Fee\w*|min\w*Fee\w*|feeFloor)|"
    r"require\s*\([^;{}]*(?:static\w*Fee\w*|staticSwapFeePercentage|"
    r"base\w*Fee\w*|min\w*Fee\w*|feeFloor)[^;{}]*(?:<=|<)"
    r"\s*(?:max\w*Fee\w*|maxSurgeFee\w*|feeCap)|"
    r"if\s*\([^;{}]*(?:max\w*Fee\w*|maxSurgeFee\w*|feeCap)"
    r"[^;{}]*<[^;{}]*(?:static\w*Fee\w*|staticSwapFeePercentage|"
    r"base\w*Fee\w*|min\w*Fee\w*|feeFloor)[^;{}]*\)"
    r"\s*(?:\{[^{}]{0,220})?(?:return\s+(?:static\w*Fee\w*|"
    r"staticSwapFeePercentage|base\w*Fee\w*|min\w*Fee\w*|feeFloor)|revert|throw))"
)
_RETURN_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:return|dynamicFee|surgeFee|swapFee|feeDelta|feeRange|"
    r"surgeRange|protocolFees|staticSwapFeePercentage|baseFee)\b"
)

_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:Range|Delta|Fee|Surge|Imbalance|"
    r"Deviation|Distance|Ratio|Balance|Bps|Percentage)[A-Za-z0-9_]*)"
    r"\s*=\s*(?P<expr>[^;{}]{1,420})\s*;"
)
_TERNARY_ZERO_ASSIGN_RE = re.compile(
    r"(?is)\b(?:uint(?:256|128|64)?|int(?:256|128|64)?|var)?\s*"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:Range|Delta|Fee|Surge|Imbalance|"
    r"Deviation|Distance|Ratio|Balance|Bps|Percentage)[A-Za-z0-9_]*)"
    r"\s*=\s*(?P<cond>[^;{}?]{1,260}(?:<|>|<=|>=)[^;{}?]{1,260})\?"
    r"(?P<then>[^;{}:]{1,260}):(?P<else>[^;{}]{1,260})\s*;"
)
_STRESS_LOW_RETURN_RE = re.compile(
    r"(?is)if\s*\((?P<cond>[^)]{1,260}(?:>|>=)[^)]{1,260})\)"
    r"\s*(?:\{[^{}]{0,220})?(?P<body>return\s+(?:0|base\w*Fee\w*|"
    r"static\w*Fee\w*|staticSwapFeePercentage|min\w*Fee\w*|feeFloor)\s*;|"
    r"(?:dynamicFee|surgeFee|feeDelta|feeRange|surgeRange)\w*\s*=\s*0\s*;)"
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
            pos = max(i, j)
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


def _window(text: str, start: int, end: int, before: int = 500, after: int = 900) -> str:
    return text[max(0, start - before):min(len(text), end + after)]


def _is_pool_fee_stress_context(text: str) -> bool:
    return bool(_POOL_WORD_RE.search(text) and _FEE_WORD_RE.search(text) and _STRESS_WORD_RE.search(text))


def _has_fee_sink_after(text: str, var_name: str, start: int) -> bool:
    tail = text[start:start + 1400]
    pattern = re.compile(
        rf"(?is)(?:"
        rf"\breturn\b[^;{{}}]*\b{re.escape(var_name)}\b|"
        rf"\b(?:dynamicFee|surgeFee|swapFee|feeDelta|protocolFees|"
        rf"calculatedFee|chargedFee)\w*\s*(?:=|\+=)[^;{{}}]*\b{re.escape(var_name)}\b|"
        rf"\b(?:staticSwapFeePercentage|baseFee|staticFeePercentage)\b"
        rf"[^;{{}}]*\+\s*\b{re.escape(var_name)}\b|"
        rf"\b{re.escape(var_name)}\b[^;{{}}]*\+\s*"
        rf"\b(?:staticSwapFeePercentage|baseFee|staticFeePercentage)\b)"
    )
    return bool(pattern.search(tail))


def _has_max_static_guard(text: str) -> bool:
    return bool(_EXPLICIT_MAX_STATIC_GUARD_RE.search(text))


def _is_max_minus_static(expr: str) -> bool:
    if "-" not in expr:
        return False
    left, right = expr.split("-", 1)
    return bool(_MAX_FEE_WORD_RE.search(left) and _STATIC_FEE_WORD_RE.search(right))


def _is_target_minus_current(expr: str) -> bool:
    if "-" not in expr:
        return False
    left, right = expr.split("-", 1)
    return bool(_TARGET_WORD_RE.search(left) and _CURRENT_WORD_RE.search(right))


def _has_order_guard(text: str, expr: str) -> bool:
    if _SAFE_FORM_RE.search(text):
        return True
    if _is_max_minus_static(expr) and _has_max_static_guard(text):
        return True
    order_guard = re.compile(
        r"(?is)(?:require|if)\s*\([^;{}]*(?:target|ideal|balanced|expected|"
        r"threshold|safe|peg|max\w*Fee\w*|maxSurgeFee\w*|feeCap)"
        r"[^;{}]*(?:>=|>|<|<=)[^;{}]*(?:current|actual|pool|balance|"
        r"reserve|observed|static\w*Fee\w*|base\w*Fee\w*|min\w*Fee\w*|feeFloor)"
        r"[^;{}]*\)"
    )
    return bool(order_guard.search(text))


def _zero_branch(branch: str) -> bool:
    return bool(re.fullmatch(r"\s*(?:0|uint256\s*\(\s*0\s*\)|int256\s*\(\s*0\s*\))\s*", branch))


def _nonzero_branch_underflow_shape(branch: str) -> bool:
    return bool("-" in branch and (_is_max_minus_static(branch) or _is_target_minus_current(branch)))


def _condition_is_stress_suppression(cond: str) -> bool:
    if not _STRESS_BRANCH_WORD_RE.search(cond):
        return False
    if not _TARGET_WORD_RE.search(cond):
        return False
    return bool(re.search(r"(?:current|actual|pool|balance|reserve|imbalance|deviation)[^<>=]*(?:>|>=)", cond, re.I | re.S))


def _find_zero_clamp(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _TERNARY_ZERO_ASSIGN_RE.finditer(text):
        cond = match.group("cond")
        then_branch = match.group("then")
        else_branch = match.group("else")
        window = _window(text, match.start(), match.end())
        if not _is_pool_fee_stress_context(window):
            continue
        if _has_max_static_guard(text) and _is_max_minus_static(then_branch + else_branch):
            continue
        zero_then = _zero_branch(then_branch)
        zero_else = _zero_branch(else_branch)
        if not zero_then and not zero_else:
            continue
        nonzero = else_branch if zero_then else then_branch
        if not _nonzero_branch_underflow_shape(nonzero):
            continue
        if not _has_fee_sink_after(text, match.group("var"), match.end()):
            continue
        if _condition_is_stress_suppression(cond):
            return match, "a stress-side imbalance branch that clamps the fee delta to zero"
        if _is_max_minus_static(nonzero):
            return match, "a max-below-static surge fee range that clamps the dynamic range to zero"
    return None


def _find_direct_underflow(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _ASSIGN_RE.finditer(text):
        expr = match.group("expr")
        window = _window(text, match.start(), match.end())
        if not _is_pool_fee_stress_context(window):
            continue
        if not (_is_max_minus_static(expr) or _is_target_minus_current(expr)):
            continue
        if _has_order_guard(text, expr):
            continue
        if not _has_fee_sink_after(text, match.group("var"), match.end()):
            continue
        if _is_max_minus_static(expr):
            return match, "an unchecked max-surge minus static-fee subtraction"
        return match, "an unchecked target minus current pool-imbalance subtraction"
    return None


def _find_stress_low_return(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    for match in _STRESS_LOW_RETURN_RE.finditer(text):
        cond = match.group("cond")
        window = _window(text, match.start(), match.end())
        if not _is_pool_fee_stress_context(window):
            continue
        if not _condition_is_stress_suppression(cond):
            continue
        if not _LOW_FEE_RETURN_RE.search(match.group("body")):
            continue
        return match, "a stress branch that returns base, static, or zero fee"
    return None


def _add_finding(
    findings: list[Finding],
    *,
    file_path: str,
    fn: FunctionSlice,
    line: int,
    reason: str,
) -> None:
    findings.append(
        Finding(
            detector=DETECTOR_NAME,
            file=file_path,
            line=line,
            severity=DETECTOR_SEVERITY_DEFAULT,
            function=fn.name,
            message=(
                f"`{fn.name}` has {reason}. Balancer-style surge fee and "
                "dynamic fee math should charge stress-side imbalance with "
                "bounded subtraction, an explicit floor, or absolute-delta "
                "math instead of underflowing or clamping to zero. "
                "NOT_SUBMIT_READY."
            ),
        )
    )


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []

    for fn in _split_functions(stripped):
        text = f"{fn.header}\n{fn.body}"
        if not _is_pool_fee_stress_context(text):
            continue
        if not _RETURN_FEE_CONTEXT_RE.search(text):
            continue

        zero_clamp = _find_zero_clamp(fn, text)
        if zero_clamp:
            match, reason = zero_clamp
            _add_finding(
                findings,
                file_path=file_path,
                fn=fn,
                line=_line_for(fn.function_line, text, match),
                reason=reason,
            )
            continue

        direct_underflow = _find_direct_underflow(fn, text)
        if direct_underflow:
            match, reason = direct_underflow
            _add_finding(
                findings,
                file_path=file_path,
                fn=fn,
                line=_line_for(fn.function_line, text, match),
                reason=reason,
            )
            continue

        stress_low_return = _find_stress_low_return(fn, text)
        if stress_low_return:
            match, reason = stress_low_return
            _add_finding(
                findings,
                file_path=file_path,
                fn=fn,
                line=_line_for(fn.function_line, text, match),
                reason=reason,
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
