"""
irm-overflow-returns-zero-rate-fire27

Fire27 Solidity detector for IRM and fee-curve arithmetic where overflow,
narrowing, or high-utilization fallback branches return zero or a lower than
expected rate.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a4dc5fcabec4193
- context_pack_hash: 5a4dc5fcabec419385f40cc3f83d3a24f63a01e0d5c301ab1ef08763094a3fe5
- source ref: reference/patterns.dsl/fx-silo-irm-overflow-returns-zero-k.yaml
- source ref: reference/patterns.dsl/fx-euler-irm-kink-type-truncation.yaml
- source ref: reference/patterns.dsl/fx-balancer-surge-fee-underflow.yaml
- attack_class: integer-overflow-clamp

The detector is candidate evidence only. It is NOT_SUBMIT_READY and cannot be
cited as exploit proof without a real in-scope path, negative control, source
existence, and R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "irm-overflow-returns-zero-rate-fire27"
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
_CALLABLE_HEADER_RE = re.compile(
    r"\b(?:(?:function)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)|(?P<ctor>constructor))\s*\("
)
_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public|internal)\b")
_MODEL_CONTEXT_RE = re.compile(
    r"(?is)\b(?:IRM|interest|borrowRate|supplyRate|rate|utilization|"
    r"utilisation|util|kink|slope|fee|surgeFee|staticFee|baseRate|"
    r"model|curve|premium|borrow|silo|maxSurgeFee|optimalUtilization|"
    r"targetUtilization)\b"
)
_LOW_UTIL_ZERO_RE = re.compile(
    r"(?is)if\s*\([^)]*(?:util(?:ization|isation)?|totalBorrow|borrowed|debt)"
    r"[^)]*(?:==\s*0|<\s*=?\s*(?:MIN|min))[^)]*\)\s*\{?\s*return\s+0\s*;"
)
_SAFE_SATURATION_RE = re.compile(
    r"(?is)(?:return\s*\(\s*0\s*,\s*(?:cfg\.)?kmin\s*\)|"
    r"return\s+(?:staticFeePercentage|baseRate|minimumRate|minRate|kmin|MAX_RATE|"
    r"maxRate)\s*;|Math\s*\.\s*(?:min|max)\s*\(|mulDiv\s*\(|"
    r"FullMath\s*\.\s*mulDiv|FixedPointMathLib\s*\.\s*mulDiv)"
)
_OVERFLOW_ZERO_RE = re.compile(
    r"(?is)(?:wouldOverflow\w*|overflows?|overflowed|SafeCast|toInt(?:256)?|"
    r"type\s*\(\s*int256\s*\)\s*\.\s*max|unchecked)"
    r"[\s\S]{0,420}"
    r"(?:return\s*\(\s*0\s*,\s*0\s*\)|return\s+0\s*;|"
    r"\b(?:rate|borrowRate|supplyRate|interestRate|fee|surgeFee|k)\s*=\s*0\s*;)"
)
_HIGH_UTIL_ZERO_RE = re.compile(
    r"(?is)if\s*\([^)]*(?:util(?:ization|isation)?|borrowed|totalBorrow|debt|liquidity)"
    r"[^)]*(?:>|>=)[^)]*(?:kink|optimal|target|max|BPS|WAD|RAY|ONE|1e18|"
    r"UTILIZATION_PRECISION)[^)]*\)\s*\{?[\s\S]{0,220}"
    r"(?:return\s+(?:0|ZERO_RATE)\s*;|return\s*\(\s*0\s*,\s*0\s*\)|"
    r"\b(?:rate|borrowRate|supplyRate|interestRate|fee|surgeFee)\s*=\s*0\s*;)"
)
_FEE_MAX_BELOW_STATIC_ZERO_RE = re.compile(
    r"(?is)if\s*\([^)]*(?:max\w*Fee\w*|maxSurgeFee\w*|feeCap)"
    r"[^)]*<[^)]*(?:static\w*Fee\w*|base\w*Fee\w*|min\w*Fee\w*)[^)]*\)"
    r"\s*\{?[\s\S]{0,180}(?:return\s+0\s*;|\b(?:fee|surgeFee)\w*\s*=\s*0\s*;)"
)
_WIDE_PARAM_RE = re.compile(r"(?is)\buint256\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
_NARROW_CAST_RE = re.compile(
    r"(?is)\b(?P<target>(?:kink|slope|baseRate|borrowRate|supplyRate|"
    r"interestRate|fee|utilization|utilisation)\w*)\s*=\s*"
    r"uint(?P<bits>8|16|24|32|40|48|56|64|96|128)\s*\(\s*"
    r"(?P<arg>(?:kink|slope|baseRate|borrowRate|supplyRate|interestRate|"
    r"fee|utilization|utilisation)\w*_?)\s*\)"
)
_BARE_ASSIGN_RE = re.compile(
    r"(?is)\b(?P<target>(?:kink|slope|baseRate|borrowRate|supplyRate|"
    r"interestRate|fee|utilization|utilisation)\w*)\s*=\s*"
    r"(?P<arg>(?:kink|slope|baseRate|borrowRate|supplyRate|interestRate|"
    r"fee|utilization|utilisation)\w*_?)\s*;"
)
_NARROW_STATE_TEMPLATE = (
    r"(?is)\buint(?P<bits>8|16|24|32|40|48|56|64|96|128)\s+"
    r"(?:(?:public|private|internal|immutable|constant)\s+)*{name}\b"
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
        match = _CALLABLE_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name") or "constructor"
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


def _has_model_context(text: str) -> bool:
    return bool(_MODEL_CONTEXT_RE.search(text))


def _has_safe_narrowing_guard(text: str, arg: str, bits: str) -> bool:
    escaped = re.escape(arg)
    type_max = rf"type\s*\(\s*uint{bits}\s*\)\s*\.\s*max"
    guard = re.compile(
        rf"(?is)(?:require|if)\s*\([^;{{}}]*(?:"
        rf"{escaped}\s*<=\s*{type_max}|{type_max}\s*>=\s*{escaped}|"
        rf"{escaped}\s*>\s*{type_max}|{type_max}\s*<\s*{escaped})[^;{{}}]*\)"
    )
    return bool(guard.search(text) or re.search(rf"(?is)\btoUint{bits}\s*\(", text))


def _wide_params(header: str) -> set[str]:
    return {match.group("name") for match in _WIDE_PARAM_RE.finditer(header)}


def _source_narrow_state_bits(source: str, name: str) -> str | None:
    pattern = re.compile(_NARROW_STATE_TEMPLATE.format(name=re.escape(name)))
    match = pattern.search(source)
    return match.group("bits") if match else None


def _is_callable_entry(fn: FunctionSlice) -> bool:
    return fn.name == "constructor" or bool(_VISIBILITY_RE.search(fn.header))


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
                f"`{fn.name}` has {reason}. Interest-rate and fee-curve "
                "overflow handling must saturate to kmin, base rate, static "
                "fee, or an explicit max bound instead of returning zero or a "
                "narrowed lower value. NOT_SUBMIT_READY."
            ),
        )
    )


def _find_zero_rate_clamp(fn: FunctionSlice, text: str) -> tuple[re.Match[str], str] | None:
    fee_match = _FEE_MAX_BELOW_STATIC_ZERO_RE.search(text)
    if fee_match:
        return fee_match, "a fee curve max-below-static branch that clamps to zero"

    overflow_match = _OVERFLOW_ZERO_RE.search(text)
    if overflow_match and not _SAFE_SATURATION_RE.search(text):
        return overflow_match, "an overflow guard that returns a zero rate or k=0"

    high_util_match = _HIGH_UTIL_ZERO_RE.search(text)
    if high_util_match and not _LOW_UTIL_ZERO_RE.search(text):
        return high_util_match, "a high-utilization branch that returns zero rate"

    return None


def _find_narrowing_truncation(
    source: str, fn: FunctionSlice, text: str
) -> tuple[re.Match[str], str] | None:
    wide_params = _wide_params(fn.header)
    for match in _NARROW_CAST_RE.finditer(text):
        arg = match.group("arg")
        bits = match.group("bits")
        if arg not in wide_params:
            continue
        if _has_safe_narrowing_guard(text, arg, bits):
            continue
        return match, f"an unchecked uint256 to uint{bits} narrowing cast on {arg}"

    for match in _BARE_ASSIGN_RE.finditer(text):
        arg = match.group("arg")
        target = match.group("target")
        if arg not in wide_params:
            continue
        bits = _source_narrow_state_bits(source, target)
        if bits is None:
            continue
        if _has_safe_narrowing_guard(text, arg, bits):
            continue
        return match, f"an unchecked assignment of uint256 {arg} into uint{bits} {target}"

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    stripped = _strip_comments_and_strings(source)
    findings: list[Finding] = []

    for fn in _split_functions(stripped):
        if not _is_callable_entry(fn):
            continue
        text = f"{fn.header}\n{fn.body}"
        if not _has_model_context(text):
            continue

        zero_match = _find_zero_rate_clamp(fn, text)
        if zero_match is not None:
            match, reason = zero_match
            _add_finding(
                findings,
                file_path=file_path,
                fn=fn,
                line=_line_for(fn.function_line, text, match),
                reason=reason,
            )
            continue

        narrow_match = _find_narrowing_truncation(stripped, fn, text)
        if narrow_match is not None:
            match, reason = narrow_match
            _add_finding(
                findings,
                file_path=file_path,
                fn=fn,
                line=_line_for(fn.function_line, text, match),
                reason=reason,
            )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
