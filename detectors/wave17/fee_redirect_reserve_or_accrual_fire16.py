"""
fee-redirect-reserve-or-accrual-fire16

Detects a narrow fee-redirect recall shape covering three source-backed
families:

1. AMM reserve math that uses raw reserves while fee accumulator state exists.
2. Public fee update or charge functions that skip an existing accrual helper.
3. Protocol fee share or sink functions that use configured receiver or share
   state without both zero-receiver and max-share guards.

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "fee-redirect-reserve-or-accrual-fire16"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b")

_FEE_ACCUMULATOR_RE = re.compile(
    r"\b(?:accruedFee|accruedFees|accumulatedFee|accumulatedFees|"
    r"launchpadFee|protocolFee|treasuryFee)\b",
    re.IGNORECASE,
)
_RESERVE_ENTRY_RE = re.compile(r"^(?:mint|burn|swap|_mint|_burn)$")
_RESERVE_USE_RE = re.compile(
    r"\b(?:reserve0|reserve1|_reserve0|_reserve1)\b|"
    r"\bbalanceOf\s*\[\s*address\s*\(\s*this\s*\)\s*\]|"
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
    re.IGNORECASE,
)
_RESERVE_GUARD_RE = re.compile(
    r"\b(?:realReserve|adjustedReserve|netReserve|feeAdjustedReserve|"
    r"subFees|_subtractFee)\b|"
    r"(?:\b(?:reserve0|reserve1|_reserve0|_reserve1|bal\w*)\b|"
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\))"
    r"\s*-\s*\b(?:accruedFee|accruedFees|accumulatedFee|"
    r"accumulatedFees|launchpadFee|protocolFee|treasuryFee)\b",
    re.IGNORECASE,
)

_ACCRUAL_HELPER_NAME_RE = re.compile(
    r"^(?:accrueFee|_accrue|updateFee|collectFee|syncFeeAccrual)$",
    re.IGNORECASE,
)
_FEE_UPDATE_ENTRY_RE = re.compile(
    r"^(?:setFee|changeFee|setRate|configureFee|chargeFee|collectFees|"
    r"updateFeeRate|setFeePerSecond|setFeePerShare)$",
    re.IGNORECASE,
)
_FEE_STATE_WRITE_RE = re.compile(
    r"\b(?:feePerSecond|feeRate|feePerShare|accumulatedFees|"
    r"accruedFees|feesAccrued)\s*(?:=|\+=|-=)",
    re.IGNORECASE,
)
_ACCRUAL_CALL_RE = re.compile(
    r"\b(?:accrueFee|_accrue|updateFee|collectFee|syncFeeAccrual)\s*\(",
    re.IGNORECASE,
)

_PROTOCOL_SHARE_NAME_RE = re.compile(r"^protocolFeeShare$")
_PROTOCOL_SINK_ENTRY_RE = re.compile(
    r"^(?:convertFees|distributeFees|claimFees|collectProtocolFees|"
    r"sweepProtocolFees|settleProtocolFees)$",
    re.IGNORECASE,
)
_PROTOCOL_CONFIG_RE = re.compile(
    r"\b(?:protocolFeeConfig|protocolShare|protocolFeeShare|feeConfig)\b",
    re.IGNORECASE,
)
_ZERO_RECEIVER_GUARD_RE = re.compile(
    r"\b(?:feeReceiver|protocolReceiver|governorReceiver|receiver|"
    r"feeRecipient)\s*==\s*address\s*\(\s*0\s*\)",
    re.IGNORECASE,
)
_MAX_SHARE_GUARD_RE = re.compile(
    r"\b(?:protocolShare|protocolFeeShare|share)\s*>\s*"
    r"MAX_PROTOCOL_FEE_SHARE\b|"
    r"\bMAX_PROTOCOL_FEE_SHARE\b\s*<\s*"
    r"\b(?:protocolShare|protocolFeeShare|share)\b",
    re.IGNORECASE,
)
_PROTOCOL_SINK_RE = re.compile(
    r"\b(?:safeTransfer|transfer|_mint|mint)\s*\([^;{}]*"
    r"\b(?:feeReceiver|protocolReceiver|governorReceiver|receiver|"
    r"feeRecipient)\b",
    re.IGNORECASE,
)
_PROTOCOL_FEE_MATH_RE = re.compile(
    r"\b(?:protocolShare|protocolFeeShare|share)\b\s*(?:\*|/)\s*"
    r"\b\w*(?:fee|amount|asset|share)\w*\b|"
    r"\b\w*(?:fee|amount|asset|share)\w*\b\s*(?:\*|/)\s*"
    r"\b(?:protocolShare|protocolFeeShare|share)\b",
    re.IGNORECASE,
)


def _split_functions(source: str) -> list[tuple[str, str, str, int]]:
    out: list[tuple[str, str, str, int]] = []
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


def _line_for(function_line: int, body: str, match: re.Match[str] | None) -> int:
    if match is None:
        return function_line
    return function_line + body.count("\n", 0, match.start())


def _has_accrual_helper(functions: list[tuple[str, str, str, int]]) -> bool:
    return any(_ACCRUAL_HELPER_NAME_RE.search(name) for name, _, _, _ in functions)


def _raw_reserve_fee_float(
    contract_source: str, function_name: str, body: str
) -> re.Match[str] | None:
    if not _RESERVE_ENTRY_RE.search(function_name):
        return None
    if not _FEE_ACCUMULATOR_RE.search(contract_source):
        return None
    reserve_use = _RESERVE_USE_RE.search(body)
    if reserve_use is None:
        return None
    if _RESERVE_GUARD_RE.search(body):
        return None
    return reserve_use


def _missing_fee_accrual(
    has_accrual_helper: bool, function_name: str, body: str
) -> re.Match[str] | None:
    if not has_accrual_helper:
        return None
    if not _FEE_UPDATE_ENTRY_RE.search(function_name):
        return None
    state_write = _FEE_STATE_WRITE_RE.search(body)
    if state_write is None:
        return None
    if _ACCRUAL_CALL_RE.search(body):
        return None
    return state_write


def _unguarded_protocol_share(function_name: str, body: str) -> re.Match[str] | None:
    if not _PROTOCOL_SHARE_NAME_RE.search(function_name):
        return None
    config = _PROTOCOL_CONFIG_RE.search(body)
    if config is None:
        return None
    has_zero_guard = bool(_ZERO_RECEIVER_GUARD_RE.search(body))
    has_max_guard = bool(_MAX_SHARE_GUARD_RE.search(body))
    if has_zero_guard and has_max_guard:
        return None
    return config


def _unguarded_protocol_sink(function_name: str, body: str) -> re.Match[str] | None:
    if not _PROTOCOL_SINK_ENTRY_RE.search(function_name):
        return None
    config = _PROTOCOL_CONFIG_RE.search(body)
    if config is None:
        return None
    if _PROTOCOL_SINK_RE.search(body) is None:
        return None
    if _PROTOCOL_FEE_MATH_RE.search(body) is None:
        return None
    has_zero_guard = bool(_ZERO_RECEIVER_GUARD_RE.search(body))
    has_max_guard = bool(_MAX_SHARE_GUARD_RE.search(body))
    if has_zero_guard and has_max_guard:
        return None
    return config


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    functions = _split_functions(source)
    has_accrual_helper = _has_accrual_helper(functions)
    findings: list[Finding] = []

    for function_name, header, body, function_line in functions:
        if not _PUBLIC_HEADER_RE.search(header):
            continue

        reason = ""
        reason_match: re.Match[str] | None = None

        reserve_match = _raw_reserve_fee_float(source, function_name, body)
        if reserve_match is not None:
            reason = (
                "uses raw reserve or self-balance math while fee accumulator "
                "state exists"
            )
            reason_match = reserve_match

        accrual_match = _missing_fee_accrual(
            has_accrual_helper, function_name, body
        )
        if reason_match is None and accrual_match is not None:
            reason = (
                "updates or charges fee state without first calling the "
                "available accrual helper"
            )
            reason_match = accrual_match

        share_match = _unguarded_protocol_share(function_name, body)
        if reason_match is None and share_match is not None:
            reason = (
                "uses protocol fee share config without both zero-receiver "
                "and max-share guards"
            )
            reason_match = share_match

        sink_match = _unguarded_protocol_sink(function_name, body)
        if reason_match is None and sink_match is not None:
            reason = (
                "routes protocol fees to a configured sink without both "
                "zero-receiver and max-share guards"
            )
            reason_match = sink_match

        if reason_match is None:
            continue

        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(function_line, body, reason_match),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=function_name,
                message=(
                    f"`{function_name}` {reason}. Materialize or isolate fee "
                    "state before pricing or redirecting protocol fees."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
