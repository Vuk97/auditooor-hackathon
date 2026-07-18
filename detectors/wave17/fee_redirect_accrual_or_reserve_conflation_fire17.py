"""
fee-redirect-accrual-or-reserve-conflation-fire17

Solidity same-class recall detector for fee-redirect shapes where fee state is
priced through the wrong reserve, skipped during accrual, routed to an
unguarded protocol sink, or redirected to a caller supplied fee recipient.

Detector hits are candidate evidence only. They do not prove exploitability or
filing readiness without a real protocol path, impact proof, and negative
control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "fee-redirect-accrual-or-reserve-conflation-fire17"
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
    body_line: int


_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
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

_ADDRESS_PARAM_RE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_DYNAMIC_FEE_SINK_NAME_RE = re.compile(
    r"(?i)^(?:referral|referrer|affiliate|affiliateReceiver|rebateReceiver|"
    r"rewardRecipient|rewardReceiver|feeReferral|feeRecipient|feeReceiver|"
    r"feeCollector|collector|beneficiary)$"
)
_FEE_CONTEXT_RE = re.compile(
    r"\b(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|"
    r"referralFee|referrerFee|affiliateFee|rebateFee|feeAmount|feeBps|"
    r"feeRate|BPS|fee)\b",
    re.IGNORECASE,
)
_FEE_VALUE_NAME = (
    r"(?:referralFee|referrerFee|affiliateFee|rebateFee|rewardFee|"
    r"protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|"
    r"feeAmount|fee)"
)
_DYNAMIC_SINK_GUARD_RE = re.compile(
    r"(?:approvedReferral|allowedReferral|trustedReferral|referralWhitelist|"
    r"referrerWhitelist|affiliateWhitelist|isReferralApproved|"
    r"IsAllowedRewardSink|MAX_REFERRAL|MAX_AFFILIATE|MAX_REBATE|"
    r"referralVault|referralTreasury|configuredReferral|protocolReferral|"
    r"defaultReferral|onlyOwner|onlyRole|onlyAdmin|onlyGovernor|_checkRole)",
    re.IGNORECASE,
)


def _strip_comments(source: str) -> str:
    source = re.sub(r"//[^\n]*", "", source)
    return re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        source,
        flags=re.S,
    )


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


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

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for(fn: FunctionSlice, match: re.Match[str] | None) -> int:
    if match is None:
        return fn.body_line
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _has_accrual_helper(functions: list[FunctionSlice]) -> bool:
    return any(_ACCRUAL_HELPER_NAME_RE.search(fn.name) for fn in functions)


def _address_sink_params(header: str) -> set[str]:
    params: set[str] = set()
    for match in _ADDRESS_PARAM_RE.finditer(header):
        name = match.group("name")
        if _DYNAMIC_FEE_SINK_NAME_RE.search(name):
            params.add(name)
    return params


def _routes_fee_to_param(body: str, param: str) -> re.Match[str] | None:
    sink = re.escape(param)
    patterns = [
        rf"\b(?:safeTransfer|transfer|sendValue|mint|_mint)\s*\(\s*{sink}\s*,\s*{_FEE_VALUE_NAME}\b",
        rf"\bpayable\s*\(\s*{sink}\s*\)\s*\.\s*(?:transfer|send)\s*\(\s*{_FEE_VALUE_NAME}\b",
        rf"\b(?:payable\s*\(\s*{sink}\s*\)|{sink})\s*\.\s*call\s*\{{\s*value\s*:\s*{_FEE_VALUE_NAME}\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, body, flags=re.IGNORECASE | re.S)
        if match is not None:
            return match
    return None


def _raw_reserve_fee_float(source: str, fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _RESERVE_ENTRY_RE.search(fn.name):
        return None
    if not _FEE_ACCUMULATOR_RE.search(source):
        return None
    reserve_use = _RESERVE_USE_RE.search(fn.body)
    if reserve_use is None:
        return None
    if _RESERVE_GUARD_RE.search(fn.body):
        return None
    return ("uses raw reserve or self-balance math while fee accumulator state exists", reserve_use)


def _missing_fee_accrual(has_accrual_helper: bool, fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not has_accrual_helper:
        return None
    if not _FEE_UPDATE_ENTRY_RE.search(fn.name):
        return None
    state_write = _FEE_STATE_WRITE_RE.search(fn.body)
    if state_write is None:
        return None
    if _ACCRUAL_CALL_RE.search(fn.body):
        return None
    return ("updates or charges fee state without first calling the accrual helper", state_write)


def _unguarded_protocol_share(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _PROTOCOL_SHARE_NAME_RE.search(fn.name):
        return None
    config = _PROTOCOL_CONFIG_RE.search(fn.body)
    if config is None:
        return None
    has_zero_guard = bool(_ZERO_RECEIVER_GUARD_RE.search(fn.body))
    has_max_guard = bool(_MAX_SHARE_GUARD_RE.search(fn.body))
    if has_zero_guard and has_max_guard:
        return None
    return ("uses protocol fee share config without both zero-receiver and max-share guards", config)


def _unguarded_protocol_sink(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _PROTOCOL_SINK_ENTRY_RE.search(fn.name):
        return None
    config = _PROTOCOL_CONFIG_RE.search(fn.body)
    if config is None:
        return None
    if _PROTOCOL_SINK_RE.search(fn.body) is None:
        return None
    if _PROTOCOL_FEE_MATH_RE.search(fn.body) is None:
        return None
    has_zero_guard = bool(_ZERO_RECEIVER_GUARD_RE.search(fn.body))
    has_max_guard = bool(_MAX_SHARE_GUARD_RE.search(fn.body))
    if has_zero_guard and has_max_guard:
        return None
    return ("routes protocol fees to a configured sink without both zero-receiver and max-share guards", config)


def _caller_controlled_fee_sink(fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    if not _FEE_CONTEXT_RE.search(fn.body):
        return None
    if _DYNAMIC_SINK_GUARD_RE.search(fn.body):
        return None
    for param in sorted(_address_sink_params(fn.header)):
        routed = _routes_fee_to_param(fn.body, param)
        if routed is not None:
            return (
                f"routes fee value to caller supplied `{param}` without an allowlist, cap, or configured fallback sink",
                routed,
            )
    return None


def _first_reason(source: str, has_accrual_helper: bool, fn: FunctionSlice) -> tuple[str, re.Match[str]] | None:
    for check in (
        lambda: _raw_reserve_fee_float(source, fn),
        lambda: _missing_fee_accrual(has_accrual_helper, fn),
        lambda: _unguarded_protocol_share(fn),
        lambda: _unguarded_protocol_sink(fn),
        lambda: _caller_controlled_fee_sink(fn),
    ):
        result = check()
        if result is not None:
            return result
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean_source = _strip_comments(source)
    functions = _split_functions(clean_source)
    has_accrual_helper = _has_accrual_helper(functions)
    findings: list[Finding] = []

    for fn in functions:
        if not _PUBLIC_HEADER_RE.search(fn.header):
            continue
        reason = _first_reason(clean_source, has_accrual_helper, fn)
        if reason is None:
            continue
        message, anchor = reason
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for(fn, anchor),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` {message}. Bind fee accounting to the "
                    "protocol-owned reserve, accrual state, or fee recipient "
                    "before routing value."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
