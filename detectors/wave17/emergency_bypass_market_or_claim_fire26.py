"""
emergency-bypass-market-or-claim-fire26

Fire26 Solidity recall detector for source-backed emergency-bypass misses.
It covers three narrow branches from confirmed DSL records:

* reference/patterns.dsl/a-market-could-be-deprecated-but-still-prevent-liquidators-to-li.yaml:
  deprecated market setters that can leave liquidation paused without an
  accrue, update, sync, validate, check, or refresh step;
* reference/patterns.dsl/admin-sweep-blocks-pending-user-claims.yaml: admin
  sweep, rescue, or emergency withdrawal paths that transfer full contract
  balance while the contract tracks pending user claims;
* reference/patterns.dsl/emergency-withdraw-bypass-lock.yaml: emergency
  withdraw or force-exit paths in lockup contracts that transfer value without
  honoring lock state or an explicit early-exit penalty.

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "emergency-bypass-market-or-claim-fire26"
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
    start_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_SKIP_RE = re.compile(r"\b(?:mock|test|fixture|harness)\b", re.IGNORECASE)

_LIQUIDATION_CONTEXT_RE = re.compile(
    r"\b(?:liquidate|liquidation|liquidator|liquidateBorrow)\b", re.IGNORECASE
)
_MARKET_PAUSE_STATE_RE = re.compile(
    r"\b(?:isDeprecated|deprecatedMarket|marketDeprecated|"
    r"isLiquidateBorrowPaused|liquidateBorrowPaused|isBorrowPaused)\b",
    re.IGNORECASE,
)
_MARKET_ADMIN_NAME_RE = re.compile(
    r"^(?:set|update|configure).*(?:Deprecated|Liquidate|BorrowPaused|Market)",
    re.IGNORECASE,
)
_MARKET_PROTECTION_CALL_RE = re.compile(
    r"\b(?:accrue|update|sync|validate|check|refresh)[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE,
)
_LIQUIDATION_UNPAUSE_RE = re.compile(
    r"\b(?:isLiquidateBorrowPaused|liquidateBorrowPaused)"
    r"\s*(?:\[[^\]]+\]\s*)?=\s*false\b",
    re.IGNORECASE,
)

_PENDING_LEDGER_RE = re.compile(
    r"\b(?:pending|unclaimed|claimable|accrued|earned|escrow|"
    r"totalPending|pendingRewards|claimableRewards|userClaims)\b",
    re.IGNORECASE,
)
_CLAIM_CONTEXT_RE = re.compile(
    r"\b(?:claim\w*|reward\w*|escrow\w*|payout\w*|vesting\w*)\b",
    re.IGNORECASE,
)
_SWEEP_NAME_RE = re.compile(
    r"^(?:sweep|rescue|recover|adminWithdraw|emergencyWithdraw|"
    r"emergencySweep|withdrawAll|sweepRewards)",
    re.IGNORECASE,
)
_ADMIN_GATE_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|"
    r"requiresAuth|auth|restricted)\b|"
    r"\b(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)\s*"
    r"(?:owner|admin|governance|governor|controller)",
    re.IGNORECASE,
)
_FULL_BALANCE_RE = re.compile(
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"\baddress\s*\(\s*this\s*\)\s*\.\s*balance\b|"
    r"\bthis\s*\.\s*balance\b",
    re.IGNORECASE,
)
_VALUE_TRANSFER_RE = re.compile(
    r"\b(?:safeTransfer|transfer|sendValue|send|call)\s*(?:\{|"
    r"\(|\.)",
    re.IGNORECASE,
)
_PENDING_RESERVE_GUARD_RE = re.compile(
    r"\b(?:pending|unclaimed|claimable|accrued|totalPending|reserved|"
    r"reserveFor|owedClaims|liability|obligation)\b|"
    r"\bbalance\s*-\s*(?:reserved|totalPending|pending|claimable|unclaimed)",
    re.IGNORECASE,
)

_LOCK_STATE_RE = re.compile(
    r"\b(?:lockEnd|lockUntil|unlockTime|unlockAt|lockPeriod|"
    r"lockedUntil|releaseTime|vestingEnd)\b",
    re.IGNORECASE,
)
_NORMAL_WITHDRAW_RE = re.compile(r"\bfunction\s+(?:withdraw|unstake|redeem)\b", re.IGNORECASE)
_EMERGENCY_EXIT_RE = re.compile(
    r"^(?:emergencyWithdraw|forceExit|panicWithdraw|emergencyExit|"
    r"breakGlassWithdraw)",
    re.IGNORECASE,
)
_LOCK_GUARD_RE = re.compile(
    r"\b(?:lockEnd|lockUntil|unlockTime|unlockAt|lockPeriod|"
    r"lockedUntil|releaseTime|vestingEnd)\b|"
    r"\bblock\s*\.\s*timestamp\s*(?:>=|>|<|<=)",
    re.IGNORECASE,
)
_PENALTY_RE = re.compile(r"\b(?:penalty|earlyExitFee|exitFee|slash|forfeit)\b", re.IGNORECASE)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    i = open_pos + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    close = _find_matching_delimiter(source, open_brace, "{", "}")
    if close < 0:
        return None, open_brace
    return source[open_brace + 1:close], close + 1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
            break

        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        i = close_paren + 1
        while i < len(source):
            if source[i] == ";":
                break
            if source[i] == "{":
                body_start = i
                break
            i += 1
        if body_start < 0:
            pos = max(i, close_paren + 1)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        out.append(
            FunctionSlice(
                name=name,
                header=header,
                body=body,
                start_line=source.count("\n", 0, match.start()) + 1,
            )
        )
        pos = end_pos
    return out


def _is_public(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header))


def _is_skipped(fn: FunctionSlice, file_path: str) -> bool:
    return bool(_SKIP_RE.search(fn.name) or _SKIP_RE.search(file_path))


def _deprecated_market_branch(fn: FunctionSlice, source: str) -> str | None:
    if not (_LIQUIDATION_CONTEXT_RE.search(source) and _MARKET_PAUSE_STATE_RE.search(source)):
        return None
    if not _MARKET_ADMIN_NAME_RE.search(fn.name):
        return None
    if not _MARKET_PAUSE_STATE_RE.search(fn.body):
        return None
    if _MARKET_PROTECTION_CALL_RE.search(fn.body):
        return None
    if _LIQUIDATION_UNPAUSE_RE.search(fn.body):
        return None
    return (
        "deprecated-market-pause: market emergency/deprecation path mutates "
        "deprecation or liquidation-pause state without refresh, accrue, sync, "
        "validate, check, or explicit liquidation unpause"
    )


def _admin_sweep_pending_claims_branch(fn: FunctionSlice, source: str) -> str | None:
    if not (_PENDING_LEDGER_RE.search(source) and _CLAIM_CONTEXT_RE.search(source)):
        return None
    if not _SWEEP_NAME_RE.search(fn.name):
        return None
    if not _ADMIN_GATE_RE.search(fn.header + "\n" + fn.body):
        return None
    if not (_FULL_BALANCE_RE.search(fn.body) and _VALUE_TRANSFER_RE.search(fn.body)):
        return None
    if _PENDING_RESERVE_GUARD_RE.search(fn.body):
        return None
    return (
        "admin-sweep-pending-claims: admin sweep, rescue, or emergency path "
        "transfers full contract balance while the contract tracks pending "
        "claims, with no reserve or liability subtraction"
    )


def _emergency_withdraw_lock_branch(fn: FunctionSlice, source: str) -> str | None:
    if not (_LOCK_STATE_RE.search(source) and _NORMAL_WITHDRAW_RE.search(source)):
        return None
    if not _EMERGENCY_EXIT_RE.search(fn.name):
        return None
    if not _VALUE_TRANSFER_RE.search(fn.body):
        return None
    if _LOCK_GUARD_RE.search(fn.body):
        return None
    if _PENALTY_RE.search(fn.body):
        return None
    return (
        "emergency-withdraw-lock-bypass: emergency exit transfers value in a "
        "lockup contract without checking lock state or applying an early-exit "
        "penalty"
    )


def _branches_for_function(fn: FunctionSlice, source: str) -> list[str]:
    branches: list[str] = []
    for branch_fn in (
        _deprecated_market_branch,
        _admin_sweep_pending_claims_branch,
        _emergency_withdraw_lock_branch,
    ):
        branch = branch_fn(fn, source)
        if branch is not None:
            branches.append(branch)
    return branches


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not re.search(
        r"(?i)\b(?:emergency|deprecated|sweep|rescue|recover|liquidate|pending|claim|lock)",
        clean,
    ):
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        if not _is_public(fn):
            continue
        if _is_skipped(fn, file_path):
            continue
        for branch in _branches_for_function(fn, clean):
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=fn.start_line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"{DETECTOR_NAME}: {branch}. "
                        "Source-backed candidate evidence only; NOT_SUBMIT_READY."
                    ),
                )
            )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "scan",
]
