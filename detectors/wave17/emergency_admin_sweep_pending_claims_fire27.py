"""
emergency-admin-sweep-pending-claims-fire27

Fire27 Solidity detector for explicit owner, admin, or emergency sweep paths
that move full contract balances or reserve balances while the contract tracks
pending user claims, withdrawals, redemptions, or liabilities.

Source records:
* reference/patterns.dsl/admin-sweep-blocks-pending-user-claims.yaml
* reference/patterns.dsl/a-market-could-be-deprecated-but-still-prevent-liquidators-to-li.yaml
* reference/patterns.dsl/emergency-withdraw-bypass-lock.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "emergency-admin-sweep-pending-claims-fire27"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False


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


@dataclass
class ContractSlice:
    source: str
    start_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_CONTRACT_HEADER_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_SKIP_RE = re.compile(r"\b(?:mock|test|fixture|harness|example|demo)\b", re.IGNORECASE)

_CLAIMABLE_STATE_RE = re.compile(
    r"\bmapping\s*\([^;]+=>\s*uint(?:8|16|32|64|128|256)?\s*\)"
    r"[^;]*(?:pending|claimable|unclaimed|accrued|earned|owed|withdrawal|"
    r"redemption|liabilit)|"
    r"\buint(?:8|16|32|64|128|256)?\s+"
    r"(?:(?:public|private|internal|constant|immutable)\s+)*"
    r"(?:totalPending|totalClaimable|totalUnclaimed|totalAccrued|"
    r"pendingWithdrawals|pendingRedemptions|claimLiabilit|"
    r"outstandingLiabilit|totalLiabilit|userLiabilit)\w*",
    re.IGNORECASE,
)
_USER_OBLIGATION_ENTRY_RE = re.compile(
    r"\bfunction\s+(?:claim\w*|withdraw\w*|redeem\w*|requestWithdraw\w*|"
    r"requestRedeem\w*|claimWithdraw\w*|claimRedemption\w*|settleClaim\w*)\s*\(",
    re.IGNORECASE,
)
_SWEEP_NAME_RE = re.compile(
    r"(?:sweep|rescue|recover|withdrawAll|adminWithdraw|emergencyWithdraw|"
    r"emergencySweep|emergencyDrain|drainReserve|drainAll|breakGlass)",
    re.IGNORECASE,
)
_ADMIN_OR_EMERGENCY_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|"
    r"onlyGuardian|requiresAuth|restricted|auth|emergencyOnly)\b|"
    r"\b(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)\s*"
    r"(?:owner|admin|governance|governor|guardian|controller|manager)|"
    r"\b(?:emergency|panic|breakGlass)\b",
    re.IGNORECASE,
)
_VALUE_TRANSFER_RE = re.compile(
    r"\b(?:safeTransfer|transfer|sendValue|send)\s*\(|"
    r"\.call\s*\{\s*value\s*:",
    re.IGNORECASE,
)
_FULL_CONTRACT_BALANCE_RE = re.compile(
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"\baddress\s*\(\s*this\s*\)\s*\.\s*balance\b|"
    r"\bthis\s*\.\s*balance\b|"
    r"\btotalBalance\b",
    re.IGNORECASE,
)
_RESERVE_BALANCE_RE = re.compile(
    r"\b(?:reserveBalance|claimReserve|withdrawalReserve|redemptionReserve|"
    r"escrowReserve|liabilityReserve|poolBalance|cashReserve|totalReserve|"
    r"totalReserves|availableReserve|backingReserve)\b",
    re.IGNORECASE,
)
_LIABILITY_PROTECTION_RE = re.compile(
    r"\b(?:settlePending|settleClaims|settleWithdrawals|flushPending|"
    r"processPending|payPending|escrowPending|escrowLiabilities|"
    r"reserveFor|reserved|sweepable|protectedBalance|owedClaims|"
    r"liability|liabilities|obligation|obligations|totalPending|"
    r"totalClaimable|totalUnclaimed|totalAccrued|pendingWithdrawals|"
    r"pendingRedemptions|claimableBalance|outstandingLiabilities)\b|"
    r"\b(?:balance|cash|amount)\s*-\s*(?:reserved|protectedBalance|"
    r"totalPending|pending|claimable|unclaimed|liabilit|owed)|"
    r"\baddress\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*!=\s*"
    r"address\s*\(\s*(?:rewardToken|claimToken|assetToken|underlying|"
    r"reserveToken|payoutToken)\s*\)|"
    r"\b(?:isRewardToken|accountedToken|claimToken|reservedToken)"
    r"\s*\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]\s*==\s*false",
    re.IGNORECASE,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        if "\n" in text:
            return "\n" * text.count("\n")
        return " "

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


def _split_contracts(source: str) -> list[ContractSlice]:
    out: list[ContractSlice] = []
    pos = 0
    while True:
        match = _CONTRACT_HEADER_RE.search(source, pos)
        if not match:
            break
        open_brace = source.find("{", match.end())
        if open_brace < 0:
            pos = match.end()
            continue
        body, end_pos = _extract_balanced_block(source, open_brace)
        if body is None:
            pos = open_brace + 1
            continue
        out.append(
            ContractSlice(
                source=body,
                start_line=source.count("\n", 0, open_brace + 1) + 1,
            )
        )
        pos = end_pos
    return out


def _split_functions(source: str, base_line: int = 1) -> list[FunctionSlice]:
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
                start_line=base_line + source.count("\n", 0, match.start()),
            )
        )
        pos = end_pos
    return out


def _has_claimable_balance_state(source: str) -> bool:
    return bool(_CLAIMABLE_STATE_RE.search(source) and _USER_OBLIGATION_ENTRY_RE.search(source))


def _is_public(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header))


def _is_skipped(fn: FunctionSlice, file_path: str) -> bool:
    return bool(_SKIP_RE.search(file_path) or _SKIP_RE.search(fn.name))


def _has_privileged_or_emergency_context(fn: FunctionSlice) -> bool:
    return bool(_ADMIN_OR_EMERGENCY_RE.search(fn.name + "\n" + fn.header + "\n" + fn.body))


def _sweep_branch(fn: FunctionSlice) -> str | None:
    if not _SWEEP_NAME_RE.search(fn.name):
        return None
    if not _has_privileged_or_emergency_context(fn):
        return None
    if not _VALUE_TRANSFER_RE.search(fn.body):
        return None
    if _LIABILITY_PROTECTION_RE.search(fn.body):
        return None

    if _FULL_CONTRACT_BALANCE_RE.search(fn.body):
        return "full-contract-balance-sweep"
    if _RESERVE_BALANCE_RE.search(fn.body):
        return "reserve-balance-sweep"
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not re.search(
        r"(?i)\b(?:sweep|rescue|recover|emergency|drain|pending|claim|withdraw|redeem|liabilit)",
        clean,
    ):
        return []
    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [ContractSlice(clean, 1)]
    for contract in contracts:
        if not _has_claimable_balance_state(contract.source):
            continue
        for fn in _split_functions(contract.source, contract.start_line):
            if not _is_public(fn):
                continue
            if _is_skipped(fn, file_path):
                continue
            branch = _sweep_branch(fn)
            if branch is None:
                continue
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=fn.start_line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"{DETECTOR_NAME}: branch {branch}: explicit admin, owner, "
                        "or emergency sweep transfers claimable or reserve balance "
                        "before pending user claims, withdrawals, redemptions, or "
                        "liabilities are settled or escrowed. NOT_SUBMIT_READY."
                    ),
                )
            )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "PROMOTION_ALLOWED",
    "Finding",
    "scan",
]
