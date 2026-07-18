"""
emergency-pending-claims-fire34

Fire34 Solidity detector for emergency-bypass misses where an admin pause,
deprecation, rescue, or emergency sweep path disables normal user exits while
pending claims, queued withdrawals, or recipient reassignment state remains
unresolved.

Source records:
* reports/detector_lift_fire33_20260605/post_priorities_all.md
* reference/patterns.dsl/emergency-bypass.yaml (requested path absent in this checkout)
* reference/patterns.dsl/emergency-withdraw-bypass-lock.yaml
* detectors/wave17/emergency_asset_scope_bypass_fire31.py
* detectors/wave17/emergency_pause_scope_fire32.py

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "emergency-pending-claims-fire34"
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
    has_pending_state: bool
    has_claim_surface: bool
    has_reassignment_state: bool


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
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_SKIP_RE = re.compile(r"\b(?:mock|test|fixture|harness|example|demo)\b", re.IGNORECASE)

_CONTEXT_HINT_RE = re.compile(
    r"\b(?:emergency|pause|paused|freeze|frozen|deprecated|deprecate|disable|"
    r"disabled|shutdown|halted|closed|sweep|rescue|recover|pendingClaims|"
    r"queuedWithdrawals|pendingWithdrawals|claimQueue|withdrawalQueue|"
    r"exitQueue|pendingRedemptions|reassignment|recipient|receiver)\b",
    re.IGNORECASE,
)
_PENDING_STATE_RE = re.compile(
    r"\b(?:mapping\s*\([^;]+\)|[A-Za-z_][A-Za-z0-9_]*(?:\s*\[\s*\])?|"
    r"uint(?:8|16|32|64|128|256)?|address|bytes32|bool)"
    r"\s+(?:public\s+|private\s+|internal\s+|external\s+)?"
    r"(?:pendingClaims?|queuedClaims?|claimQueue|claimable|unclaimed|"
    r"unresolvedClaims?|pendingWithdrawals?|queuedWithdrawals?|withdrawalQueue|"
    r"exitQueue|pendingExits?|pendingRedemptions?|queuedRedemptions?|"
    r"recipientReassignment|receiverReassignment|pendingReassignment|"
    r"recipientAssignment|receiverAssignment|branchRecipient|branchReceiver)"
    r"\b[^;]*;",
    re.IGNORECASE | re.DOTALL,
)
_REASSIGNMENT_STATE_RE = re.compile(
    r"\b(?:recipientReassignment|receiverReassignment|pendingReassignment|"
    r"recipientAssignment|receiverAssignment|branchRecipient|branchReceiver|"
    r"claimRecipient|claimReceiver)\b",
    re.IGNORECASE,
)
_USER_CLAIM_SURFACE_RE = re.compile(
    r"\bfunction\s+(?:claim|claimPending|claimRewards|withdraw|withdrawQueued|"
    r"completeWithdrawal|finalizeWithdrawal|redeem|redeemQueued|processExit|"
    r"finalizeExit|releaseClaim|collectClaim)\b",
    re.IGNORECASE,
)
_ADMIN_AUTH_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernor|onlyGovernance|onlyGov|onlyGuardian|"
    r"onlyEmergencyAdmin|onlyRole|requiresAuth|auth|requiresAuthorization|"
    r"hasRole|_checkRole|AccessControl)\b|"
    r"\bmsg\.sender\s*==\s*(?:owner|admin|governor|governance|guardian|"
    r"emergencyAdmin|treasury)\b",
    re.IGNORECASE,
)
_ADMIN_EMERGENCY_NAME_RE = re.compile(
    r"(?:pause|unpause|freeze|unfreeze|deprecat|disable|enable|shutdown|halt|"
    r"close|suspend|resume|emergency|rescue|sweep|recover|drain|set.*(?:Status|"
    r"Paused|Disabled|Deprecated|Closed|Frozen|Halted)|update.*(?:Status|Paused|"
    r"Disabled|Deprecated|Closed|Frozen|Halted))",
    re.IGNORECASE,
)
_DISABLE_WRITE_RE = re.compile(
    r"\b(?:(?:global|protocol|system|emergency)|(?:claim|claims|withdraw|"
    r"withdrawal|withdrawals|exit|exits|redemption|redemptions|queue|market|"
    r"markets|branch|branches|route|routes|recipient|receiver)[A-Za-z0-9_]*)"
    r"(?:Paused|Disabled|Deprecated|Frozen|Halted|Closed|Blocked|"
    r"Suspended|Shutdown|Stopped|EmergencyMode)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:true|1|[A-Za-z_][A-Za-z0-9_]*\."
    r"(?:Paused|Disabled|Deprecated|Frozen|Halted|Closed|Blocked|Suspended|"
    r"Shutdown|Stopped))\b|"
    r"\b(?:claim|claims|withdraw|withdrawal|withdrawals|exit|exits|redemption|"
    r"redemptions|market|markets|branch|branches|route|routes|recipient|receiver)"
    r"[A-Za-z0-9_]*(?:Enabled|Open|Live|Active)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:false|0)\b|"
    r"\b(?:market|markets|branch|branches|route|routes)[A-Za-z0-9_]*Status"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*[A-Za-z_][A-Za-z0-9_]*\."
    r"(?:Deprecated|Paused|Disabled|Frozen|Halted|Closed|Blocked|Suspended)\b|"
    r"\bdelete\s+(?:markets?|branches?|routes?)[A-Za-z0-9_]*\s*\[[^\]]+\]",
    re.IGNORECASE | re.DOTALL,
)
_BRANCH_STATUS_WRITE_RE = re.compile(
    r"\b(?:branch|branches|route|routes)[A-Za-z0-9_]*Status"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*[A-Za-z_][A-Za-z0-9_]*\."
    r"(?:Deprecated|Paused|Disabled|Frozen|Halted|Closed|Blocked|Suspended)\b|"
    r"\b(?:branch|route)[A-Za-z0-9_]*(?:Disabled|Closed|Deprecated|Paused)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:true|1)\b",
    re.IGNORECASE | re.DOTALL,
)
_SWEEP_NAME_RE = re.compile(
    r"(?:sweep|rescue|recover|drain|seize|emergencySweep|sweepUnclaimed|"
    r"recoverEscrow|rescueEscrow)",
    re.IGNORECASE,
)
_SWEEP_VALUE_RE = re.compile(
    r"\b(?:safeTransfer|transfer|sendValue|send|call)\s*(?:\(|\{)|"
    r"\b(?:marketEscrow|claimEscrow|withdrawalEscrow|queuedAssets|pendingAssets|"
    r"exitEscrow|branchEscrow|claimReserve|withdrawalReserve|escrow|reserves?)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*(?:-=|=)",
    re.IGNORECASE,
)
_SWEEP_PENDING_SURFACE_RE = re.compile(
    r"\b(?:market|branch|route|vault|pool|claim|claims|withdraw|withdrawal|"
    r"withdrawals|queue|queued|pending|escrow|reserve|redemption|exit|exits)"
    r"[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)
_PENDING_RESOLUTION_RE = re.compile(
    r"\b(?:process|settle|resolve|flush|release|pay|honor|finalize|migrate|"
    r"reassign|rollover|refund|cancel|clear|closeOut)"
    r"(?:Pending|Queued|User|Users|Market|Branch|Route|Claim|Claims|Withdrawal|"
    r"Withdrawals|Exit|Exits|Redemption|Redemptions|Recipient|Receiver|"
    r"Reassignment)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:pendingClaims?|queuedClaims?|claimQueue|claimable|unclaimed|"
    r"unresolvedClaims?|pendingWithdrawals?|queuedWithdrawals?|withdrawalQueue|"
    r"exitQueue|pendingExits?|pendingRedemptions?|queuedRedemptions?)"
    r"(?:\s*\[[^\]]+\]\s*){1,4}\s*=\s*(?:0|false)\b|"
    r"\bdelete\s+(?:pendingClaims?|queuedClaims?|claimQueue|claimable|unclaimed|"
    r"unresolvedClaims?|pendingWithdrawals?|queuedWithdrawals?|withdrawalQueue|"
    r"exitQueue|pendingExits?|pendingRedemptions?|queuedRedemptions?)"
    r"(?:\s*\[[^\]]+\]\s*){1,4}|"
    r"\b(?:recipientReassignment|receiverReassignment|pendingReassignment|"
    r"recipientAssignment|receiverAssignment|branchRecipient|branchReceiver|"
    r"claimRecipient|claimReceiver)(?:\s*\[[^\]]+\]\s*){1,4}\s*=",
    re.IGNORECASE | re.DOTALL,
)


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
                has_pending_state=bool(_PENDING_STATE_RE.search(body)),
                has_claim_surface=bool(_USER_CLAIM_SURFACE_RE.search(body)),
                has_reassignment_state=bool(_REASSIGNMENT_STATE_RE.search(body)),
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


def _is_public(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header))


def _is_skipped(fn: FunctionSlice, file_path: str) -> bool:
    return bool(_SKIP_RE.search(file_path) or _SKIP_RE.search(fn.name))


def _is_admin_emergency_path(fn: FunctionSlice) -> bool:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    return bool(_ADMIN_EMERGENCY_NAME_RE.search(fn.name) and (_ADMIN_AUTH_RE.search(text) or _SWEEP_NAME_RE.search(fn.name)))


def _has_pending_resolution(fn: FunctionSlice) -> bool:
    return bool(_PENDING_RESOLUTION_RE.search(fn.body))


def _disable_branch(fn: FunctionSlice) -> str | None:
    if _DISABLE_WRITE_RE.search(fn.body):
        return "emergency-disable-pending-claims-unresolved"
    return None


def _sweep_branch(fn: FunctionSlice) -> str | None:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _SWEEP_NAME_RE.search(fn.name):
        return None
    if not _SWEEP_VALUE_RE.search(fn.body):
        return None
    if not _SWEEP_PENDING_SURFACE_RE.search(text):
        return None
    return "admin-sweep-pending-claims-unresolved"


def _branch_status_without_reassignment(fn: FunctionSlice, contract: ContractSlice) -> str | None:
    if not contract.has_reassignment_state:
        return None
    if not _BRANCH_STATUS_WRITE_RE.search(fn.body):
        return None
    return "branch-status-update-without-recipient-reassignment"


def _candidate_branch(fn: FunctionSlice, contract: ContractSlice) -> str | None:
    if not contract.has_pending_state:
        return None
    if not contract.has_claim_surface:
        return None
    if _VIEW_OR_PURE_RE.search(fn.header):
        return None
    if not _is_admin_emergency_path(fn):
        return None
    if _has_pending_resolution(fn):
        return None

    for branch_fn in (
        _sweep_branch,
        lambda candidate: _branch_status_without_reassignment(candidate, contract),
        _disable_branch,
    ):
        branch = branch_fn(fn)
        if branch is not None:
            return branch
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _CONTEXT_HINT_RE.search(clean):
        return []

    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [
        ContractSlice(
            clean,
            1,
            bool(_PENDING_STATE_RE.search(clean)),
            bool(_USER_CLAIM_SURFACE_RE.search(clean)),
            bool(_REASSIGNMENT_STATE_RE.search(clean)),
        )
    ]
    for contract in contracts:
        if not contract.has_pending_state or not contract.has_claim_surface:
            continue
        for fn in _split_functions(contract.source, contract.start_line):
            if not _is_public(fn):
                continue
            if _is_skipped(fn, file_path):
                continue
            branch = _candidate_branch(fn, contract)
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
                        f"{DETECTOR_NAME}: branch {branch}: emergency pause, "
                        "deprecation, rescue, or sweep path can freeze or bypass "
                        "user claim surfaces while pending claims, queued "
                        "withdrawals, or reassignment state remains unresolved. "
                        "NOT_SUBMIT_READY."
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
