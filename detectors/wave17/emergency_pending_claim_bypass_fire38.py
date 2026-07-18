"""
emergency-pending-claim-bypass-fire38

Fire38 Solidity detector for emergency-bypass misses where a deprecation,
pause, shutdown, emergency sweep, or market status update locks pending user
claims, queued withdrawals, liquidation rescue, or recipient reassignment
state without settling it or exposing an explicit rescue path.

Source refs:
* reports/detector_lift_fire37_20260605/post_priorities_solidity.md
* reference/patterns.dsl/admin-bypass-umbrella.yaml
* reference/patterns.dsl/a-market-could-be-deprecated-but-still-prevent-liquidators-to-li.yaml
* reference/patterns.dsl/admin-sweep-blocks-pending-user-claims.yaml
* reference/patterns.dsl/freeze-control-unguarded-state-flip.yaml
* reference/patterns.dsl/permanent-freeze.yaml was requested by the lane brief but is absent in this checkout.

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "emergency-pending-claim-bypass-fire38"
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
    has_claim_or_withdraw_surface: bool
    has_liquidation_surface: bool
    has_recipient_state: bool
    has_contract_rescue_surface: bool


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
    r"disabled|shutdown|halted|closed|sweep|rescue|recover|pending|claim|"
    r"withdraw|withdrawal|liquidat|recipient|receiver|market|route|branch)\b",
    re.IGNORECASE,
)
_PENDING_STATE_RE = re.compile(
    r"\b(?:mapping\s*\([^;]+\)|uint(?:8|16|32|64|128|256)?|address|bytes32|bool)"
    r"[^;{}]*(?:pendingClaims?|queuedClaims?|claimable|unclaimed|"
    r"unresolvedClaims?|pendingWithdrawals?|queuedWithdrawals?|"
    r"withdrawalQueue|exitQueue|pendingExits?|pendingRedemptions?|"
    r"queuedRedemptions?|totalPending|totalQueued|totalClaimable|"
    r"claimLiabilit|outstandingLiabilit|reservedForClaims|"
    r"pendingLiquidations?|queuedLiquidations?)\b[^;]*;",
    re.IGNORECASE | re.DOTALL,
)
_CLAIM_WITHDRAW_SURFACE_RE = re.compile(
    r"\bfunction\s+(?:claim|claimPending|claimRewards|claimWithdrawal|"
    r"claimRedemption|withdraw|withdrawQueued|completeWithdrawal|"
    r"finalizeWithdrawal|redeem|redeemQueued|processExit|finalizeExit|"
    r"releaseClaim|collectClaim|requestWithdraw|requestRedeem)\b",
    re.IGNORECASE,
)
_LIQUIDATION_SURFACE_RE = re.compile(
    r"\bfunction\s+(?:liquidate|liquidateBorrow|repay|repayBorrow|absorb|"
    r"closeBadDebt|settleBadDebt|writeOff|seize|auction|deleverage)\b|"
    r"\b(?:isLiquidateBorrowPaused|liquidateBorrowPaused|liquidationsPaused|"
    r"marketDeprecated|isDeprecated|badDebt|shortfall|insolvent|borrower)\b",
    re.IGNORECASE,
)
_RECIPIENT_STATE_RE = re.compile(
    r"\b(?:pendingRecipients?|claimRecipients?|claimReceivers?|"
    r"recipientReassignment|receiverReassignment|pendingReassignment|"
    r"recipientAssignment|receiverAssignment|branchRecipient|branchReceiver|"
    r"routeRecipient|routeReceiver)\b",
    re.IGNORECASE,
)
_CONTRACT_RESCUE_SURFACE_RE = re.compile(
    r"\bfunction\s+(?:claimAfterShutdown|withdrawAfterShutdown|"
    r"redeemAfterShutdown|rescuePendingClaims|rescueQueuedWithdrawals|"
    r"migratePendingClaims|migrateQueuedWithdrawals|liquidateDeprecatedMarket|"
    r"repayDeprecatedMarket|claimClosedRoute|reassignClosedRoute|"
    r"releaseBlockedRecipient|refundBlockedUsers)\b",
    re.IGNORECASE,
)

_ADMIN_AUTH_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernor|onlyGovernance|onlyGov|"
    r"onlyGuardian|onlyEmergencyAdmin|onlyPauser|onlyRole|onlyRoles|"
    r"requiresAuth|requiresAuthorization|restricted|auth|AccessControl|"
    r"hasRole|_checkRole|EMERGENCY_ADMIN|GUARDIAN_ROLE|PAUSER_ROLE|ADMIN_ROLE)\b|"
    r"\b(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)\s*"
    r"(?:owner|admin|governance|governor|guardian|emergencyAdmin|"
    r"pauser|controller|manager|treasury)",
    re.IGNORECASE,
)
_ADMIN_EMERGENCY_NAME_RE = re.compile(
    r"(?:pause|unpause|freeze|unfreeze|deprecat|disable|enable|shutdown|"
    r"halt|close|suspend|resume|emergency|rescue|sweep|recover|drain|"
    r"set.*(?:Status|Paused|Disabled|Deprecated|Closed|Frozen|Halted)|"
    r"update.*(?:Status|Paused|Disabled|Deprecated|Closed|Frozen|Halted)|"
    r"mark.*(?:Status|Paused|Disabled|Deprecated|Closed|Frozen|Halted))",
    re.IGNORECASE,
)
_STATUS_WRITE_RE = re.compile(
    r"\b(?:global|protocol|system|emergency|market|markets|vault|vaults|"
    r"claim|claims|withdraw|withdrawal|withdrawals|liquidat|route|routes|"
    r"branch|branches|recipient|receiver)[A-Za-z0-9_]*"
    r"(?:Status|Paused|Disabled|Deprecated|Frozen|Halted|Closed|Blocked|"
    r"Shutdown|Stopped|Suspended)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:true|1|[A-Za-z_][A-Za-z0-9_]*\."
    r"(?:Paused|Disabled|Deprecated|Frozen|Halted|Closed|Blocked|Shutdown|"
    r"Stopped|Suspended))\b|"
    r"\b(?:isLiquidateBorrowPaused|liquidateBorrowPaused|liquidationsPaused|"
    r"marketDeprecated|isDeprecated|isMarketDeprecated)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:true|1)\b|"
    r"\bdelete\s+(?:pendingRecipients?|claimRecipients?|claimReceivers?|"
    r"recipientReassignment|receiverReassignment|branchRecipient|branchReceiver|"
    r"routeRecipient|routeReceiver)(?:\s*\[[^\]]+\]\s*){1,4}",
    re.IGNORECASE | re.DOTALL,
)
_SWEEP_NAME_RE = re.compile(
    r"(?:sweep|rescue|recover|drain|emergencySweep|adminWithdraw|withdrawAll|"
    r"recoverEscrow|rescueEscrow|sweepClaims?|sweepRewards?)",
    re.IGNORECASE,
)
_SWEEP_PENDING_CONTEXT_RE = re.compile(
    r"(?:claim|withdraw|queued|pending|escrow|reserve|redemption|exit|"
    r"liabilit|obligation|reward)",
    re.IGNORECASE,
)
_VALUE_TRANSFER_RE = re.compile(
    r"\b(?:safeTransfer|transfer|sendValue|send|call)\s*(?:\(|\{)|"
    r"\b(?:escrow|reserve|reserves|claimReserve|withdrawalReserve|"
    r"marketEscrow|queuedAssets|pendingAssets|branchBalance|routeBalance)"
    r"(?:\s*\[[^\]]+\]\s*){0,4}\s*(?:-=|=)",
    re.IGNORECASE,
)
_PROTECTED_BALANCE_RE = re.compile(
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"\baddress\s*\(\s*this\s*\)\s*\.\s*balance\b|"
    r"\bthis\s*\.\s*balance\b|"
    r"\b(?:escrow|reserve|reserves|claimReserve|withdrawalReserve|"
    r"marketEscrow|queuedAssets|pendingAssets|branchBalance|routeBalance)"
    r"(?:\s*\[[^\]]+\]\s*){0,4}",
    re.IGNORECASE,
)
_SWEEP_PROTECTION_RE = re.compile(
    r"\b(?:settlePending|settleClaims|settleWithdrawals|flushPending|"
    r"processPending|processQueued|payPending|escrowPending|reserveFor|"
    r"reserved|sweepable|protectedBalance|owedClaims|liability|liabilities|"
    r"obligation|obligations|totalPending|totalQueued|totalClaimable|"
    r"pendingWithdrawals|pendingClaims|claimableBalance|outstandingLiabilities)\b|"
    r"\b(?:balance|cash|amount|assets?|collateral)\s*-\s*(?:reserved|"
    r"protectedBalance|totalPending|totalQueued|pending|claimable|unclaimed|"
    r"liabilit|owed)|"
    r"\brequire\s*\([^;{}]*(?:pending|queued|claimable|unclaimed|owed|"
    r"liabilit|reserved|sweepable)[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_DIRECT_RESOLUTION_RE = re.compile(
    r"\b(?:process|settle|resolve|flush|release|pay|honor|finalize|migrate|"
    r"reassign|assign|refund|cancel|clear|closeOut|unblock|unlock|rescue)"
    r"(?:Pending|Queued|User|Users|Claim|Claims|Withdrawal|Withdrawals|"
    r"Liquidation|Liquidations|Market|Markets|Recipient|Recipients|Receiver|"
    r"Receivers|Route|Routes|Branch|Branches)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:pendingClaims?|queuedClaims?|pendingWithdrawals?|queuedWithdrawals?|"
    r"pendingRecipients?|claimRecipients?|recipientReassignment|receiverReassignment)"
    r"(?:\s*\[[^\]]+\]\s*){1,4}\s*=\s*(?:0|false|address\s*\(\s*0\s*\))|"
    r"\bdelete\s+(?:pendingClaims?|queuedClaims?|pendingWithdrawals?|"
    r"queuedWithdrawals?|pendingRecipients?|claimRecipients?|"
    r"recipientReassignment|receiverReassignment)(?:\s*\[[^\]]+\]\s*){1,4}",
    re.IGNORECASE | re.DOTALL,
)
_MARKET_REFRESH_OR_EXCEPTION_RE = re.compile(
    r"\b(?:accrue|update|sync|validate|check|refresh)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:isLiquidateBorrowPaused|liquidateBorrowPaused|liquidationsPaused)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:false|0)\b|"
    r"\b(?:liquidationExempt|allowLiquidation|debtReductionMode|"
    r"repayDeprecated|liquidateDeprecated|closeoutException|ignorePauseForDebt)"
    r"\b",
    re.IGNORECASE,
)
_LIQUIDATION_STATUS_WRITE_RE = re.compile(
    r"\b(?:isLiquidateBorrowPaused|liquidateBorrowPaused|liquidationsPaused|"
    r"marketDeprecated|isDeprecated|isMarketDeprecated|marketStatus)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=",
    re.IGNORECASE,
)
_RECIPIENT_RESOLUTION_RE = re.compile(
    r"\b(?:reassign|assign|migrate|release|refund|rescue|claimClosedRoute|"
    r"releaseBlockedRecipient|setFallbackRecipient|setFallbackReceiver)"
    r"(?:Pending|Recipient|Recipients|Receiver|Receivers|Route|Branch)"
    r"[A-Za-z0-9_]*\s*\(|"
    r"\b(?:pendingRecipients?|claimRecipients?|claimReceivers?|"
    r"recipientReassignment|receiverReassignment|branchRecipient|branchReceiver|"
    r"routeRecipient|routeReceiver)(?:\s*\[[^\]]+\]\s*){1,4}\s*=",
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


def _make_contract_slice(body: str, start_line: int) -> ContractSlice:
    return ContractSlice(
        source=body,
        start_line=start_line,
        has_pending_state=bool(_PENDING_STATE_RE.search(body)),
        has_claim_or_withdraw_surface=bool(_CLAIM_WITHDRAW_SURFACE_RE.search(body)),
        has_liquidation_surface=bool(_LIQUIDATION_SURFACE_RE.search(body)),
        has_recipient_state=bool(_RECIPIENT_STATE_RE.search(body)),
        has_contract_rescue_surface=bool(_CONTRACT_RESCUE_SURFACE_RE.search(body)),
    )


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
        out.append(_make_contract_slice(body, source.count("\n", 0, open_brace + 1) + 1))
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


def _has_admin_or_emergency_context(fn: FunctionSlice) -> bool:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    return bool(_ADMIN_AUTH_RE.search(text) or _ADMIN_EMERGENCY_NAME_RE.search(fn.name))


def _has_exit_or_rescue_surface(contract: ContractSlice) -> bool:
    return (
        (contract.has_pending_state and contract.has_claim_or_withdraw_surface)
        or contract.has_liquidation_surface
        or contract.has_recipient_state
    )


def _has_direct_resolution(fn: FunctionSlice) -> bool:
    return bool(_DIRECT_RESOLUTION_RE.search(fn.body))


def _status_lock_branch(fn: FunctionSlice, contract: ContractSlice) -> str | None:
    if not _has_exit_or_rescue_surface(contract):
        return None
    if contract.has_contract_rescue_surface:
        return None
    if not _has_admin_or_emergency_context(fn):
        return None
    if not _STATUS_WRITE_RE.search(fn.body):
        return None
    if _has_direct_resolution(fn):
        return None
    return "status-update-blocks-pending-user-paths"


def _liquidation_lock_branch(fn: FunctionSlice, contract: ContractSlice) -> str | None:
    if not contract.has_liquidation_surface:
        return None
    if not _has_admin_or_emergency_context(fn):
        return None
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not re.search(r"(?i)(deprecat|liquidat|pause|status|market)", text):
        return None
    if not _LIQUIDATION_STATUS_WRITE_RE.search(fn.body):
        return None
    if not _STATUS_WRITE_RE.search(fn.body):
        return None
    if _MARKET_REFRESH_OR_EXCEPTION_RE.search(fn.body):
        return None
    if _has_direct_resolution(fn):
        return None
    return "deprecated-market-locks-liquidation-rescue"


def _recipient_lock_branch(fn: FunctionSlice, contract: ContractSlice) -> str | None:
    if not contract.has_recipient_state:
        return None
    if contract.has_contract_rescue_surface:
        return None
    if not _has_admin_or_emergency_context(fn):
        return None
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not re.search(r"(?i)(recipient|receiver|route|branch)", text):
        return None
    if not _STATUS_WRITE_RE.search(fn.body):
        return None
    if _RECIPIENT_RESOLUTION_RE.search(fn.body):
        return None
    return "recipient-route-closed-without-reassignment"


def _sweep_pending_branch(fn: FunctionSlice, contract: ContractSlice) -> str | None:
    if not (contract.has_pending_state and contract.has_claim_or_withdraw_surface):
        return None
    if not _SWEEP_NAME_RE.search(fn.name):
        return None
    if not _SWEEP_PENDING_CONTEXT_RE.search(fn.name + "\n" + fn.header + "\n" + fn.body):
        return None
    if not _has_admin_or_emergency_context(fn):
        return None
    if not (_VALUE_TRANSFER_RE.search(fn.body) and _PROTECTED_BALANCE_RE.search(fn.body)):
        return None
    if _SWEEP_PROTECTION_RE.search(fn.body) or _has_direct_resolution(fn):
        return None
    return "emergency-sweep-drains-pending-claim-reserve"


def _candidate_branch(fn: FunctionSlice, contract: ContractSlice) -> str | None:
    for branch_fn in (
        _sweep_pending_branch,
        _recipient_lock_branch,
        _liquidation_lock_branch,
        _status_lock_branch,
    ):
        branch = branch_fn(fn, contract)
        if branch is not None:
            return branch
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _CONTEXT_HINT_RE.search(clean):
        return []

    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [_make_contract_slice(clean, 1)]
    for contract in contracts:
        if not _has_exit_or_rescue_surface(contract):
            continue
        for fn in _split_functions(contract.source, contract.start_line):
            if not _is_public(fn):
                continue
            if _VIEW_OR_PURE_RE.search(fn.header):
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
                        f"{DETECTOR_NAME}: branch {branch}: admin or "
                        "emergency status/sweep path can block pending user "
                        "claims, withdrawals, liquidations, or recipient "
                        "handoffs without direct settlement or an explicit "
                        "rescue path. NOT_SUBMIT_READY."
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
