"""
admin-sweep-pending-claims-bypass-fire30

Fire30 Solidity detector for emergency-bypass misses where an admin sweep,
rescue, or emergency withdrawal moves protected funds while user claims,
pending balances, deprecated markets, or branch state remain unresolved.

Source records:
* reports/detector_lift_fire29_20260605/post_priorities_solidity.md
* reference/patterns.dsl/admin-sweep-blocks-pending-user-claims.yaml
* reference/patterns.dsl/reentrancy-during-pause.yaml
* reference/patterns.dsl.zellic_k2_mined/emergency-admin-can-unpause-reserves-breaking-pause-asymmetry.yaml
* reference/patterns.dsl.zellic_k2_mined/collateral-can-be-enabled-despite-pause-freeze-or-invalid-pricing.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-sweep-pending-claims-bypass-fire30"
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

_CONTEXT_HINT_RE = re.compile(
    r"\b(?:emergency|sweep|rescue|recover|withdraw|claim|pending|unclaimed|"
    r"deprecated|branch|market|reserve|paused|frozen|disabled|closed)\b",
    re.IGNORECASE,
)
_PENDING_OR_CLAIM_STATE_RE = re.compile(
    r"\bmapping\s*\([^;]+=>\s*uint(?:8|16|32|64|128|256)?\s*\)"
    r"[^;]*(?:pending|claimable|unclaimed|accrued|earned|owed|withdrawal|"
    r"redemption|reward|escrow|liabilit|balance)|"
    r"\buint(?:8|16|32|64|128|256)?\s+"
    r"(?:(?:public|private|internal|constant|immutable)\s+)*"
    r"(?:totalPending|totalClaimable|totalUnclaimed|totalAccrued|"
    r"pendingWithdrawals|pendingRedemptions|pendingClaims|claimLiabilit|"
    r"outstandingLiabilit|totalLiabilit|userLiabilit|reservedForClaims)\w*",
    re.IGNORECASE,
)
_CLAIM_ENTRY_RE = re.compile(
    r"\bfunction\s+(?:claim\w*|withdraw\w*|redeem\w*|requestWithdraw\w*|"
    r"requestRedeem\w*|claimWithdraw\w*|claimRedemption\w*|settleClaim\w*|"
    r"collect\w*Reward\w*)\s*\(",
    re.IGNORECASE,
)
_BRANCH_OR_MARKET_STATE_RE = re.compile(
    r"\bmapping\s*\([^;]+=>\s*(?:bool|uint(?:8|16|32|64|128|256)?|"
    r"[A-Za-z_][A-Za-z0-9_]*)\s*\)[^;]*(?:market|reserve|branch|epoch|"
    r"deprecated|paused|frozen|disabled|closed|settled|resolved|status)|"
    r"\b(?:marketDeprecated|isDeprecated|deprecatedMarket|branchClosed|"
    r"branchResolved|branchStatus|marketStatus|reservePaused|marketPaused|"
    r"isFrozen|frozen|disabled|halted|closedBranch|pendingBranch)\b",
    re.IGNORECASE,
)
_BRANCH_ENTRY_RE = re.compile(
    r"\bfunction\s+(?:set\w*(?:Deprecated|Pause|Frozen|Disabled|Status)|"
    r"resolve\w*Branch|close\w*Branch|settle\w*Branch|refresh\w*Market|"
    r"accrue\w*|liquidate\w*)\s*\(",
    re.IGNORECASE,
)

_ADMIN_OR_EMERGENCY_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyPoolAdmin|onlyRole|onlyRoles|onlyGovernance|"
    r"onlyGovernor|onlyGuardian|onlyEmergencyAdmin|onlyPauser|"
    r"requiresAuth|restricted|auth|emergencyOnly|guardianOnly|"
    r"EMERGENCY_ADMIN|GUARDIAN_ROLE|PAUSER_ROLE|ADMIN_ROLE)\b|"
    r"\b(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)\s*"
    r"(?:owner|admin|governance|governor|guardian|controller|manager|"
    r"poolAdmin|emergencyAdmin|pauser)|"
    r"\b(?:emergency|panic|breakGlass)\b",
    re.IGNORECASE,
)
_SWEEP_OR_RESCUE_NAME_RE = re.compile(
    r"(?:sweep|rescue|recover|withdrawAll|adminWithdraw|emergencyWithdraw|"
    r"emergencySweep|emergencyDrain|drainReserve|drainAll|breakGlass|"
    r"forceWithdraw|clawback|recoverMarket|sweepMarket|rescueMarket)",
    re.IGNORECASE,
)
_BRANCH_FUNCTION_CONTEXT_RE = re.compile(
    r"\b(?:market|reserve|branch|deprecated|paused|frozen|disabled|closed|"
    r"status|collateral)\b",
    re.IGNORECASE,
)
_EMERGENCY_WITHDRAW_NAME_RE = re.compile(
    r"(?:emergencyWithdraw|panicWithdraw|breakGlassWithdraw|forceWithdraw|"
    r"emergencyExit|emergencyRedeem|emergencyClaim)",
    re.IGNORECASE,
)
_VALUE_TRANSFER_RE = re.compile(
    r"\b(?:safeTransfer|transfer|sendValue|send)\s*\(|"
    r"\.call\s*\{\s*value\s*:",
    re.IGNORECASE,
)
_PROTECTED_BALANCE_RE = re.compile(
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"\baddress\s*\(\s*this\s*\)\s*\.\s*balance\b|"
    r"\bthis\s*\.\s*balance\b|"
    r"\b(?:reserveBalance|claimReserve|withdrawalReserve|redemptionReserve|"
    r"escrowReserve|liabilityReserve|poolBalance|cashReserve|totalReserve|"
    r"totalReserves|availableReserve|backingReserve|marketBalance|"
    r"branchBalance|balances?|shares?|collateralBalance)\b"
    r"(?:\s*\[[^\]]+\]\s*)?",
    re.IGNORECASE,
)
_CLAIM_PROTECTION_RE = re.compile(
    r"\b(?:settlePending|settleClaims|settleWithdrawals|flushPending|"
    r"processPending|payPending|escrowPending|escrowLiabilities|"
    r"reserveFor|reserved|sweepable|protectedBalance|owedClaims|"
    r"liability|liabilities|obligation|obligations|totalPending|"
    r"totalClaimable|totalUnclaimed|totalAccrued|pendingWithdrawals|"
    r"pendingRedemptions|pendingClaims|claimableBalance|outstandingLiabilities)\b|"
    r"\b(?:balance|cash|amount|assets?|collateral)\s*-\s*(?:reserved|"
    r"protectedBalance|totalPending|pending|claimable|unclaimed|liabilit|owed)|"
    r"\brequire\s*\([^;{}]*(?:pending|claimable|unclaimed|owed|liabilit|"
    r"reserved|sweepable)[^;{}]*\)|"
    r"\baddress\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*!=\s*"
    r"address\s*\(\s*(?:rewardToken|claimToken|assetToken|underlying|"
    r"reserveToken|payoutToken|collateral)\s*\)",
    re.IGNORECASE | re.DOTALL,
)
_BRANCH_PROTECTION_RE = re.compile(
    r"\b(?:resolveBranch|settleBranch|closeBranch|reassignBranch|"
    r"assignBranchRecipient|refreshMarket|syncMarket|accrue|updateIndexes|"
    r"validateMarket|checkMarket|refreshReserve|settleMarketClaims|"
    r"processBranchClaims|marketIsLive|branchIsResolved)\s*\(|"
    r"\brequire\s*\([^;{}]*(?:!\s*(?:marketDeprecated|isDeprecated|"
    r"reservePaused|marketPaused|branchClosed|branchPending|frozen|disabled)|"
    r"(?:marketDeprecated|isDeprecated|reservePaused|marketPaused|branchClosed|"
    r"branchPending|frozen|disabled)\s*==\s*false|"
    r"(?:branchStatus|marketStatus)[^;{}]*(?:Resolved|Active|Live|Settled)|"
    r"recipient[^;{}]*!=\s*address\s*\(\s*0\s*\))[^;{}]*\)",
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


def _has_claim_context(contract_source: str) -> bool:
    return bool(_PENDING_OR_CLAIM_STATE_RE.search(contract_source) and _CLAIM_ENTRY_RE.search(contract_source))


def _has_branch_context(contract_source: str) -> bool:
    return bool(_BRANCH_OR_MARKET_STATE_RE.search(contract_source) and _BRANCH_ENTRY_RE.search(contract_source))


def _has_privileged_or_emergency_context(fn: FunctionSlice) -> bool:
    return bool(_ADMIN_OR_EMERGENCY_RE.search(fn.name + "\n" + fn.header + "\n" + fn.body))


def _moves_protected_funds(fn: FunctionSlice) -> bool:
    return bool(_VALUE_TRANSFER_RE.search(fn.body) and _PROTECTED_BALANCE_RE.search(fn.body))


def _has_claim_protection(fn: FunctionSlice) -> bool:
    return bool(_CLAIM_PROTECTION_RE.search(fn.body))


def _has_branch_protection(fn: FunctionSlice) -> bool:
    return bool(_BRANCH_PROTECTION_RE.search(fn.body))


def _pending_claim_sweep_branch(fn: FunctionSlice, contract_source: str) -> str | None:
    if not _has_claim_context(contract_source):
        return None
    if not _SWEEP_OR_RESCUE_NAME_RE.search(fn.name):
        return None
    if not _has_privileged_or_emergency_context(fn):
        return None
    if not _moves_protected_funds(fn):
        return None
    if _has_claim_protection(fn):
        return None
    return "pending-claims-admin-sweep"


def _deprecated_market_sweep_branch(fn: FunctionSlice, contract_source: str) -> str | None:
    if not _has_branch_context(contract_source):
        return None
    if not _SWEEP_OR_RESCUE_NAME_RE.search(fn.name):
        return None
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _BRANCH_FUNCTION_CONTEXT_RE.search(text):
        return None
    if not _has_privileged_or_emergency_context(fn):
        return None
    if not _moves_protected_funds(fn):
        return None
    if _has_claim_protection(fn):
        return None
    if _has_branch_protection(fn):
        return None
    return "deprecated-market-or-branch-sweep"


def _emergency_withdraw_branch_state(fn: FunctionSlice, contract_source: str) -> str | None:
    if not _has_branch_context(contract_source):
        return None
    if not _EMERGENCY_WITHDRAW_NAME_RE.search(fn.name):
        return None
    if not _moves_protected_funds(fn):
        return None
    if _has_branch_protection(fn) or _has_claim_protection(fn):
        return None
    return "branch-state-emergency-withdraw"


def _candidate_branch(fn: FunctionSlice, contract_source: str) -> str | None:
    for branch_fn in (
        _deprecated_market_sweep_branch,
        _pending_claim_sweep_branch,
        _emergency_withdraw_branch_state,
    ):
        branch = branch_fn(fn, contract_source)
        if branch is not None:
            return branch
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _CONTEXT_HINT_RE.search(clean):
        return []

    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [ContractSlice(clean, 1)]
    for contract in contracts:
        if not (_has_claim_context(contract.source) or _has_branch_context(contract.source)):
            continue
        for fn in _split_functions(contract.source, contract.start_line):
            if not _is_public(fn):
                continue
            if _is_skipped(fn, file_path):
                continue
            branch = _candidate_branch(fn, contract.source)
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
                        f"{DETECTOR_NAME}: branch {branch}: privileged sweep, "
                        "rescue, or emergency withdrawal moves protected funds "
                        "while pending claims, user balances, deprecated markets, "
                        "or branch state remain unresolved. NOT_SUBMIT_READY."
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
