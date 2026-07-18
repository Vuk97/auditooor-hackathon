"""
emergency-unpause-bypass-fire29

Fire29 Solidity detector for emergency bypasses where a pause, emergency, or
market-deprecated state is defeated or misapplied by a secondary unpause,
resume, sweep, withdraw, liquidation, or admin recovery path.

Source records:
* reference/patterns.dsl.zellic_k2_mined/emergency-admin-can-unpause-reserves-breaking-pause-asymmetry.yaml
* reference/patterns.dsl.r74_mined_oz.PROMOTED/paused-token-blocks-vault-emergency-withdrawal.yaml
* reference/patterns.dsl/glider-pausable-contract-cannot-unpause.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "emergency-unpause-bypass-fire29"
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

_EMERGENCY_SURFACE_RE = re.compile(
    r"\b(?:Pausable|pause|paused|unpause|resume|emergency|guardian|"
    r"deprecated|deprecat|frozen|freeze|disabled|halted|marketPaused|"
    r"reservePaused|whenNotPaused|whenPaused|notDeprecated|notFrozen)\b",
    re.IGNORECASE,
)
_PRIMARY_GUARD_RE = re.compile(
    r"\b(?:whenNotPaused|notPaused|marketNotPaused|reserveNotPaused|"
    r"whenMarketActive|onlyActiveMarket|notDeprecated|notFrozen|"
    r"notDisabled|notHalted)\b|"
    r"\brequire\s*\([^;{}]*(?:!\s*[A-Za-z0-9_\.\[\]]*paused|"
    r"paused\s*==\s*false|!\s*[A-Za-z0-9_\.\[\]]*deprecated|"
    r"deprecated\s*==\s*false|!\s*[A-Za-z0-9_\.\[\]]*frozen|"
    r"frozen\s*==\s*false|!\s*[A-Za-z0-9_\.\[\]]*disabled|"
    r"disabled\s*==\s*false)[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_WHEN_PAUSED_OR_EMERGENCY_RE = re.compile(
    r"\b(?:whenPaused|onlyPaused|whenEmergency|onlyEmergencyMode|"
    r"emergencyModeOnly)\b|"
    r"\brequire\s*\([^;{}]*(?:paused|emergency|halted)\s*==\s*true[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_STRICT_UNPAUSE_RE = re.compile(
    r"\bfunction\s+[A-Za-z0-9_]*(?:unpause|resume|reactivate|enable)[A-Za-z0-9_]*\s*\("
    r"[^{};]*(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyPoolAdmin|"
    r"ADMIN_ROLE|POOL_ADMIN|validate_admin|validateAdmin)",
    re.IGNORECASE | re.DOTALL,
)
_EMERGENCY_GUARD_RE = re.compile(
    r"\b(?:onlyEmergencyAdmin|onlyGuardian|onlyPauser|onlyEmergency|"
    r"emergencyOnly|guardianOnly|validate_emergency_admin|"
    r"validateEmergencyAdmin|EMERGENCY_ADMIN|GUARDIAN_ROLE|PAUSER_ROLE|"
    r"emergencyAdmin|guardian|pauser)\b",
    re.IGNORECASE,
)
_ADMIN_GUARD_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyPoolAdmin|"
    r"ADMIN_ROLE|POOL_ADMIN|validate_admin|validateAdmin)\b",
    re.IGNORECASE,
)
_UNPAUSE_OR_RESUME_NAME_RE = re.compile(
    r"(?:unpause|resume|reactivate|enable|set.*pause|set.*paused|"
    r"update.*pause|configure.*pause|set.*deprecated|undeprecate|"
    r"set.*frozen|set.*disabled)",
    re.IGNORECASE,
)
_STATE_FALSE_ASSIGN_RE = re.compile(
    r"\b(?:isPaused|paused|pauseState|marketPaused|reservePaused|"
    r"isReservePaused|marketDeprecated|isDeprecated|deprecated|"
    r"isFrozen|frozen|disabled|halted)"
    r"(?:\s*\[[^\]]+\]\s*)?(?:\.\s*[A-Za-z_][A-Za-z0-9_]*\s*)?"
    r"\s*=\s*(?:false|0|[A-Za-z_][A-Za-z0-9_]*\.(?:Active|Open|Enabled|Live)|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Paused|Deprecated|Frozen|Disabled)?)\b",
    re.IGNORECASE,
)
_BOOL_PAUSE_PARAM_RE = re.compile(
    r"\bbool\s+(?P<param>paused_?|isPaused|pause|deprecated_?|isDeprecated|frozen|disabled)\b",
    re.IGNORECASE,
)

_RECOVERY_NAME_RE = re.compile(
    r"(?:sweep|rescue|recover|adminWithdraw|withdrawAll|emergencySweep|"
    r"drain|forceWithdraw|recoverMarket|sweepMarket)",
    re.IGNORECASE,
)
_LIQUIDATION_NAME_RE = re.compile(
    r"(?:liquidat|seize|closePosition|forceClose|settleBadDebt|"
    r"recoverBadDebt|writeOff|absorb)",
    re.IGNORECASE,
)
_EMERGENCY_WITHDRAW_NAME_RE = re.compile(
    r"(?:emergencyWithdraw|panicWithdraw|breakGlassWithdraw|"
    r"emergencyExit|emergencyRedeem|emergencyClaim)",
    re.IGNORECASE,
)
_STATEFUL_CONTEXT_RE = re.compile(
    r"\b(?:market|reserve|vault|collateral|position|debt|borrower|claim|"
    r"asset|token|balance|share|withdraw|liquidat|deprecated|paused|frozen)\b",
    re.IGNORECASE,
)
_VALUE_TRANSFER_RE = re.compile(
    r"\b(?:safeTransfer|transfer|sendValue|send)\s*\(|"
    r"\.call\s*\{\s*value\s*:",
    re.IGNORECASE,
)
_FULL_OR_STATEFUL_BALANCE_RE = re.compile(
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|"
    r"\baddress\s*\(\s*this\s*\)\s*\.\s*balance\b|"
    r"\bthis\s*\.\s*balance\b|"
    r"\b(?:reserveBalance|vaultBalance|poolBalance|collateralBalance|"
    r"marketBalance|totalCollateral|totalAssets|totalDebt|balances?|shares?)\b",
    re.IGNORECASE,
)
_SAFE_RECOVERY_RE = re.compile(
    r"\b(?:reserved|protectedBalance|sweepable|owed|liabilit|"
    r"totalPending|pendingClaims|claimable|unclaimed|settlePending|"
    r"escrow|onlyDust|strayToken|nonReserveToken|nonMarketToken|"
    r"notProtectedToken|allowWhilePaused|allowedDuringPause)\b|"
    r"\b(?:balance|amount|cash)\s*-\s*(?:reserved|protectedBalance|"
    r"totalPending|pending|claimable|unclaimed|liabilit|owed)",
    re.IGNORECASE,
)
_LIQUIDATION_EXCEPTION_RE = re.compile(
    r"\b(?:whenLiquidationAllowed|liquidationExempt|allowLiquidationWhilePaused|"
    r"allowWhilePaused|ignorePauseForLiquidation|debtReductionMode|"
    r"closeoutException|bypassPausedForDebtReduction|liquidationKeeper)\b",
    re.IGNORECASE,
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


def _has_pause_guard(fn: FunctionSlice) -> bool:
    return bool(_PRIMARY_GUARD_RE.search(fn.header + "\n" + fn.body))


def _has_contract_guarded_primary(contract_source: str) -> bool:
    return bool(_PRIMARY_GUARD_RE.search(contract_source))


def _has_strict_unpause(contract_source: str) -> bool:
    return bool(_STRICT_UNPAUSE_RE.search(contract_source))


def _unpause_bypass_branch(fn: FunctionSlice, contract_source: str) -> str | None:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _UNPAUSE_OR_RESUME_NAME_RE.search(fn.name):
        return None
    if not _EMERGENCY_GUARD_RE.search(text):
        return None
    if _ADMIN_GUARD_RE.search(fn.header):
        return None
    if not _has_strict_unpause(contract_source):
        return None

    bool_param = _BOOL_PAUSE_PARAM_RE.search(fn.header)
    if bool_param:
        param = bool_param.group("param")
        if re.search(
            rf"\b(?:isPaused|paused|marketPaused|reservePaused|isReservePaused|"
            rf"marketDeprecated|isDeprecated|deprecated|isFrozen|frozen|disabled)"
            rf"(?:\s*\[[^\]]+\]\s*)?\s*=\s*{re.escape(param)}\b",
            fn.body,
            re.IGNORECASE,
        ):
            return "emergency-role-bidirectional-pause-setter"

    if _STATE_FALSE_ASSIGN_RE.search(fn.body):
        return "emergency-role-unpause-or-resume"
    return None


def _recovery_bypass_branch(fn: FunctionSlice) -> str | None:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _RECOVERY_NAME_RE.search(fn.name):
        return None
    if _has_pause_guard(fn):
        return None
    if _SAFE_RECOVERY_RE.search(text):
        return None
    if not (_STATEFUL_CONTEXT_RE.search(text) and _VALUE_TRANSFER_RE.search(fn.body)):
        return None
    if not _FULL_OR_STATEFUL_BALANCE_RE.search(fn.body):
        return None
    return "unguarded-secondary-sweep-or-admin-recovery"


def _liquidation_bypass_branch(fn: FunctionSlice) -> str | None:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _LIQUIDATION_NAME_RE.search(text):
        return None
    if _has_pause_guard(fn):
        return None
    if _LIQUIDATION_EXCEPTION_RE.search(text):
        return None
    if not _STATEFUL_CONTEXT_RE.search(text):
        return None
    if not (
        _VALUE_TRANSFER_RE.search(fn.body)
        or re.search(r"\b(?:debt|collateral|positions?|health)\w*(?:\s*\[[^\]]+\]\s*)?\s*=", fn.body, re.IGNORECASE)
    ):
        return None
    return "unguarded-secondary-liquidation-or-debt-recovery"


def _emergency_withdraw_blocked_branch(fn: FunctionSlice) -> str | None:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _EMERGENCY_WITHDRAW_NAME_RE.search(fn.name):
        return None
    if _WHEN_PAUSED_OR_EMERGENCY_RE.search(text):
        return None
    if not _has_pause_guard(fn):
        return None
    if not (_VALUE_TRANSFER_RE.search(fn.body) or _FULL_OR_STATEFUL_BALANCE_RE.search(fn.body)):
        return None
    return "emergency-withdrawal-gated-by-global-pause"


def _candidate_branch(fn: FunctionSlice, contract_source: str) -> str | None:
    for branch_fn in (
        lambda item: _unpause_bypass_branch(item, contract_source),
        _recovery_bypass_branch,
        _liquidation_bypass_branch,
        _emergency_withdraw_blocked_branch,
    ):
        branch = branch_fn(fn)
        if branch is not None:
            return branch
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _EMERGENCY_SURFACE_RE.search(clean):
        return []

    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [ContractSlice(clean, 1)]
    for contract in contracts:
        if not _has_contract_guarded_primary(contract.source):
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
                        f"{DETECTOR_NAME}: branch {branch}: pause, emergency, "
                        "or market-deprecated state is bypassed or inverted by "
                        "a secondary unpause, resume, sweep, withdraw, "
                        "liquidation, or admin recovery path. NOT_SUBMIT_READY."
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
