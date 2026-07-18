"""
emergency-branch-recipient-reassignment-fire27

Fire27 Solidity detector for emergency branch, channel, market, route, or
claim status updates that pause, reject, deprecate, cancel, halt, or close a
route while a pending recipient or claim ledger exists, without reassigning the
recipient or preserving claimability in the same function.

Source records:
* reference/patterns.dsl/branch-status-update-without-recipient-reassignment.yaml
* reference/patterns.dsl/bridge-strict-channel-nonce-blocks-governance.yaml
* reference/patterns.dsl/emergency-withdraw-bypass-lock.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "emergency-branch-recipient-reassignment-fire27"
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

_ROUTE_CONTEXT_RE = re.compile(
    r"(?:branch|channel|route|market|claim|dispute|game|proof|message|"
    r"bridge|settlement|payout|recipient|beneficiary|payee|claimant)",
    re.IGNORECASE,
)
_PENDING_RECIPIENT_STATE_RE = re.compile(
    r"\bmapping\s*\([^;]+=>\s*address(?:\s+payable)?\s*\)"
    r"[^;]*(?:pending|recipient|receiver|beneficiary|payee|claimant|bondRecipient)|"
    r"\baddress(?:\s+payable)?\s+"
    r"(?:(?:public|private|internal|constant|immutable)\s+)*"
    r"(?:pendingRecipient|recipient|receiver|beneficiary|payee|claimant|"
    r"bondRecipient|claimRecipient|payoutRecipient)\w*|"
    r"\bstruct\s+[A-Za-z_][A-Za-z0-9_]*\s*\{[^{}]*"
    r"address(?:\s+payable)?\s+"
    r"(?:pendingRecipient|recipient|receiver|beneficiary|payee|claimant|"
    r"bondRecipient|claimRecipient|payoutRecipient)\w*",
    re.IGNORECASE | re.DOTALL,
)
_PENDING_CLAIM_STATE_RE = re.compile(
    r"\bmapping\s*\([^;]+=>\s*uint(?:8|16|32|64|128|256)?\s*\)"
    r"[^;]*(?:pending|claimable|unclaimed|owed|escrow|payout|recipient)|"
    r"\buint(?:8|16|32|64|128|256)?\s+"
    r"(?:(?:public|private|internal|constant|immutable)\s+)*"
    r"(?:pending|claimable|unclaimed|owed|escrow|payout|recipient|"
    r"totalPending|pendingClaims|claimLiabilit)\w*",
    re.IGNORECASE,
)
_CLAIM_ENTRY_RE = re.compile(
    r"\bfunction\s+(?:claim\w*|withdraw\w*|redeem\w*|claimCredit|"
    r"claimPayout|settleClaim|finalizeClaim|release\w*)\s*\(",
    re.IGNORECASE,
)
_CONTROL_CONTEXT_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|"
    r"onlyGuardian|requiresAuth|restricted|auth|emergencyOnly)\b|"
    r"\b(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)\s*"
    r"(?:owner|admin|governance|governor|guardian|controller|manager)|"
    r"\b(?:emergency|pause|paused|reject|deprecat|close|halt|disable|cancel)\b",
    re.IGNORECASE,
)
_STATUS_UPDATE_RE = re.compile(
    r"(?:"
    r"\b(?:branch|channel|route|market|claim|dispute|game|proof|message)"
    r"[A-Za-z0-9_]*(?:\s*\[[^\]]+\]\s*)?"
    r"(?:\.\s*)?(?:status|state|paused|deprecated|closed)|"
    r"\b(?:status|state|outcome|result|isPaused|isDeprecated|isClosed|"
    r"routePaused|branchPaused|channelPaused|marketDeprecated|claimStatus|"
    r"channelStatus|branchStatus|marketStatus)\b(?:\s*\[[^\]]+\]\s*)?"
    r")\s*=\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?"
    r"(?:Paused|Rejected|Deprecated|Closed|EmergencyClosed|Cancelled|Canceled|"
    r"Invalid|Halted|Blocked|Disabled|Voided|Frozen|true)\b",
    re.IGNORECASE,
)
_STATUS_CALL_RE = re.compile(
    r"\b(?:pause|reject|deprecate|close|halt|disable|cancel|emergencyClose)"
    r"[A-Za-z0-9_]*\s*\([^;]*(?:branch|channel|route|market|claim|"
    r"Status\s*\.\s*(?:Paused|Rejected|Deprecated|Closed|Cancelled|Halted))",
    re.IGNORECASE,
)
_RECIPIENT_REASSIGNMENT_RE = re.compile(
    r"(?:\b|\.\s*)(?:pendingRecipient|recipient|receiver|beneficiary|payee|claimant|"
    r"bondRecipient|claimRecipient|payoutRecipient)\w*"
    r"(?:\s*\[[^\]]+\]\s*)?(?:\.\s*[A-Za-z_][A-Za-z0-9_]*\s*)?\s*=",
    re.IGNORECASE,
)
_CLAIM_PRESERVATION_RE = re.compile(
    r"\b(?:claimable|pendingClaims|pendingPayout|unclaimed|owed|escrow|"
    r"liability|reserved)\w*(?:\s*\[[^;]+\]\s*)?(?:\+=|=)|"
    r"(?:\b|_)(?:preserve|reassign|migrate|rollover|refund|credit|escrow|unlock|"
    r"protect|settle|release)[A-Za-z0-9_]*"
    r"(?:Recipient|Receiver|Beneficiary|Claim|Payout|Route|Branch|Channel|Market)"
    r"[A-Za-z0-9_]*\s*\(",
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


def _has_pending_recipient_or_claim_state(source: str) -> bool:
    return bool(
        _ROUTE_CONTEXT_RE.search(source)
        and (_PENDING_RECIPIENT_STATE_RE.search(source) or _PENDING_CLAIM_STATE_RE.search(source))
        and _CLAIM_ENTRY_RE.search(source)
    )


def _is_public(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header))


def _is_skipped(fn: FunctionSlice, file_path: str) -> bool:
    return bool(_SKIP_RE.search(file_path) or _SKIP_RE.search(fn.name))


def _updates_terminal_status(fn: FunctionSlice) -> bool:
    return bool(_STATUS_UPDATE_RE.search(fn.body) or _STATUS_CALL_RE.search(fn.body))


def _preserves_recipient_or_claimability(fn: FunctionSlice) -> bool:
    return bool(_RECIPIENT_REASSIGNMENT_RE.search(fn.body) or _CLAIM_PRESERVATION_RE.search(fn.body))


def _candidate_branch(fn: FunctionSlice) -> str | None:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _ROUTE_CONTEXT_RE.search(text):
        return None
    if not _CONTROL_CONTEXT_RE.search(text):
        return None
    if not _updates_terminal_status(fn):
        return None
    if _preserves_recipient_or_claimability(fn):
        return None
    return "status-update-without-recipient-preservation"


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not re.search(
        r"(?i)\b(?:branch|channel|route|market|claim|recipient|beneficiary|"
        r"pause|reject|deprecat|emergency|halt|close|cancel|claimable|pending)",
        clean,
    ):
        return []

    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [ContractSlice(clean, 1)]
    for contract in contracts:
        if not _has_pending_recipient_or_claim_state(contract.source):
            continue
        for fn in _split_functions(contract.source, contract.start_line):
            if not _is_public(fn):
                continue
            if _is_skipped(fn, file_path):
                continue
            branch = _candidate_branch(fn)
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
                        f"{DETECTOR_NAME}: branch {branch}: emergency or "
                        "administrative branch, channel, market, route, or "
                        "claim status update reaches a pause, reject, "
                        "deprecate, halt, cancel, or close state while pending "
                        "recipient or claim state exists, but the function does "
                        "not reassign the recipient or preserve claimability. "
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
