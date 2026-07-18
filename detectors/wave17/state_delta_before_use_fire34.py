"""
state-delta-before-use-fire34

Solidity regex detector for a state-change-between-check-and-use shape:
a function snapshots a sender binding, balance, fee, price, or token delta,
checks that snapshot, crosses an external call or mutable-state update, then
uses the stale value for authorization, settlement, or accounting.

Source refs:
- reports/detector_lift_fire33_20260605/post_priorities_all.md
- reference/patterns.dsl/state-change-between-check-and-use.yaml
- detectors/wave17/state_check_token_delta_fire31.py
- detectors/wave17/state_tocou_external_balance_fire32.py

Hits are candidate evidence only. They are NOT_SUBMIT_READY and must not be
used as exploit proof without R40, R76, and R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "state-delta-before-use-fire34"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False
SUBMISSION_POSTURE = "NOT_SUBMIT_READY"


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


@dataclass
class TrackedSnapshot:
    name: str
    source_kind: str
    assign_start: int
    check_start: int


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b", re.IGNORECASE)
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_REENTRANCY_GUARD_RE = re.compile(
    r"(?is)\b(?:nonReentrant|ReentrancyGuard|_reentrancyGuardEntered|"
    r"reentrancyLock|locked\s*=\s*true)\b"
)

_SURFACE_RE = re.compile(
    r"(?is)\b(?:msg\.sender|sender|payer|beneficiary|recipient|ownerOf|"
    r"balanceOf|allowance|balance|fee|fees|feeBps|premium|commission|"
    r"price|oracle|twap|quote|delta|received|net|sync|update|refresh|"
    r"accrue|checkpoint|settle|finalize|execute|transfer|safeTransfer|"
    r"transferFrom|call|delegatecall|hook|callback)\b"
)
_BOUNDARY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:safeTransferFrom|transferFrom|safeTransfer|transfer|send|"
    r"deposit|withdraw|redeem|borrow|repay|liquidate|swap|joinPool|"
    r"exitPool|rebalance|harvest|claim|settle|sync|execute|executeCall|"
    r"flashLoan|pull|push|notify|before[A-Za-z0-9_]*|after[A-Za-z0-9_]*)"
    r"\s*(?:\{|\.value\s*\(|\()|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:call|delegatecall|functionCall)"
    r"\s*(?:\{|\.value\s*\(|\()|"
    r"\bI[A-Za-z0-9_]*(?:Hook|Hooks|Callback|Receiver|Policy|Manager|"
    r"Router|Adapter|Vault|Pool|Token|Market|Strategy|Oracle|Controller|"
    r"Protocol)[A-Za-z0-9_]*\s*\([^;)]*\)\s*\.[A-Za-z_][A-Za-z0-9_]*"
    r"\s*\(|"
    r"\b_?(?:sync|update|refresh|accrue|checkpoint|settle|fill|consume|"
    r"mark|cancel|close|finalize|execute|apply|reprice|rebalance|collect|"
    r"harvest|pull|push)[A-Za-z0-9_]*\s*\("
    r")"
)

_SOURCE_EXPR_PART = (
    r"\b(?:msg\.sender|tx\.origin|ownerOf\s*\(|senderOf\s*\(|"
    r"payerOf\s*\(|recipientOf\s*\(|beneficiaryOf\s*\(|currentSender|"
    r"authorizedSender|balanceOf\s*\(|allowance\s*\(|totalAssets\s*\(|"
    r"totalSupply\s*\(|getReserves?\s*\(|reserve[01]?|_reserve[01]?|"
    r"balance|balances|fee|fees|feeBps|rate|premium|commission|"
    r"price|prices|oracle|twap|quote|quoteOut|getAmountOut|"
    r"delta|received|netReceived|actualReceived|amountIn|amountOut)\b"
)
_SOURCE_EXPR_RE = re.compile(_SOURCE_EXPR_PART, re.IGNORECASE | re.DOTALL)
_TRACKED_NAME_RE = re.compile(
    r"(?i)(?:before|pre|cached|snapshot|old|prior|sender|payer|"
    r"beneficiary|recipient|owner|balance|fee|price|quote|rate|premium|"
    r"delta|received|net|amountIn|amountOut)"
)
_ASSIGN_RE = re.compile(
    r"(?is)"
    r"(?:\b(?:uint|uint256|uint128|uint64|uint32|int|int256|int128|"
    r"int64|int32|address|bytes32)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;{}]*);"
)
_CHECK_RE = re.compile(r"(?is)\b(?:require|assert|if)\s*\((?P<expr>[^;{}]*)\)")
_FRESH_NAME_RE = re.compile(
    r"(?i)(?:after|post|fresh|actual|received|delta|net|current|latest|"
    r"recomputed|revalidated|updated|new)"
)
_DELTA_NAME_RE = re.compile(
    r"(?i)(?:actualReceived|receivedDelta|deltaIn|deltaOut|balanceDelta|"
    r"netReceived|netDelta|postBalance|balanceAfter|feeAfter|priceAfter|"
    r"senderAfter|freshSender|freshBalance|freshFee|freshPrice|"
    r"currentPrice|currentFee|latestPrice|latestFee)"
)
_VALUE_USE_RE = re.compile(
    r"(?is)\b(?:transfer|safeTransfer|safeTransferFrom|mint|_mint|burn|"
    r"_burn|payout|pay|settle|release|claim|withdraw|redeem|borrow|repay|"
    r"liquidate|seize|charge|credit|debit|account|authorize|settlement|"
    r"finalize)[A-Za-z0-9_]*\s*\("
)
_VALUE_USE_PREFIX = (
    r"\b(?:transfer|safeTransfer|safeTransferFrom|mint|_mint|burn|"
    r"_burn|payout|pay|settle|release|claim|withdraw|redeem|borrow|repay|"
    r"liquidate|seize|charge|credit|debit|account|authorize|settlement|"
    r"finalize)[A-Za-z0-9_]*\s*\("
)
_ACCOUNTING_WRITE_PART = (
    r"\b(?:balances?|credits?|debts?|fees?|proceeds|settlements?|"
    r"rewards?|claims?|orders?|positions?|escrow|accounted|payouts?)\s*\["
)
_ACCOUNTING_WRITE_RE = re.compile(_ACCOUNTING_WRITE_PART, re.IGNORECASE | re.DOTALL)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


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
    close_brace = _find_matching_delimiter(source, open_brace, "{", "}")
    if close_brace < 0:
        return None, open_brace
    return source[open_brace + 1 : close_brace], close_brace + 1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        j = close_paren + 1
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, close_paren + 1)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue
        header = source[match.start() : body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _line_for_offset(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, offset))


def _token_re(name: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(name)}\b")


def _check_uses_name(prefix: str, name: str, start: int) -> re.Match[str] | None:
    token = _token_re(name)
    for check in _CHECK_RE.finditer(prefix, start):
        if token.search(check.group("expr")):
            return check
    return None


def _source_kind(expr: str, name: str) -> str | None:
    lower = expr.lower()
    name_lower = name.lower()
    if any(word in lower for word in ("delta", "received", "netreceived", "amountin", "amountout")):
        return "token delta"
    if any(word in name_lower for word in ("delta", "received", "net", "amountin", "amountout")):
        return "token delta"
    if "msg.sender" in lower or "tx.origin" in lower:
        return "sender"
    if any(word in name_lower for word in ("sender", "payer", "beneficiary", "recipient", "owner")):
        return "sender"
    if any(word in lower for word in ("ownerof", "senderof", "payerof", "recipientof", "beneficiaryof")):
        return "sender"
    if "balanceof" in lower or "allowance" in lower or "balance" in name_lower:
        return "balance"
    if "price" in lower or "oracle" in lower or "twap" in lower or "quote" in lower:
        return "price"
    if any(word in name_lower for word in ("price", "quote")):
        return "price"
    if any(word in lower for word in ("fee", "feebps", "premium", "commission")):
        return "fee"
    if any(word in name_lower for word in ("fee", "premium", "commission", "rate")):
        return "fee"
    if _SOURCE_EXPR_RE.search(expr) or _TRACKED_NAME_RE.search(name):
        return "mutable state"
    return None


def _tracked_snapshots_before(body: str, boundary_start: int) -> list[TrackedSnapshot]:
    prefix = body[:boundary_start]
    tracked: list[TrackedSnapshot] = []
    seen: set[str] = set()
    for assignment in _ASSIGN_RE.finditer(prefix):
        name = assignment.group("name")
        if name in seen:
            continue
        expr = assignment.group("expr")
        kind = _source_kind(expr, name)
        if kind is None:
            continue
        if not _TRACKED_NAME_RE.search(name) and not _SOURCE_EXPR_RE.search(expr):
            continue
        check = _check_uses_name(prefix, name, assignment.end())
        if check is None:
            continue
        seen.add(name)
        tracked.append(
            TrackedSnapshot(
                name=name,
                source_kind=kind,
                assign_start=assignment.start(),
                check_start=check.start(),
            )
        )
    return tracked


def _statement_ranges(source: str, start: int) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    stmt_start = start
    depth = 0
    for i in range(start, len(source)):
        char = source[i]
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == ";" and depth == 0:
            ranges.append((stmt_start, i + 1, source[stmt_start : i + 1]))
            stmt_start = i + 1
    tail = source[stmt_start:].strip()
    if tail:
        ranges.append((stmt_start, len(source), source[stmt_start:]))
    return ranges


def _fresh_update_statement(statement: str, tracked: TrackedSnapshot) -> bool:
    name = tracked.name
    token = _token_re(name)
    if re.search(rf"(?is)\b{re.escape(name)}\b\s*=\s*[^;]*{_SOURCE_EXPR_PART}", statement):
        return True
    if token.search(statement) and _DELTA_NAME_RE.search(statement):
        if re.search(rf"(?is)(?:-\s*{re.escape(name)}\b|\b{re.escape(name)}\b\s*[+\-])", statement):
            return True
    if token.search(statement) and _SOURCE_EXPR_RE.search(statement):
        if re.search(r"(?is)\b(?:require|assert|if)\s*\(", statement):
            return True
    return False


def _has_fresh_revalidation(segment: str, tracked: TrackedSnapshot) -> bool:
    if re.search(rf"(?is)\b{re.escape(tracked.name)}\b\s*=\s*[^;]*{_SOURCE_EXPR_PART}", segment):
        return True
    if _FRESH_NAME_RE.search(segment) and _SOURCE_EXPR_RE.search(segment):
        if re.search(r"(?is)\b(?:require|assert|if)\s*\(", segment):
            return True
    if _DELTA_NAME_RE.search(segment) and _SOURCE_EXPR_RE.search(segment):
        if re.search(r"(?is)\b(?:require|assert|if)\s*\(", segment):
            return True
    return False


def _is_stale_use_statement(statement: str, tracked: TrackedSnapshot) -> bool:
    token = _token_re(tracked.name)
    if token.search(statement) is None:
        return False
    if _fresh_update_statement(statement, tracked):
        return False
    name = re.escape(tracked.name)
    return bool(
        re.search(
            rf"(?is)"
            rf"(?:"
            rf"\breturn\b[^;]*\b{name}\b|"
            rf"\b(?:require|assert|if)\s*\([^;{{}}]*\b{name}\b|"
            rf"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]*\b{name}\b|"
            rf"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:\+=|-=|\*=|/=)\s*"
            rf"[^;]*\b{name}\b|"
            rf"{_VALUE_USE_PREFIX}[^;]*\b{name}\b|"
            rf"\[[^;\]]*\b{name}\b[^;\]]*\]\s*(?:=|\+=|-=)|"
            rf"{_ACCOUNTING_WRITE_PART}[^;]*(?:=|\+=|-=)[^;]*\b{name}\b|"
            rf"\b{name}\b\s*(?:[+\-*/%]|<<|>>)|"
            rf"(?:[+\-*/%]|<<|>>)\s*\b{name}\b"
            rf")",
            statement,
        )
    )


def _stale_use_after_boundary(
    body: str,
    boundary: re.Match[str],
    tracked: TrackedSnapshot,
) -> tuple[int, str] | None:
    segment_start = boundary.end()
    for stmt_start, _stmt_end, statement in _statement_ranges(body, segment_start):
        before_statement = body[segment_start:stmt_start]
        if _has_fresh_revalidation(before_statement, tracked):
            return None
        if _fresh_update_statement(statement, tracked):
            continue
        if _is_stale_use_statement(statement, tracked):
            return stmt_start, statement.strip()
    return None


def _match_function(fn: FunctionSlice) -> tuple[TrackedSnapshot, re.Match[str], int] | None:
    for boundary in _BOUNDARY_RE.finditer(fn.body):
        tracked_values = _tracked_snapshots_before(fn.body, boundary.start())
        if not tracked_values:
            continue
        for tracked in tracked_values:
            stale_use = _stale_use_after_boundary(fn.body, boundary, tracked)
            if stale_use is None:
                continue
            use_offset, _statement = stale_use
            return tracked, boundary, use_offset
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if not source:
        return findings
    if _SURFACE_RE.search(source) is None:
        return findings

    stripped = _strip_comments_and_strings(source)
    for fn in _split_functions(stripped):
        if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
            continue
        if _VIEW_OR_PURE_RE.search(fn.header):
            continue
        if _REENTRANCY_GUARD_RE.search(fn.header) or _REENTRANCY_GUARD_RE.search(fn.body):
            continue
        matched = _match_function(fn)
        if matched is None:
            continue
        tracked, _boundary, use_offset = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_offset(fn, use_offset),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` checks pre-boundary {tracked.source_kind} "
                    f"snapshot `{tracked.name}`, crosses an external call or "
                    "state mutation, then uses that stale value for "
                    "authorization, settlement, or accounting without a fresh "
                    "post-boundary revalidation."
                ),
            )
        )
    return findings


__all__ = [
    "scan",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "PROMOTION_ALLOWED",
    "SUBMISSION_POSTURE",
]
