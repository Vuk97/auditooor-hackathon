"""
readonly-reentrancy-accounting-fire35

Solidity regex detector for read-only or callback reentrancy accounting
drift: an entrypoint snapshots accounting indexes, reserves, exchange rates,
or cached totals, then crosses an external view or hook boundary and later
uses the stale snapshot for mint, burn, borrow, redeem, or settlement without
refreshing the accounting value.

Source refs:
- reports/detector_lift_fire34_20260605/post_priorities_all.md
- reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml
- reference/patterns.dsl/fx-euler-erc4626-view-readonly-reentrancy-unguarded.yaml
- detectors/wave17/callback_ledger_settlement_fire33.py
- detectors/wave17/read_only_reentrancy_view.py

Provenance and evidence limits:
- R37: this detector emits source-state candidate evidence only.
- R40: fixtures are detector smoke tests, not exploit PoCs.
- R76: candidate promotion must grep-verify any cited excerpt exists.
- R80: detector hits are not load-bearing exploit evidence.

Submission posture: NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "readonly-reentrancy-accounting-fire35"
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
class AccountingSnapshot:
    name: str
    source_kind: str
    assign_start: int


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
_GUARD_RE = re.compile(
    r"(?is)\b(?:nonReentrant|nonreentrant|nonReentrantView|"
    r"checkNotInVaultContext|ensureNotInVaultContext|noReentrancy|"
    r"reentrancyGuard|ReentrancyGuard|_reentrancyGuardEntered|"
    r"_status\s*=\s*_ENTERED|locked\s*=\s*true|_locked\s*=\s*true|"
    r"entered\s*=\s*true|_entered\s*=\s*true|reentrancyLock)\b"
)
_SURFACE_RE = re.compile(
    r"(?is)\b(?:totalAssets|totalSupply|totalDebt|totalBorrow|"
    r"borrowIndex|supplyIndex|rewardIndex|liquidityIndex|exchangeRate|"
    r"pricePerShare|virtualPrice|getRate|getReserves|reserve|reserves|"
    r"cachedTotal|cachedAssets|cachedShares|accountingIndex|"
    r"mint|burn|borrow|redeem|settle|settlement|hook|callback|oracle|"
    r"rateProvider|preview|convertTo)\b"
)
_EXTERNAL_VIEW_OR_HOOK_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:"
    r"before[A-Za-z0-9_]*|after[A-Za-z0-9_]*|"
    r"on[A-Za-z0-9_]*(?:Received|Callback|Hook|Mint|Burn|Borrow|"
    r"Redeem|Settle)?|callback|hook|"
    r"latest[A-Za-z0-9_]*|peek|consult|quote[A-Za-z0-9_]*|"
    r"getRate|getReserves?|getPrice|getVirtualPrice|virtualPrice|"
    r"pricePerShare|preview[A-Za-z0-9_]*|convertTo[A-Za-z0-9_]*|"
    r"totalAssets|totalSupply|balanceOf)"
    r"\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Hook|Hooks|Callback|Receiver|Oracle|Feed|"
    r"RateProvider|Vault|Pool|Pair|Market|Strategy)[A-Za-z0-9_]*"
    r"\s*\([^;)]*\)\s*\.[A-Za-z_][A-Za-z0-9_]*\s*\("
    r")"
)
_ASSIGN_RE = re.compile(
    r"(?is)"
    r"(?:\b(?:uint|uint256|uint128|uint112|uint96|uint64|uint32|int|"
    r"int256|address|bytes32)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;{}]*);"
)
_ACCOUNTING_EXPR_PART = (
    r"\b(?:totalAssets|totalSupply|totalDebt|totalBorrow|"
    r"totalBorrowAssets|totalBorrowShares|totalReserves|cash|"
    r"exchangeRate(?:Stored|Current)?|pricePerShare|getRate|"
    r"virtualPrice|getVirtualPrice|convertToAssets|convertToShares|"
    r"previewDeposit|previewMint|previewRedeem|previewWithdraw|"
    r"getReserves?|reserve0|reserve1|reserves?|borrowIndex|supplyIndex|"
    r"rewardIndex|liquidityIndex|accountingIndex|accumulator|"
    r"cachedTotal|cachedAssets|cachedShares|cachedDebt|cachedBorrow|"
    r"balanceOf)\b"
)
_ACCOUNTING_EXPR_RE = re.compile(_ACCOUNTING_EXPR_PART, re.IGNORECASE | re.DOTALL)
_ACCOUNTING_NAME_RE = re.compile(
    r"(?i)(?:before|pre|snapshot|cached|stored|old|prior|rate|exchange|"
    r"index|reserve|total|assets|supply|shares|debt|borrow|cash|"
    r"price|virtual|accumulator)"
)
_FRESH_NAME_RE = re.compile(
    r"(?i)(?:after|post|fresh|latest|current|updated|recomputed|"
    r"revalidated|new)"
)
_REFRESH_CALL_RE = re.compile(
    r"(?is)\b(?:refresh|sync|update|accrue|checkpoint|recompute|"
    r"reload)[A-Za-z0-9_]*(?:Rate|Index|Reserve|Accounting|Total|"
    r"Assets|Supply|Debt|Borrow)?\s*\("
)
_SINK_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b_?(?:mint|burn)\s*\(|"
    r"\b(?:borrow|redeem|withdraw|settle|settlement|finalize|"
    r"finalise|liquidate|repay|credit|debit|account)[A-Za-z0-9_]*\s*\(|"
    r"\b(?:balances?|shares?|debts?|borrowShares|borrowDebt|"
    r"settlements?|credits?|positions?|collateral|owed|payouts?)\s*\["
    r"[^;\]]*\]\s*(?:=|\+=|-=)|"
    r"\b(?:totalSupply|totalAssets|totalDebt|totalBorrow|"
    r"cachedTotal[A-Za-z0-9_]*)\s*(?:=|\+=|-=)|"
    r"\b(?:uint256|uint128|uint112|uint|int256|int)?\s*"
    r"(?:"
    r"[A-Za-z_][A-Za-z0-9_]*(?:Shares?|shares?|Assets?|assets?|"
    r"Debt|debt|Borrow|borrow|Redeem|redeem|Payout|payout|"
    r"Credit|credit|Amount|amount|Burn|burn|Mint|mint)[A-Za-z0-9_]*|"
    r"shares?|assets?|debts?|borrow|redeem|payout|credit|amount|burn|mint"
    r")"
    r"\s*=\s*[^;]*"
    r")"
)
_FP_SOURCE_RE = re.compile(
    r"(?i)\b(?:mock|test|fixture|notifyOnly|viewOnly|readOnlyProbe|"
    r"readonlyReentrancy|super\.(?:deposit|withdraw|redeem))\b"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    pos = open_pos + 1
    while pos < len(source) and depth > 0:
        char = source[pos]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        pos += 1
    return pos - 1 if depth == 0 else -1


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    close_brace = _find_matching_delimiter(source, open_brace, "{", "}")
    if close_brace < 0:
        return None, open_brace
    return source[open_brace + 1:close_brace], close_brace + 1


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
        cursor = close_paren + 1
        while cursor < len(source):
            if source[cursor] == ";":
                break
            if source[cursor] == "{":
                body_start = cursor
                break
            cursor += 1
        if body_start < 0:
            pos = max(cursor, close_paren + 1)
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


def _line_for_offset(fn: FunctionSlice, offset: int) -> int:
    return fn.body_line + fn.body.count("\n", 0, max(0, offset))


def _token_re(name: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(name)}\b")


def _source_kind(expr: str, name: str) -> str | None:
    lower = f"{expr} {name}".lower()
    if "reserve" in lower or "getreserves" in lower:
        return "reserve"
    if "index" in lower or "accumulator" in lower:
        return "accounting index"
    if "rate" in lower or "pricepershare" in lower or "virtualprice" in lower:
        return "exchange rate"
    if any(word in lower for word in ("total", "assets", "supply", "shares", "debt", "borrow", "cash", "balanceof")):
        return "cached total"
    if _ACCOUNTING_EXPR_RE.search(expr) or _ACCOUNTING_NAME_RE.search(name):
        return "accounting value"
    return None


def _accounting_snapshots_before(body: str, boundary_start: int) -> list[AccountingSnapshot]:
    prefix = body[:boundary_start]
    tracked: list[AccountingSnapshot] = []
    seen: set[str] = set()
    for assignment in _ASSIGN_RE.finditer(prefix):
        name = assignment.group("name")
        if name in seen:
            continue
        expr = assignment.group("expr")
        if not (_ACCOUNTING_EXPR_RE.search(expr) or _ACCOUNTING_NAME_RE.search(name)):
            continue
        kind = _source_kind(expr, name)
        if kind is None:
            continue
        seen.add(name)
        tracked.append(AccountingSnapshot(name=name, source_kind=kind, assign_start=assignment.start()))
    return tracked


def _statement_ranges(source: str, start: int) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    stmt_start = start
    depth = 0
    for pos in range(start, len(source)):
        char = source[pos]
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == ";" and depth == 0:
            ranges.append((stmt_start, pos + 1, source[stmt_start:pos + 1]))
            stmt_start = pos + 1
    tail = source[stmt_start:].strip()
    if tail:
        ranges.append((stmt_start, len(source), source[stmt_start:]))
    return ranges


def _fresh_revalidation(segment: str, snapshot: AccountingSnapshot) -> bool:
    name = re.escape(snapshot.name)
    if re.search(rf"(?is)\b{name}\b\s*=\s*[^;]*{_ACCOUNTING_EXPR_PART}", segment):
        return True
    if _FRESH_NAME_RE.search(segment) and _ACCOUNTING_EXPR_RE.search(segment):
        return True
    if _REFRESH_CALL_RE.search(segment):
        return True
    return False


def _stale_use_after_boundary(
    body: str,
    boundary: re.Match[str],
    snapshot: AccountingSnapshot,
) -> int | None:
    token = _token_re(snapshot.name)
    segment_start = boundary.end()
    for stmt_start, _stmt_end, statement in _statement_ranges(body, segment_start):
        before_statement = body[segment_start:stmt_start]
        if _fresh_revalidation(before_statement, snapshot):
            return None
        if re.search(rf"(?is)\b{re.escape(snapshot.name)}\b\s*=\s*", statement):
            return None
        if token.search(statement) and _SINK_RE.search(statement):
            return stmt_start
    return None


def _match_function(fn: FunctionSlice) -> tuple[AccountingSnapshot, re.Match[str], int] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if _VIEW_OR_PURE_RE.search(fn.header):
        return None
    joined = f"{fn.name}\n{fn.header}\n{fn.body}"
    if _FP_SOURCE_RE.search(joined):
        return None
    if _GUARD_RE.search(fn.header) or _GUARD_RE.search(fn.body):
        return None

    for boundary in _EXTERNAL_VIEW_OR_HOOK_RE.finditer(fn.body):
        snapshots = _accounting_snapshots_before(fn.body, boundary.start())
        if not snapshots:
            continue
        for snapshot in snapshots:
            stale_use = _stale_use_after_boundary(fn.body, boundary, snapshot)
            if stale_use is not None:
                return snapshot, boundary, stale_use
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if not source or _SURFACE_RE.search(source) is None:
        return findings
    stripped = _strip_comments_and_strings(source)
    if _EXTERNAL_VIEW_OR_HOOK_RE.search(stripped) is None:
        return findings

    for fn in _split_functions(stripped):
        matched = _match_function(fn)
        if matched is None:
            continue
        snapshot, boundary, use_offset = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_offset(fn, use_offset),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` snapshots {snapshot.source_kind} "
                    f"`{snapshot.name}` before an external view or hook "
                    f"boundary near line {_line_for_offset(fn, boundary.start())}, "
                    "then uses the stale accounting value for mint, burn, "
                    "borrow, redeem, or settlement without a fresh refresh. "
                    "NOT_SUBMIT_READY: validate source existence and real "
                    "entrypoint evidence before use."
                ),
            )
        )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "PROMOTION_ALLOWED",
    "SUBMISSION_POSTURE",
    "scan",
]
