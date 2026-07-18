"""
reentrancy-share-callback-midstate-fire37

Regex API detector for Solidity accounting entrypoints that snapshot share,
collateral, debt, packet, or reward state before an external receiver hook or
token transfer, then mint, burn, settle, or update accounting after that
callback without a shared lock or post-callback refresh.

Source refs:
- reports/detector_lift_fire36_20260605/post_priorities_solidity.md
- reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml
- detectors/wave17/reentrancy_callback_balance_snapshot_fire36.py
- detectors/wave17/readonly_reentrancy_accounting_fire35.py

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


DETECTOR_NAME = "reentrancy-share-callback-midstate-fire37"
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
    kind: str
    assign_start: int


@dataclass
class AccountingFinalization:
    kind: str
    start: int
    text: str


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
_ENTRY_NAME_RE = re.compile(
    r"(?i)^_?(?:deposit|withdraw|redeem|mint|burn|borrow|repay|"
    r"liquidate|settle|finali[sz]e|complete|claim|reward|collect|"
    r"release|stake|unstake|supply|queue|consume|open|close|fill|"
    r"execute|swap|match|packet)[A-Za-z0-9_]*$"
)
_GUARD_RE = re.compile(
    r"(?is)\b(?:nonReentrant|nonreentrant|ReentrancyGuard|"
    r"noReentrant|noReentry|noReentrancy|reentrancyGuard|"
    r"reentrancyLock|lockReentrancy|depositLock|withdrawLock|"
    r"shareLock|collateralLock|debtLock|packetLock|rewardLock|"
    r"settlementLock|checkNotInVaultContext|ensureNotInVaultContext|"
    r"_reentrancyGuardEntered)\b|"
    r"\b(?:_status|status|locked|_locked|entered|_entered|"
    r"reentrancyLock|shareLock|packetLock|rewardLock)"
    r"\s*=\s*(?:true|2|_ENTERED|ENTERED)"
)
_SURFACE_RE = re.compile(
    r"(?is)\b(?:shares?|shareBalance|collateral|collateralShares|"
    r"debts?|debtShares|borrowShares|packets?|packetState|packetShares|"
    r"rewards?|rewardDebt|rewardIndex|pendingRewards?|settlement|"
    r"receiver|recipient|hook|callback|safeTransferFrom|safeTransfer|"
    r"transferFrom|transfer|mint|burn|settle|finali[sz]e)\b|"
    r"\.on[A-Za-z0-9_]*(?:Received|Callback|Hook)"
)
_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?is)(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:"
    r"on[A-Za-z0-9_]*(?:Received|Callback|Hook|Mint|Burn|Claim|"
    r"Settle|Reward|Packet|Transfer|Liquidate|Repay)|"
    r"before[A-Za-z0-9_]*|after[A-Za-z0-9_]*|"
    r"callback|hook|notify|receive[A-Za-z0-9_]*|"
    r"safeTransferFrom|safeTransfer|transferFrom|transfer|"
    r"sendValue|send|call)"
    r"\s*(?:\{|\(|\.value\s*\()|"
    r"\bI[A-Za-z0-9_]*(?:Callback|Hook|Receiver|Recipient|"
    r"Token|Vault|Pool|Strategy|Settlement|Reward|Packet)"
    r"[A-Za-z0-9_]*\s*\([^;\n)]*\)\s*"
    r"\.[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer)\s*\("
    r")"
)
_ASSIGN_RE = re.compile(
    r"(?is)"
    r"(?:(?:[A-Za-z_][A-Za-z0-9_]*(?:\s+(?:memory|storage|calldata))?|"
    r"u?int(?:8|16|32|64|96|112|128|160|192|224|256)?|"
    r"bool|address|bytes(?:[0-9]+)?|string|var)\s+)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;{}]+);"
)
_ACCOUNTING_EXPR_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:shares?|shareBalance|shareBalances|shareOf|shareIndex|"
    r"totalShares|totalSupply|collateral|collaterals|collateralShares|"
    r"collateralBalance|totalCollateral|debts?|debtShares|borrowShares|"
    r"borrowDebt|totalDebt|totalBorrow|packets?|packetState|packetShares|"
    r"packetDebt|packetReward|rewards?|rewardDebt|rewardIndex|"
    r"pendingRewards?|claimableRewards?|accruedRewards?|settlements?)"
    r"\s*(?:\[|\.|\b)|"
    r"\.balanceOf\s*\(|"
    r"\baddress\s*\(\s*this\s*\)\s*\.\s*balance\b"
    r")"
)
_ACCOUNTING_NAME_RE = re.compile(
    r"(?i)(?:before|pre|snapshot|cached|stored|old|prior|share|"
    r"collateral|debt|borrow|packet|reward|settle|accounting|index|"
    r"supply|total|owed|pending|claim|amount)"
)
_FRESH_NAME_RE = re.compile(
    r"(?i)(?:after|post|fresh|latest|current|updated|recomputed|"
    r"reloaded|revalidated|new)"
)
_REFRESH_CALL_RE = re.compile(
    r"(?is)\b(?:refresh|sync|update|accrue|checkpoint|recompute|"
    r"reload|revalidate|validateAfter|postCallbackCheck|"
    r"postHookCheck|settleFresh)[A-Za-z0-9_]*\s*\("
)
_WRITE_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\bdelete\s+(?P<delete>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\]\s*)*(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?|"
    r"\b(?P<slot>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?P<tail>(?:\[[^\]]+\]\s*)*(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?)"
    r"\s*(?:=|\+=|-=|\+\+|--)|"
    r"\b(?P<call>_?(?:mint|burn)|mintShares|burnShares|"
    r"creditShares|debitShares|_?settle[A-Za-z0-9_]*|"
    r"_?finali[sz]e[A-Za-z0-9_]*|complete[A-Za-z0-9_]*|"
    r"markPacket[A-Za-z0-9_]*|updateReward[A-Za-z0-9_]*|"
    r"syncReward[A-Za-z0-9_]*|accountShare[A-Za-z0-9_]*)\s*\("
    r")"
)
_FINALIZATION_NAME_RE = re.compile(
    r"(?i)(?:share|shares|collateral|debt|borrow|packet|reward|"
    r"pending|claim|settle|settlement|status|state|account|index|"
    r"position|order|remaining|filled|owed|paid|escrow|total|"
    r"supply|amount|mint|burn)"
)
_DIRECT_STATE_NAME_RE = re.compile(
    r"(?i)^(?:total[A-Za-z0-9_]*|global[A-Za-z0-9_]*|"
    r"totalShares|totalSupply|totalCollateral|totalDebt|totalBorrow|"
    r"shareIndex|rewardIndex|rewardDebt|packetNonce|packetState|"
    r"settlementState|accountingState)$"
)
_NOISY_SOURCE_RE = re.compile(
    r"(?i)\b(?:mock|test|fixture|example|notifyOnly|pingOnly|"
    r"viewOnly|readOnlyProbe|readonlyReentrancy|super\."
    r"(?:deposit|withdraw|redeem|claim))\b"
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


def _snapshot_kind(expr: str, name: str) -> str | None:
    joined = f"{expr} {name}".lower()
    if "packet" in joined:
        return "packet accounting"
    if "reward" in joined or "claimable" in joined or "accrued" in joined:
        return "reward accounting"
    if "debt" in joined or "borrow" in joined:
        return "debt accounting"
    if "collateral" in joined:
        return "collateral accounting"
    if "share" in joined or "supply" in joined:
        return "share accounting"
    if "settle" in joined or "pending" in joined or "claim" in joined:
        return "settlement accounting"
    return None


def _snapshots_before(body: str, boundary_start: int) -> list[AccountingSnapshot]:
    prefix = body[:boundary_start]
    snapshots: list[AccountingSnapshot] = []
    seen: set[str] = set()
    for assignment in _ASSIGN_RE.finditer(prefix):
        name = assignment.group("name")
        if name in seen:
            continue
        expr = assignment.group("expr")
        if not (_ACCOUNTING_EXPR_RE.search(expr) or _ACCOUNTING_NAME_RE.search(name)):
            continue
        kind = _snapshot_kind(expr, name)
        if kind is None:
            continue
        seen.add(name)
        snapshots.append(AccountingSnapshot(name=name, kind=kind, assign_start=assignment.start()))
    return snapshots


def _contains_refresh(segment: str, snapshot: AccountingSnapshot) -> bool:
    if _REFRESH_CALL_RE.search(segment):
        return True
    if re.search(rf"(?is)\b{re.escape(snapshot.name)}\b\s*=", segment):
        return True
    if _FRESH_NAME_RE.search(segment) and _ACCOUNTING_EXPR_RE.search(segment):
        return True
    return False


def _is_local_assignment(statement: str, match: re.Match[str]) -> bool:
    slot = match.groupdict().get("slot")
    tail = match.groupdict().get("tail") or ""
    if not slot:
        return False
    if "[" in tail or "." in tail:
        return False
    if _DIRECT_STATE_NAME_RE.search(slot):
        return False
    line_start = statement.rfind("\n", 0, match.start()) + 1
    prefix = statement[line_start:match.start()]
    if re.search(
        r"(?is)\b(?:uint|int|bool|address|bytes|string|var|"
        r"[A-Z][A-Za-z0-9_]*(?:\s+(?:memory|storage|calldata))?)\s+$",
        prefix,
    ):
        return True
    return True


def _call_kind(call_name: str, statement: str) -> str:
    lower = f"{call_name} {statement}".lower()
    if "packet" in lower:
        return "packet accounting"
    if "reward" in lower:
        return "reward accounting"
    if "debt" in lower or "borrow" in lower:
        return "debt accounting"
    if "collateral" in lower:
        return "collateral accounting"
    if "settle" in lower or "final" in lower or "complete" in lower:
        return "settlement accounting"
    return "share accounting"


def _finalization_kind(statement: str) -> AccountingFinalization | None:
    for match in _WRITE_RE.finditer(statement):
        call = match.groupdict().get("call")
        if call:
            return AccountingFinalization(
                kind=_call_kind(call, statement),
                start=match.start(),
                text=statement,
            )

        slot = match.groupdict().get("delete") or match.groupdict().get("slot") or ""
        if not slot or not _FINALIZATION_NAME_RE.search(slot):
            continue
        if _is_local_assignment(statement, match):
            continue
        kind = _snapshot_kind(statement, slot)
        if kind is None:
            kind = "share accounting"
        return AccountingFinalization(kind=kind, start=match.start(), text=statement)
    return None


def _compatible(snapshot: AccountingSnapshot, finalization: AccountingFinalization) -> bool:
    if snapshot.name and re.search(rf"\b{re.escape(snapshot.name)}\b", finalization.text):
        return True
    if snapshot.kind == finalization.kind:
        return True
    if snapshot.kind == "share accounting" and finalization.kind in {
        "collateral accounting",
        "settlement accounting",
    }:
        return True
    if snapshot.kind == "collateral accounting" and finalization.kind == "share accounting":
        return True
    if snapshot.kind == "debt accounting" and re.search(r"(?i)(debt|borrow|share|mint|burn)", finalization.text):
        return True
    if snapshot.kind == "packet accounting" and re.search(r"(?i)(packet|settle|status|state)", finalization.text):
        return True
    if snapshot.kind == "reward accounting" and re.search(r"(?i)(reward|claim|debt|index|pending)", finalization.text):
        return True
    if snapshot.kind == "settlement accounting" and re.search(r"(?i)(settle|claim|pending|share)", finalization.text):
        return True
    return False


def _post_boundary_finalization(
    body: str,
    boundary: re.Match[str],
    snapshot: AccountingSnapshot,
) -> AccountingFinalization | None:
    segment_start = boundary.end()
    for stmt_start, _stmt_end, statement in _statement_ranges(body, segment_start):
        between = body[segment_start:stmt_start]
        if _contains_refresh(between, snapshot):
            return None
        finalization = _finalization_kind(statement)
        if finalization is None:
            continue
        if _compatible(snapshot, finalization):
            return AccountingFinalization(
                kind=finalization.kind,
                start=stmt_start + finalization.start,
                text=statement,
            )
    return None


def _match_function(fn: FunctionSlice) -> tuple[AccountingSnapshot, re.Match[str], AccountingFinalization] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if _VIEW_OR_PURE_RE.search(fn.header):
        return None
    if not _ENTRY_NAME_RE.search(fn.name):
        return None

    joined = f"{fn.name}\n{fn.header}\n{fn.body}"
    if _NOISY_SOURCE_RE.search(joined):
        return None
    if _GUARD_RE.search(fn.header) or _GUARD_RE.search(fn.body):
        return None

    for boundary in _EXTERNAL_BOUNDARY_RE.finditer(fn.body):
        snapshots = _snapshots_before(fn.body, boundary.start())
        if not snapshots:
            continue
        for snapshot in snapshots:
            finalization = _post_boundary_finalization(fn.body, boundary, snapshot)
            if finalization is not None:
                return snapshot, boundary, finalization
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if not source or _SURFACE_RE.search(source) is None:
        return findings

    stripped = _strip_comments_and_strings(source)
    if _EXTERNAL_BOUNDARY_RE.search(stripped) is None:
        return findings

    for fn in _split_functions(stripped):
        matched = _match_function(fn)
        if matched is None:
            continue
        snapshot, boundary, finalization = matched
        boundary_line = _line_for_offset(fn, boundary.start())
        finalization_line = _line_for_offset(fn, finalization.start)
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=finalization_line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` snapshots {snapshot.kind} `{snapshot.name}` "
                    f"before an external receiver hook or token transfer near "
                    f"line {boundary_line}, then finalizes {finalization.kind} "
                    f"near line {finalization_line} after external control "
                    "transfer with no shared reentrancy guard or post-callback "
                    "refresh. NOT_SUBMIT_READY: validate source existence and "
                    "real entrypoint exploit evidence before use."
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
