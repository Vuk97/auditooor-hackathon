"""
cross-contract-callback-ledger-fire32

Regex API detector for Solidity entrypoints that transfer control to an
external callback, hook, router, vault, token, or IRM before committing
ledger-like state such as debt, claims, nonces, shares, positions, or
accrual timestamps.

Source refs:
- reports/detector_lift_fire31_20260605/post_priorities_all.md
- detectors/wave17/callback_state_reentrancy_fire31.py
- reference/patterns.dsl/callback_reentrancy_no_guard.yaml
- reference/patterns.dsl/morpho-accrue-interest-irm-cei.yaml

Provenance and evidence limits:
- R37: this detector is source-state candidate evidence only.
- R40: fixture hits are not an exploit PoC and do not prove impact.
- R76: candidate promotion must grep-verify the cited source excerpt exists.
- R80: fixture smoke tests are not load-bearing exploit evidence.

Submission posture: NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "cross-contract-callback-ledger-fire32"
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
    line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_RE = re.compile(r"\b(?:external|public)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b")
_ENTRY_NAME_RE = re.compile(
    r"(?i)^_?(?:deposit|withdraw|redeem|borrow|repay|liquidate|"
    r"preLiquidate|settle|fill|match|execute|buy|purchase|claim|"
    r"cancel|mint|burn|refund|route|swap|bridge|release|finali[sz]e|"
    r"accrue|sync|update|process|complete)[A-Za-z0-9_]*$"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(?is)\b(?:nonReentrant|nonreentrant|noReentrant|noReentry|"
    r"noReentrancy|reentrancyGuard|ReentrancyGuard|reentrancyLock|"
    r"lockReentrancy|checkNotInVaultContext)\b|"
    r"\b(?:_status|status|locked|_locked|entered|_entered)\s*=\s*"
    r"(?:true|2|_ENTERED|ENTERED)\b"
)
_SURFACE_RE = re.compile(
    r"(?is)\b(?:callback|hook|router|vault|receiver|recipient|adapter|"
    r"safeTransfer|safeTransferFrom|transferFrom|transfer|borrowRate|"
    r"liquidate|settle|claim|nonce|debt|shares?|positions?|ledger|"
    r"lastUpdate|lastAccrual|accounting)\b"
)
_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?is)(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:"
    r"on[A-Za-z0-9_]*(?:Received|Callback|Hook|Liquidate|Repay|"
    r"FlashLoan|Settle|Vault|Claim)|"
    r"on[A-Za-z0-9_]*|"
    r"before[A-Za-z0-9_]*|after[A-Za-z0-9_]*|callback|hook|"
    r"execute[A-Za-z0-9_]*|route[A-Za-z0-9_]*|swap[A-Za-z0-9_]*|"
    r"withdraw[A-Za-z0-9_]*|deposit[A-Za-z0-9_]*|release[A-Za-z0-9_]*|"
    r"settle[A-Za-z0-9_]*|borrowRate|safeTransferFrom|safeTransfer|"
    r"transferFrom|transfer|send|call|delegatecall|functionCall)"
    r"\s*(?:\{|\(|\.value\s*\()|"
    r"\bI[A-Za-z0-9_]*(?:Callback|Hook|Receiver|Router|Adapter|"
    r"Manager|Token|Vault|Bridge|Liquidator|Irm|IRM|RateModel)"
    r"[A-Za-z0-9_]*\s*\([^;\n)]*\)\s*\.[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer)\s*\("
    r")"
)
_LEDGER_SLOT_RE = re.compile(
    r"(?i)(?:balance|balances|share|shares|debt|debts|borrow|borrowed|"
    r"claim|claimed|claimable|nonce|nonces|used|consumed|processed|"
    r"request|requests|pending|position|positions|order|orders|filled|"
    r"remaining|status|state|settled|finalized|finalised|owed|paid|"
    r"escrow|collateral|account|accounts|ledger|accrual|accrued|"
    r"lastUpdate|lastAccrual|lastAccrued|lastTimestamp|totalShares|"
    r"totalDebt|totalBorrow|totalSupply)"
)
_MAPPING_OR_STRUCT_WRITE_RE = re.compile(
    r"(?is)\b(?P<slot>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\]\s*)+(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*"
    r"(?:\+=|-=|\+\+|--|=(?!=))"
)
_DELETE_WRITE_RE = re.compile(
    r"(?is)\bdelete\s+(?P<slot>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\]\s*)+"
)
_SET_WRITE_RE = re.compile(
    r"(?is)\b(?P<slot>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:add|set)\s*\("
)
_DIRECT_LEDGER_WRITE_RE = re.compile(
    r"(?is)\b(?P<slot>"
    r"lastUpdate|lastAccrual|lastAccrued|lastTimestamp|totalShares|"
    r"totalDebt|totalBorrowAssets|totalBorrowShares|totalSupply|"
    r"globalNonce|claimNonce|positionNonce|ledgerNonce|cachedDebt|"
    r"cachedShares|accountingState"
    r")\s*(?:\+=|-=|\+\+|--|=(?!=))"
)
_STATE_DECLARATION_RE = re.compile(
    r"(?i)\b(?:uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|"
    r"bool|address|bytes(?:[0-9]+)?|string|var)\s+$"
)
_POST_BOUNDARY_CLEAN_RE = re.compile(
    r"(?i)\b(?:revalidate|validateAfter|fresh|AfterCallback|[A-Za-z0-9_]*After|"
    r"balanceAfter|"
    r"debtAfter|sharesAfter|nonceAfter|positionAfter|postCallbackCheck|"
    r"postHookCheck)\b"
)
_FALSE_POSITIVE_SOURCE_RE = re.compile(
    r"(?i)\b(?:mock|test|fixture|notifyOnly|pingOnly|viewOnly|readOnly|"
    r"readonlyReentrancy|super\.(?:deposit|withdraw|redeem))\b"
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
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line))
        pos = end_pos
    return out


def _line_for_body_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.line + fn.body.count("\n", 0, match.start())


class _OffsetMatch:
    def __init__(self, match: re.Match[str], offset: int) -> None:
        self._match = match
        self._offset = offset

    def start(self, group: int = 0) -> int:
        return self._offset + self._match.start(group)

    def end(self, group: int = 0) -> int:
        return self._offset + self._match.end(group)

    def group(self, *args: object) -> str:
        return self._match.group(*args)

    def groupdict(self) -> dict[str, str]:
        return self._match.groupdict()


def _slot_name(match: re.Match[str]) -> str:
    return match.groupdict().get("slot") or ""


def _slot_write_re(slot: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?is)(?:\bdelete\s+{re.escape(slot)}\s*(?:\[[^\]]+\]\s*)+|"
        rf"\b{re.escape(slot)}\s*(?:\[[^\]]+\]\s*)+"
        rf"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:\+=|-=|\+\+|--|=(?!=))|"
        rf"\b{re.escape(slot)}\s*\.\s*(?:add|set)\s*\(|"
        rf"\b{re.escape(slot)}\b\s*(?:\+=|-=|\+\+|--|=(?!=)))"
    )


def _is_declaration_assignment(text: str, match: re.Match[str]) -> bool:
    line_start = text.rfind("\n", 0, match.start()) + 1
    prefix = text[line_start:match.start()]
    return bool(_STATE_DECLARATION_RE.search(prefix))


def _ledger_writes(text: str) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for regex in (
        _MAPPING_OR_STRUCT_WRITE_RE,
        _DELETE_WRITE_RE,
        _SET_WRITE_RE,
        _DIRECT_LEDGER_WRITE_RE,
    ):
        for match in regex.finditer(text):
            slot = _slot_name(match)
            if not slot or not _LEDGER_SLOT_RE.search(slot):
                continue
            if regex is _DIRECT_LEDGER_WRITE_RE and _is_declaration_assignment(text, match):
                continue
            matches.append(match)
    return sorted(matches, key=lambda item: item.start())


def _written_before_boundary(slot: str, prefix: str) -> bool:
    for match in _slot_write_re(slot).finditer(prefix):
        if not _is_declaration_assignment(prefix, match):
            return True
    return False


def _has_clean_revalidation(tail: str, write: re.Match[str]) -> bool:
    window = tail[max(0, write.start() - 220):write.start()]
    return bool(_POST_BOUNDARY_CLEAN_RE.search(window))


def _risky_ledger_commit_after_boundary(fn: FunctionSlice) -> tuple[re.Match[str], re.Match[str], str] | None:
    if not _CALLABLE_RE.search(fn.header):
        return None
    if _VIEW_OR_PURE_RE.search(fn.header):
        return None
    if _REENTRANCY_GUARD_RE.search(f"{fn.header}\n{fn.body}"):
        return None

    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    if not (_ENTRY_NAME_RE.search(fn.name) or _SURFACE_RE.search(text)):
        return None
    if _FALSE_POSITIVE_SOURCE_RE.search(text):
        return None

    boundary = _EXTERNAL_BOUNDARY_RE.search(fn.body)
    if boundary is None:
        return None

    prefix = fn.body[:boundary.start()]
    tail = fn.body[boundary.end():]
    for state_write in _ledger_writes(tail):
        slot = _slot_name(state_write)
        if _written_before_boundary(slot, prefix):
            continue
        if _has_clean_revalidation(tail, state_write):
            continue
        return boundary, _OffsetMatch(state_write, boundary.end()), slot
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _SURFACE_RE.search(clean):
        return []
    if _EXTERNAL_BOUNDARY_RE.search(clean) is None:
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _risky_ledger_commit_after_boundary(fn)
        if result is None:
            continue
        boundary, state_write, slot = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_body_match(fn, state_write),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` transfers control to an external protocol "
                    f"callback near line {_line_for_body_match(fn, boundary)} "
                    f"before committing ledger state `{slot}`. Commit debt, "
                    "claim, nonce, share, position, or accrual state before "
                    "hooks, routers, vaults, token calls, or IRM calls, or "
                    "protect the path with one shared nonReentrant guard."
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
