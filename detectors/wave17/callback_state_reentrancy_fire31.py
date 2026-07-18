"""
callback-state-reentrancy-fire31

Regex API detector for callback, hook, router, or token-transfer control flow
that runs before protocol state is finalized. It targets a Fire31
reentrancy-cross-contract recall miss: balances, nonce consumption, debt, or
claim state are checked before an external boundary, but the same state slot is
written only after that boundary.

Source refs:
- reports/detector_lift_fire30_20260605/post_priorities_all.md
- reference/patterns.dsl/callback_reentrancy_no_guard.yaml
- reference/patterns.dsl/state-check-before-token-or-sender-mutation.yaml

This is candidate evidence only. Hits are NOT_SUBMIT_READY and require source
existence, a real in-scope entrypoint, a negative control, and R40/R76/R80
evidence honesty before any filing use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "callback-state-reentrancy-fire31"
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
    r"(?i)^_?(?:deposit|withdraw|redeem|borrow|repay|liquidate|settle|"
    r"fill|match|execute|buy|purchase|claim|cancel|mint|burn|refund|"
    r"finali[sz]e|release|request|route|swap|bridge|receive|relay|"
    r"fulfill|process|complete)[A-Za-z0-9_]*$"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(?is)\b(?:nonReentrant|nonreentrant|noReentrant|noReentry|"
    r"noReentrancy|reentrancyGuard|ReentrancyGuard|reentrancyLock|"
    r"lockReentrancy)\b|"
    r"\b(?:_status|status|locked|_locked|entered|_entered)\s*=\s*"
    r"(?:true|2|_ENTERED|ENTERED)\b"
)
_SURFACE_RE = re.compile(
    r"(?is)\b(?:callback|hook|router|receiver|recipient|safeTransfer|"
    r"safeTransferFrom|transferFrom|claim|claimed|nonce|nonces|debt|"
    r"balances?|shares?|position|settle|finali[sz]e|execute)\b"
)
_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?is)(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:on[A-Za-z0-9_]*(?:Received|"
    r"Callback|Hook|Liquidate|Repay|FlashLoan)|before[A-Za-z0-9_]*|"
    r"after[A-Za-z0-9_]*|callback|execute[A-Za-z0-9_]*|route[A-Za-z0-9_]*|"
    r"swap[A-Za-z0-9_]*|safeTransferFrom|safeTransfer|transferFrom|"
    r"transfer|send|call|delegatecall|functionCall)\s*(?:\{|\(|\.value\s*\()|"
    r"\bI[A-Za-z0-9_]*(?:Callback|Hook|Receiver|Router|Adapter|Manager|"
    r"Token|Vault|Bridge|Liquidator)[A-Za-z0-9_]*\s*\([^;\n)]*\)\s*\."
    r"[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer)\s*\("
    r")"
)
_STATE_NAME_RE = re.compile(
    r"(?i)(?:balance|balances|share|shares|debt|debts|borrow|borrowed|"
    r"claim|claimed|claimable|nonce|nonces|used|consumed|processed|"
    r"replay|request|requests|pending|position|positions|order|orders|"
    r"filled|remaining|status|state|settled|finalized|owed|paid|escrow|"
    r"collateral|account|accounts)"
)
_STATE_WRITE_RE = re.compile(
    r"(?is)\b(?P<slot>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\]\s*)+(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*"
    r"(?:=|\+=|-=|\+\+|--)"
)
_STATE_DELETE_RE = re.compile(
    r"(?is)\bdelete\s+(?P<slot>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\]\s*)+"
)
_SET_ADD_RE = re.compile(
    r"(?is)\b(?P<slot>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:add|set)\s*\("
)
_CHECK_RE = re.compile(
    r"(?is)\b(?:require|assert|if)\s*\([^;{}]*(?:!|==|!=|<=|>=|<|>)"
)
_POST_BOUNDARY_CLEAN_RE = re.compile(
    r"(?i)\b(?:revalidate|validateAfter|freshBalance|freshDebt|"
    r"balanceAfter|debtAfter|claimAfter|nonceAfter|postCallbackCheck)\b"
)
_FALSE_POSITIVE_SOURCE_RE = re.compile(
    r"(?i)\b(?:mock|test|example|notifyOnly|pingOnly|viewOnly|readOnly)\b"
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


def _slot_access_re(slot: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(slot)}\b\s*(?:\[[^\]]+\]\s*)+", re.IGNORECASE)


def _slot_write_re(slot: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?is)(?:\bdelete\s+{re.escape(slot)}\s*(?:\[[^\]]+\]\s*)+|"
        rf"\b{re.escape(slot)}\s*(?:\[[^\]]+\]\s*)+"
        rf"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?:=|\+=|-=|\+\+|--)|"
        rf"\b{re.escape(slot)}\s*\.\s*(?:add|set)\s*\()"
    )


def _first_state_write(text: str) -> re.Match[str] | None:
    matches: list[re.Match[str]] = []
    for regex in (_STATE_WRITE_RE, _STATE_DELETE_RE, _SET_ADD_RE):
        matches.extend(regex.finditer(text))
    if not matches:
        return None
    return min(matches, key=lambda match: match.start())


def _slot_name(match: re.Match[str]) -> str:
    return match.groupdict().get("slot") or ""


def _is_finalization_slot(slot: str) -> bool:
    return bool(_STATE_NAME_RE.search(slot))


def _checked_before_boundary(slot: str, prefix: str) -> bool:
    access_re = _slot_access_re(slot)
    access = None
    for access in access_re.finditer(prefix):
        pass
    if access is None:
        return False

    window = prefix[max(0, access.start() - 220):min(len(prefix), access.end() + 260)]
    if _CHECK_RE.search(window):
        return True
    return bool(_CHECK_RE.search(prefix) and _STATE_NAME_RE.search(window))


def _written_before_boundary(slot: str, prefix: str) -> bool:
    return bool(_slot_write_re(slot).search(prefix))


def _risky_finalization_after_boundary(fn: FunctionSlice) -> tuple[re.Match[str], re.Match[str], str] | None:
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
    if _POST_BOUNDARY_CLEAN_RE.search(tail[:260]):
        return None

    for state_write in sorted(
        [
            match
            for regex in (_STATE_WRITE_RE, _STATE_DELETE_RE, _SET_ADD_RE)
            for match in regex.finditer(tail)
        ],
        key=lambda match: match.start(),
    ):
        slot = _slot_name(state_write)
        if not slot or not _is_finalization_slot(slot):
            continue
        if _written_before_boundary(slot, prefix):
            continue
        if not _checked_before_boundary(slot, prefix):
            continue
        absolute_write = _OffsetMatch(state_write, boundary.end())
        return boundary, absolute_write, slot

    return None


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


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _SURFACE_RE.search(clean):
        return []
    if _EXTERNAL_BOUNDARY_RE.search(clean) is None:
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _risky_finalization_after_boundary(fn)
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
                    f"`{fn.name}` checks `{slot}` before callback-capable "
                    f"control flow near line {_line_for_body_match(fn, boundary)}, "
                    "but finalizes that state only after the boundary. Finalize "
                    "balances, nonce, debt, or claim state before callbacks, "
                    "router calls, or token transfers, or protect the path with "
                    "one shared nonReentrant guard."
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
