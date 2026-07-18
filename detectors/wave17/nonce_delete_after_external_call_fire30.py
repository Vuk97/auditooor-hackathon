"""
nonce-delete-after-external-call-fire30

Solidity recall-lift detector for replay-key finalization that happens only
after attacker-controlled external control flow. It targets a narrow
reentrancy-cross-contract miss: a nonce, commitment, proof flag, nullifier, or
message key is checked before an external call, callback, or token transfer,
but is deleted, incremented, or marked consumed only after that boundary.

Hits are candidate evidence only. They require a real protocol path, impact
proof, and negative control before any filing use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "nonce-delete-after-external-call-fire30"
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
    body_line: int


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"\b(?:public|external)\b")
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b")
_REENTRANCY_GUARD_RE = re.compile(
    r"(?is)\b(?:nonReentrant|nonreentrant|noReentrancy|reentrancyGuard|"
    r"ReentrancyGuard|_reentrancyGuardEntered|reentrancyLock)\b|"
    r"\b(?:locked|_locked|entered|_entered)\s*=\s*true\b|"
    r"\b_status\s*=\s*(?:_ENTERED|2)\b"
)

_SINGLE_USE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:nonce|nonces|commitment|commitments|proof|proofs|"
    r"consumed|used|processed|replay|replayed|nullifier|nullifiers|"
    r"digest|hash|messageId|messageHash|leaf|signature|sig)\b"
)
_FUNCTION_CONTEXT_RE = re.compile(
    r"(?i)^(?:_)?(?:sign|verify|consume|claim|redeem|finalize|settle|"
    r"process|execute|complete|withdraw|borrow|repay|liquidate|release|"
    r"mint|bridge|receive|relay|fulfill)[A-Za-z0-9_]*$"
)

_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer)\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:safeTransferFrom|safeTransfer|"
    r"transferFrom|transfer|call|delegatecall|staticcall|send)\s*(?:\{|"
    r"\(|\.value\s*\()|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*on[A-Za-z0-9_]*\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Hook|Hooks|Callback|Receiver|Router|Adapter|"
    r"Manager|Token|Vault|Bridge)[A-Za-z0-9_]*\s*\([^;)]*\)\s*\.\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\("
    r")"
)

_DELETE_RE = re.compile(
    r"\bdelete\s+(?P<slot>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\]\s*)+",
    re.IGNORECASE | re.DOTALL,
)
_MARK_TRUE_RE = re.compile(
    r"\b(?P<slot>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]+\]\s*)+"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*)?\s*=\s*(?:true|1)\s*;",
    re.IGNORECASE | re.DOTALL,
)
_SET_ADD_RE = re.compile(
    r"\b(?P<slot>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:add|set)\s*\(",
    re.IGNORECASE,
)
_NONCE_INCREMENT_RE = re.compile(
    r"\b(?P<slot>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\]\s*)+(?:\+\+|"
    r"(?:\+=\s*1)|"
    r"(?:=\s*[^;]{0,120}\+\s*1))\s*;",
    re.IGNORECASE | re.DOTALL,
)
_CONSUME_PATTERNS: tuple[re.Pattern[str], ...] = (
    _DELETE_RE,
    _MARK_TRUE_RE,
    _SET_ADD_RE,
    _NONCE_INCREMENT_RE,
)

_REPLAY_SLOT_NAME_RE = re.compile(
    r"(?i)(?:nonce|commit|proof|consum|used|processed|replay|claim|"
    r"nullifier|digest|hash|message|request|leaf|sig|executed|finalized)"
)
_REPLAY_CHECK_RE = re.compile(
    r"(?is)(?:"
    r"\brequire\s*\([^;{}]*(?:!|==|!=|<=|>=)|"
    r"\bif\s*\([^;{}]*(?:!|==|!=|<=|>=)|"
    r"\b(?:MerkleProof|ecrecover|recover|verify|isValidSignature|"
    r"SignatureChecker|keccak256|abi\.encode)"
    r")"
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


def _line_for_match(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _base_slot(match: re.Match[str]) -> str:
    return match.groupdict().get("slot") or ""


def _slot_access_re(slot: str) -> re.Pattern[str]:
    return re.compile(rf"\b{re.escape(slot)}\b\s*(?:\[[^\]]+\]\s*)+", re.IGNORECASE)


def _is_replay_slot(slot: str, context: str) -> bool:
    if _REPLAY_SLOT_NAME_RE.search(slot):
        return True
    return bool(_REPLAY_SLOT_NAME_RE.search(context[:160]))


def _is_replay_key_read_before_boundary(slot: str, prefix: str) -> bool:
    slot_access = _slot_access_re(slot)
    if slot_access.search(prefix) is None:
        return False

    last_access = None
    for last_access in slot_access.finditer(prefix):
        pass
    if last_access is None:
        return False

    local_window_start = max(0, last_access.start() - 180)
    local_window_end = min(len(prefix), last_access.end() + 240)
    local_window = prefix[local_window_start:local_window_end]

    if _REPLAY_CHECK_RE.search(local_window):
        return True
    if _REPLAY_CHECK_RE.search(prefix) and _SINGLE_USE_CONTEXT_RE.search(local_window):
        return True
    return False


def _first_match(regexes: tuple[re.Pattern[str], ...], text: str) -> re.Match[str] | None:
    matches = [match for regex in regexes if (match := regex.search(text)) is not None]
    if not matches:
        return None
    return min(matches, key=lambda match: match.start())


def _delayed_consume(fn: FunctionSlice) -> tuple[re.Match[str], re.Match[str], str] | None:
    if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
        return None
    if _VIEW_OR_PURE_RE.search(fn.header):
        return None
    if _REENTRANCY_GUARD_RE.search(f"{fn.header}\n{fn.body}"):
        return None

    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    if not (_FUNCTION_CONTEXT_RE.search(fn.name) or _SINGLE_USE_CONTEXT_RE.search(text)):
        return None

    boundary = _EXTERNAL_BOUNDARY_RE.search(fn.body)
    if boundary is None:
        return None

    tail = fn.body[boundary.end() :]
    consume = _first_match(_CONSUME_PATTERNS, tail)
    if consume is None:
        return None

    consume_start = boundary.end() + consume.start()
    consume_in_body = _OffsetMatch(consume, consume_start)
    slot = _base_slot(consume)
    if not slot:
        return None
    local_context = fn.body[max(0, consume_start - 160) : consume_start + 220]
    if not _is_replay_slot(slot, local_context):
        return None

    prefix = fn.body[: boundary.start()]
    if not _is_replay_key_read_before_boundary(slot, prefix):
        return None

    return boundary, consume_in_body, slot


class _OffsetMatch:
    """Small adapter that makes a tail match report body-relative offsets."""

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
    if not _SINGLE_USE_CONTEXT_RE.search(clean):
        return []
    if _EXTERNAL_BOUNDARY_RE.search(clean) is None:
        return []

    findings: list[Finding] = []
    for fn in _split_functions(clean):
        result = _delayed_consume(fn)
        if result is None:
            continue
        boundary, consume, slot = result
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=_line_for_match(fn, consume),
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` reads replay key `{slot}` before external control "
                    f"flow near line {_line_for_match(fn, boundary)}, but consumes "
                    "or deletes it only after that boundary. Mark the key consumed "
                    "before callback-capable calls or protect the whole path with "
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
