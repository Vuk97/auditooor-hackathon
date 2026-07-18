"""
state-check-token-delta-fire31

Solidity regex detector for a narrow state-change-between-check-and-use
shape: a function snapshots a balance, allowance, reserve, or accounting
value, checks it, crosses a token transfer or callback boundary, then uses the
pre-boundary value before deriving a fresh post-boundary delta.

Source refs:
* reports/detector_lift_fire30_20260605/post_priorities_all.md
* reference/patterns.dsl/state-check-before-token-or-sender-mutation.yaml
* detectors/wave17/state_check_then_external_or_mutating_use_fire17.py

Hits are candidate evidence only. They are NOT_SUBMIT_READY and must not be
used as exploit proof without R40, R76, and R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "state-check-token-delta-fire31"
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
    body_line: int


@dataclass
class TrackedValue:
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

_BOUNDARY_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:safeTransferFrom|transferFrom|safeTransfer|transfer|send)\s*\(|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(?:call|delegatecall)\s*(?:\{|"
    r"\(|\.value\s*\()|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*"
    r"(?:on[A-Za-z0-9_]*|before[A-Za-z0-9_]*|after[A-Za-z0-9_]*|"
    r"execute|executeCall|notify|notify[A-Za-z0-9_]*)\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Hook|Hooks|Callback|Receiver|Policy|Manager|"
    r"Router|Adapter|Vault|Pool|Token)[A-Za-z0-9_]*\s*\([^;)]*\)\s*\.\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\("
    r")"
)

_SOURCE_EXPR_RE = re.compile(
    r"(?is)\b(?:balanceOf|allowance|getReserves|reserve[01]?|_reserve[01]?|"
    r"totalAssets|totalSupply|cached|accounted|accounting|credits?|shares?|"
    r"liabilit|assetBalance|tokenBalance|poolBalance|availableBalance)\b"
)
_TRACKED_NAME_RE = re.compile(
    r"(?i)(?:before|pre|cached|snapshot|old|prior|balance|allowance|reserve|"
    r"account|credit|share|asset|liabilit)"
)
_ASSIGN_RE = re.compile(
    r"(?is)"
    r"(?:\b(?:uint|uint256|uint128|uint64|int|int256|int128|int64)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<expr>[^;]*);"
)
_CHECK_RE = re.compile(r"(?is)\b(?:require|if)\s*\((?P<expr>[^;{}]*)\)")

_FRESH_NAME_RE = re.compile(
    r"(?i)(?:after|post|fresh|actual|received|delta|net|current|new)"
)
_DELTA_NAME_RE = re.compile(
    r"(?i)(?:actualReceived|receivedDelta|deltaIn|balanceDelta|netReceived|"
    r"receivedAmount|postBalance|balanceAfter|allowanceAfter|freshBalance|"
    r"freshAllowance|accountedAfter|creditsAfter)"
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
    if "balanceof" in lower:
        return "balance"
    if "allowance" in lower:
        return "allowance"
    if "reserve" in lower:
        return "reserve"
    if _SOURCE_EXPR_RE.search(expr) or _TRACKED_NAME_RE.search(name):
        return "cached accounting"
    return None


def _tracked_values_before(body: str, boundary_start: int) -> list[TrackedValue]:
    prefix = body[:boundary_start]
    tracked: list[TrackedValue] = []
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
            TrackedValue(
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


def _fresh_update_statement(statement: str, tracked: TrackedValue) -> bool:
    name = tracked.name
    token = _token_re(name)
    assign_fresh = re.search(
        rf"(?is)\b{re.escape(name)}\b\s*=\s*[^;]*"
        rf"(?:balanceOf\s*\(|allowance\s*\(|getReserves\s*\(|"
        rf"reserve|accounted|accounting|cached)",
        statement,
    )
    if assign_fresh is not None:
        return True
    if _DELTA_NAME_RE.search(statement) and token.search(statement):
        if re.search(rf"(?is)(?:-\s*{re.escape(name)}\b|\b{re.escape(name)}\b\s*-)", statement):
            return True
    return False


def _has_fresh_revalidation(segment: str, tracked: TrackedValue) -> bool:
    if re.search(
        rf"(?is)\b{re.escape(tracked.name)}\b\s*=\s*[^;]*"
        rf"(?:balanceOf\s*\(|allowance\s*\(|getReserves\s*\(|"
        rf"reserve|accounted|accounting|cached)",
        segment,
    ):
        return True
    if _DELTA_NAME_RE.search(segment):
        return True
    if _FRESH_NAME_RE.search(segment) and _SOURCE_EXPR_RE.search(segment):
        return True
    return False


def _is_stale_use_statement(statement: str, tracked: TrackedValue) -> bool:
    token = _token_re(tracked.name)
    if token.search(statement) is None:
        return False
    if _fresh_update_statement(statement, tracked):
        return False
    return bool(
        re.search(
            rf"(?is)"
            rf"(?:"
            rf"\breturn\b[^;]*\b{re.escape(tracked.name)}\b|"
            rf"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]*\b{re.escape(tracked.name)}\b|"
            rf"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:\+=|-=|\*=|/=)\s*"
            rf"[^;]*\b{re.escape(tracked.name)}\b|"
            rf"\b(?:transfer|safeTransfer|safeTransferFrom|mint|_mint|burn|"
            rf"settle|release|claim|withdraw|redeem|spend|charge)"
            rf"[A-Za-z0-9_]*\s*\([^;]*\b{re.escape(tracked.name)}\b|"
            rf"\brequire\s*\([^;]*\b{re.escape(tracked.name)}\b|"
            rf"\b{re.escape(tracked.name)}\b\s*(?:[+\-*/%]|<<|>>)|"
            rf"(?:[+\-*/%]|<<|>>)\s*\b{re.escape(tracked.name)}\b"
            rf")",
            statement,
        )
    )


def _stale_use_after_boundary(
    body: str,
    boundary: re.Match[str],
    tracked: TrackedValue,
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


def _match_function(fn: FunctionSlice) -> tuple[TrackedValue, re.Match[str], int] | None:
    body = fn.body
    for boundary in _BOUNDARY_RE.finditer(body):
        tracked_values = _tracked_values_before(body, boundary.start())
        if not tracked_values:
            continue
        for tracked in tracked_values:
            stale_use = _stale_use_after_boundary(body, boundary, tracked)
            if stale_use is None:
                continue
            use_offset, _statement = stale_use
            return tracked, boundary, use_offset
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if not source:
        return findings
    if not any(marker in source for marker in ("balanceOf", "allowance", "transfer", "call", "callback", "Receiver", "Hook")):
        return findings
    stripped = _strip_comments_and_strings(source)
    for fn in _split_functions(stripped):
        if not _PUBLIC_OR_EXTERNAL_RE.search(fn.header):
            continue
        if _VIEW_OR_PURE_RE.search(fn.header):
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
                    f"`{tracked.name}`, crosses a token transfer or callback "
                    "boundary, then uses that stale value without deriving a "
                    "fresh post-boundary delta or revalidation."
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
]
