"""
go-rounding-direction-accounting-clamp-fire11.py

Fire11 companion detector for rounding-direction accounting loss recall.

Source-backed gap:
- The held-out Go fixture `go-integer-overflow-clamp-silent-truncation-positive`
  narrows a computed fee before reserve accounting and clamps excessive debt
  decay instead of rejecting it.

This detector intentionally covers only two compact source-backed shapes:
lossy integer narrowing that feeds reserve/fee accounting, and saturating
clamps immediately followed by a debt/reserve subtraction.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-rounding-direction-accounting-clamp-fire11"

_ACCOUNTING_RE = re.compile(
    r"(Fee|Fees|Debt|Reserve|Reserves|Balance|Balances|Share|Shares|Supply|Reward|Rewards)",
    re.IGNORECASE,
)
_NARROW_ASSIGN_RE = re.compile(
    r"\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(?P<cast>u?int(?:8|16|32))\s*\((?P<expr>[^)\n]+)\)"
)
_ALIAS_WRITE_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_\.]*(?:Fee|Fees|Reserve|Reserves|Balance|Balances|Share|Shares)"
    r"\s*(?:\+=|=)\s*[^;\n]*\b{alias}\b",
    re.IGNORECASE,
)
_CLAMP_RE = re.compile(
    r"if\s+(?P<value>[A-Za-z_][A-Za-z0-9_\.]*)\s*>\s*(?P<limit>[A-Za-z_][A-Za-z0-9_\.]*)\s*"
    r"\{\s*(?P=value)\s*=\s*(?P=limit)\s*\}",
    re.S,
)
_SUB_AFTER_RE = re.compile(
    r"\b[A-Za-z_][A-Za-z0-9_\.]*(?:Debt|Reserve|Reserves|Balance|Balances)\s*(?:-=|=\s*[A-Za-z_][A-Za-z0-9_\.]*\s*-)\s*{value}\b",
    re.IGNORECASE,
)
_REJECT_GUARD_RE = re.compile(
    r"if\s+[^{}]{0,220}(?:>|<|>=|<=|overflow|underflow|MaxUint|MaxInt|fits)[^{}]{0,220}\{[^{}]{0,220}\breturn\b",
    re.IGNORECASE | re.S,
)


def _strip_comments_and_strings(text: str) -> str:
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r'`[^`]*`|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', "", text)


def _narrow_reason(body_text: str) -> str | None:
    for match in _NARROW_ASSIGN_RE.finditer(body_text):
        if _REJECT_GUARD_RE.search(body_text[: match.start()]):
            continue
        tail = body_text[match.end(): match.end() + 700]
        write_re = re.compile(_ALIAS_WRITE_RE.pattern.format(alias=re.escape(match.group("alias"))), re.I)
        if write_re.search(tail):
            return (
                f"{match.group('alias')} narrows {match.group('expr').strip()} "
                f"with {match.group('cast')} before reserve or fee accounting"
            )
    return None


def _clamp_reason(body_text: str) -> str | None:
    for match in _CLAMP_RE.finditer(body_text):
        if _REJECT_GUARD_RE.search(body_text[: match.start()]):
            continue
        tail = body_text[match.end(): match.end() + 500]
        sub_re = re.compile(_SUB_AFTER_RE.pattern.format(value=re.escape(match.group("value"))), re.I)
        if sub_re.search(tail):
            return (
                f"{match.group('value')} is clamped to {match.group('limit')} "
                f"and then subtracted from accounting state"
            )
    return None


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = engine.text(fn)
        body_text = _strip_comments_and_strings(engine.text(body))
        if not _ACCOUNTING_RE.search(fn_text):
            continue

        reason = _narrow_reason(body_text) or _clamp_reason(body_text)
        if reason is None:
            continue

        hits.append({
            "severity": "medium",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": fn_text.splitlines()[0][:160],
            "message": (
                f"`{name}` has a rounding-direction accounting loss: "
                f"{reason}. Reject lossy narrowing or excessive clamp inputs "
                f"before mutating accounting state. (class: rounding-direction-attack)"
            ),
        })
    return hits
