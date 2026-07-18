"""
zkbugs_num2bits_254_state_alias.py

Flags Circom circuits that decompose state/flag/blacklist leaves with
Num2Bits(254). On BN254, field elements cannot represent every 254-bit pattern
as an unconstrained external integer; using high bits for state encodings can
make intended states unreachable or aliased.

Source: zkBugs / panther-core
`veridise_blacklist_states_not_representable_in_field`.
"""
from __future__ import annotations

import re


_NUM2BITS_254_RE = re.compile(r"\bNum2Bits\s*\(\s*254\s*\)")
_STATE_HINT_RE = re.compile(r"(?:blacklist|state|status|flag|zone|kyc|leaf|membership)", re.I)
_HIGH_BIT_RE = re.compile(r"\[\s*(?:25[1-3]|24[8-9]|250)\s*\]")
_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def _strip_comments(source: str) -> str:
    return _COMMENT_RE.sub("", source)


def _line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def num2bits_254_state_alias_offsets(source: str) -> list[int]:
    """Return Num2Bits(254) offsets that look tied to state/high-bit encodings."""
    body = _strip_comments(source)
    out: list[int] = []
    for match in _NUM2BITS_254_RE.finditer(body):
        start = max(0, match.start() - 320)
        end = min(len(body), match.end() + 520)
        window = body[start:end]
        if _STATE_HINT_RE.search(window) and _HIGH_BIT_RE.search(window):
            out.append(match.start())
    return out


def run_text(source: str, filepath: str) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for offset in num2bits_254_state_alias_offsets(source):
        line, col = _line_col(source, offset)
        snippet = source[offset : offset + 180].replace("\n", " ")
        hits.append(
            {
                "severity": "medium",
                "line": line,
                "col": col,
                "snippet": snippet,
                "message": (
                    "State/blacklist-style encoding uses Num2Bits(254) and high "
                    "bit positions. Verify that all intended states are "
                    "representable in the Circom field and range constrained. "
                    "See zkBugs panther-core "
                    "veridise_blacklist_states_not_representable_in_field."
                ),
            }
        )
    return hits
