"""_util.py — shared helpers for noir_wave1 regex-based detectors.

Noir (Aztec's circuit DSL, https://noir-lang.org) is a Rust-inspired
circuit language with a `.nr` file extension. These helpers extract
Noir-specific shape info from source WITHOUT requiring a full parser.
They operate on raw strings.

Key Noir constructs detected:
  - fn / unconstrained fn / comptime fn
  - assert, assert_eq, constrain (deprecated alias)
  - Arrays with literal bounds (e.g. [Field; 32])
  - #[aztec] / #[oracle] annotations
  - global / use / mod declarations
"""
from __future__ import annotations

import re
from typing import Iterable

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    """Strip // and /* */ comments. Conservative."""
    return _COMMENT_RE.sub("", source)


def line_col(source: str, offset: int) -> tuple[int, int]:
    """1-indexed line, 1-indexed column for a byte offset into `source`."""
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def block_end(source: str, open_brace_offset: int) -> int:
    """Return the offset just past the matching `}` for the `{` at
    `open_brace_offset`. Returns len(source) if unbalanced."""
    depth = 0
    for idx in range(open_brace_offset, len(source)):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return len(source)


def is_noir_file(source: str) -> bool:
    """Heuristic: Noir files use `fn`, `unconstrained fn`, `use dep::`,
    `assert`, or have the characteristic `Field` type annotation."""
    if re.search(r"\bunconstrained\s+fn\b", source):
        return True
    if re.search(r"\buse\s+dep::", source):
        return True
    if re.search(r":\s*Field\b", source):
        return True
    if re.search(r"\bpub\s+fn\b.*->.*Field", source, re.S):
        return True
    if re.search(r"\bstruct\b.*\{[^}]*Field", source, re.S):
        return True
    return False


_FN_RE = re.compile(
    # Match Noir fn declarations including complex return types like -> [u8; 32]
    # Use [^{]* for return type to avoid stopping on ; inside array types.
    r"(?P<unconstrained>\bunconstrained\s+)?(?P<comptime>\bcomptime\s+)?"
    r"\b(?:pub\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:<[^>]*>)?\s*\([^)]*\)(?:\s*->\s*[^{]+)?\s*\{",
    re.M | re.S,
)


def iter_fns(source: str) -> Iterable[tuple[str, bool, int, int]]:
    """Yield (fn_name, is_unconstrained, body_start, body_end).
    body bounds exclude the outer `{}`."""
    for m in _FN_RE.finditer(source):
        is_unconstrained = bool(m.group("unconstrained"))
        open_brace = m.end() - 1
        end = block_end(source, open_brace)
        yield m.group("name"), is_unconstrained, open_brace + 1, end - 1


def find_assert_eq_calls(body: str) -> list[tuple[int, str]]:
    """Return (offset, full_match_text) for each assert_eq!(...) call in body."""
    out = []
    for m in re.finditer(r"\bassert_eq\s*!\s*\(", body):
        out.append((m.start(), m.group()))
    return out


def find_assert_calls(body: str) -> list[tuple[int, str]]:
    """Return (offset, snippet) for each assert(...) or constrain(...) call."""
    out = []
    for m in re.finditer(r"\b(?:assert|constrain)\s*\(", body):
        out.append((m.start(), m.group()))
    return out
