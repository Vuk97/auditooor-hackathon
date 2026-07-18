"""_util.py — shared helpers for plonky3_wave1 regex-based detectors.

Plonky3 (Polygon's next-gen AIR/STARK framework, https://github.com/Plonky3/Plonky3)
is written in Rust. These helpers extract Plonky3-specific shape info from Rust
source WITHOUT requiring tree-sitter-rust. They operate on raw strings.

Key Plonky3 API surfaces detected:
  - Air<AB: AirBuilder> trait impls with fn eval(&self, builder: &mut AB)
  - builder.main() row accessors (local, next)
  - builder.assert_eq / builder.assert_zero for constraints
  - Lookup argument: builder.send / builder.receive (LogUp / Lasso)
  - Column types accessed via row[i] or struct field projection
"""
from __future__ import annotations

import re
from typing import Iterable

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    """Strip // and /* */ comments. Conservative; does not handle string
    literals containing comment-like substrings."""
    return _COMMENT_RE.sub("", source)


def line_col(source: str, offset: int) -> tuple[int, int]:
    """1-indexed line, 1-indexed column for a byte offset into `source`."""
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def block_end(source: str, open_brace_offset: int) -> int:
    """Return the offset just past the matching `}` for the `{` at
    `open_brace_offset`. Returns len(source) if unbalanced (degraded)."""
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


def is_plonky3_file(source: str) -> bool:
    """Heuristic: Plonky3 sources import p3_* crates or implement Air<AB>."""
    if re.search(r"\buse\s+p3_(?:air|field|matrix|uni_stark|commit)\s*::", source):
        return True
    if re.search(r"\bimpl\s*(?:<[^>]*>)?\s*Air\s*<", source):
        return True
    if re.search(r"\bAirBuilder\b", source):
        return True
    return False


def find_eval_body(source: str) -> tuple[int, int] | None:
    """Find the body of `fn eval(&self, builder: &mut AB)` in an Air impl.
    Returns (body_start, body_end) or None."""
    pat = re.compile(
        r"\bfn\s+eval\s*(?:<[^>]*>)?\s*\(\s*&\s*self\s*,\s*"
        r"(?:[^)]*builder[^)]*)\)\s*(?:->[^{]*)?\{",
        re.M | re.S,
    )
    m = pat.search(source)
    if not m:
        return None
    open_brace = m.end() - 1
    end = block_end(source, open_brace)
    return open_brace + 1, end - 1


def extract_row_field_accesses(body: str) -> list[str]:
    """Extract column names accessed as `local.<field>` or `next.<field>`
    or via `row[<idx>]` in an eval body. Name-based only."""
    names: list[str] = []
    for m in re.finditer(
        r"\b(?:local|next)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)", body
    ):
        names.append(m.group(1))
    return names


def extract_assert_calls(body: str) -> str:
    """Return concatenation of all builder.assert_eq / assert_zero call sites.
    Only captures the text up to the matching closing parenthesis to avoid
    pulling in code that follows the assert call."""
    parts: list[str] = []
    for m in re.finditer(
        r"\bbuilder\s*\.\s*(?:assert_eq|assert_zero|when|assert_bool)\s*\(",
        body,
    ):
        # Balance-match parens to find the end of this call.
        depth = 1
        i = m.end()
        while i < len(body) and depth > 0:
            if body[i] == "(":
                depth += 1
            elif body[i] == ")":
                depth -= 1
            i += 1
        parts.append(body[m.start() : i])
    return "\n".join(parts)
