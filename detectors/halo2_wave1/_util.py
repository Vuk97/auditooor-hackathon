"""_util.py — shared helpers for halo2_wave1 regex-based detectors.

These helpers extract Halo2-specific shape info (impl Chip blocks, fn
synthesize bodies, advice/fixed/selector column names) from Rust source
WITHOUT requiring tree-sitter-rust. They operate on raw strings.

Designed as a sister module to detectors/rust_wave1/_util.py (which is
tree-sitter-rust-based and remains the canonical Rust extractor). The
Halo2 wave intentionally chooses the regex path to keep new framework
detectors decoupled from the heavier AST stack.
"""
from __future__ import annotations

import re
from typing import Iterable

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    """Strip // and /* */ comments. Conservative; does not handle string
    literals containing comment-like substrings, which is acceptable for
    coarse pattern-scanning."""
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


def is_halo2_file(source: str) -> bool:
    """Heuristic: Halo2 sources `use halo2_proofs::*` or `use halo2::*` or
    define `impl<F: Field> Chip<F>`. Either is sufficient."""
    if re.search(r"\buse\s+halo2(?:_proofs)?\s*::", source):
        return True
    if re.search(r"\bimpl\s*<[^>]*>\s*Chip\s*<", source):
        return True
    if re.search(r"\bConstraintSystem\s*<", source):
        return True
    return False


_IMPL_BLOCK_RE = re.compile(
    r"\bimpl\s*(?:<[^>]*>)?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:\s*<[^>]*>)?)"
    r"(?:\s+for\s+(?P<for_target>[A-Za-z_][A-Za-z0-9_:]*(?:\s*<[^>]*>)?))?\s*\{",
    re.M,
)


def iter_impl_blocks(source: str) -> Iterable[tuple[int, int, str, str | None]]:
    """Yield (body_start, body_end, impl_target_name, for_target_or_none)
    for each `impl ... { ... }` block. Body offsets bracket the inner
    block contents (excluding the outer braces)."""
    src = source
    for m in _IMPL_BLOCK_RE.finditer(src):
        # Open brace is the final char of the match
        open_brace = m.end() - 1
        end = block_end(src, open_brace)
        body_start = open_brace + 1
        body_end = end - 1
        yield body_start, body_end, m.group("name").strip(), (
            m.group("for_target").strip() if m.group("for_target") else None
        )


_FN_BODY_RE = re.compile(
    r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\([^)]*\)"
    r"(?:\s*->\s*[^\{;]+)?\s*\{",
    re.M | re.S,
)


def iter_fn_bodies(source: str) -> Iterable[tuple[str, int, int]]:
    """Yield (fn_name, body_start, body_end) for each top-level / nested
    `fn name(...) [-> ret] { ... }` in `source`. body bounds exclude the
    outer `{}`."""
    src = source
    for m in _FN_BODY_RE.finditer(src):
        open_brace = m.end() - 1
        end = block_end(src, open_brace)
        yield m.group("name").strip(), open_brace + 1, end - 1


def find_advice_columns(body: str) -> list[str]:
    """Extract names of advice columns assigned via `let X = meta.advice_column()`
    or `let X = config.<field>` patterns. Best-effort; pattern is a hint, not
    a guarantee."""
    out: list[str] = []
    for m in re.finditer(
        r"\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*meta\s*\.\s*advice_column\s*\(",
        body,
    ):
        out.append(m.group("name"))
    return out


def find_fixed_columns(body: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(
        r"\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*meta\s*\.\s*fixed_column\s*\(",
        body,
    ):
        out.append(m.group("name"))
    return out


def find_selectors(body: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(
        r"\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*meta\s*\.\s*(?:complex_)?selector\s*\(",
        body,
    ):
        out.append(m.group("name"))
    return out
