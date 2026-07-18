"""_util.py — shared helpers for cairo_wave1 regex-based detectors.

Cairo (StarkWare's ZK-VM language, https://cairo-lang.org) uses a unique
syntax with hints (`%{ ... %}`), references, and tempvar/local/let bindings.
These helpers extract Cairo-specific shape info from source files WITHOUT
requiring a full parser. They operate on raw strings.

Supports both Cairo 0.x (with `%builtins`, `func`, `alloc_locals`) and
Cairo 1.x (with `fn`, `use starknet::`, `#[storage_var]`, `#[view]`).

Key constructs:
  - Hints: %{ ... %}
  - Storage vars: @storage_var / #[storage_var]
  - Assertions: assert X = Y (Cairo 0.x) / assert!(X == Y) (Cairo 1.x)
  - Tempvar / local / let bindings
"""
from __future__ import annotations

import re
from typing import Iterable

_LINE_COMMENT_RE = re.compile(r"//.*?$", re.M)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.M | re.S)
_HASH_COMMENT_RE = re.compile(r"#.*?$", re.M)  # Cairo 0.x uses # comments too


def strip_comments(source: str) -> str:
    """Strip // line comments and /* */ block comments.
    Cairo 0.x # comments are kept (they're decorators too)."""
    s = _LINE_COMMENT_RE.sub("", source)
    s = _BLOCK_COMMENT_RE.sub("", s)
    return s


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


def is_cairo_file(source: str) -> bool:
    """Heuristic: Cairo files use %builtins, %{ hints, func/fn with
    felt/felt252 types, or starknet imports."""
    if re.search(r"%\{", source):  # hint block
        return True
    if re.search(r"\b(?:felt|felt252)\b", source):
        return True
    if re.search(r"\buse\s+starknet\s*::", source):
        return True
    if re.search(r"#\[starknet::", source):
        return True
    if re.search(r"@storage_var\b|\bstorage_var\b", source):
        return True
    if re.search(r"\bfunc\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", source):
        return True
    return False


# Cairo 0.x: func name{implicit_args}(params) -> ret { ... }
# Cairo 1.x: fn name(params) -> ret { ... }
# Use [^{]* to skip over implicit arg blocks and return types before the body.
_FN_RE = re.compile(
    r"\b(?:func|fn)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)[^{;]*\{",
    re.M | re.S,
)


def iter_fn_bodies(source: str) -> Iterable[tuple[str, int, int]]:
    """Yield (fn_name, body_start, body_end) for each fn/func body."""
    for m in _FN_RE.finditer(source):
        open_brace = m.end() - 1
        end = block_end(source, open_brace)
        yield m.group("name"), open_brace + 1, end - 1


def find_hint_blocks(source: str) -> list[tuple[int, int, str]]:
    """Return list of (start, end, hint_text) for each %{ ... %} block."""
    out = []
    pat = re.compile(r"%\{(?P<body>.*?)%\}", re.M | re.S)
    for m in pat.finditer(source):
        out.append((m.start(), m.end(), m.group("body")))
    return out


def find_storage_var_defs(source: str) -> list[str]:
    """Return names of storage_var decorated variables.
    Handles both @storage_var (Cairo 0.x) and #[storage_var] (Cairo 1.x)."""
    out = []
    # Cairo 0.x: @storage_var\nfunc name_storage{...}
    for m in re.finditer(
        r"@storage_var\s*\n\s*func\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        source,
        re.M,
    ):
        out.append(m.group("name"))
    # Cairo 1.x: #[storage_var]\nfn name() -> ...
    for m in re.finditer(
        r"#\[storage_var\]\s*\n\s*(?:fn|func)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
        source,
        re.M,
    ):
        out.append(m.group("name"))
    return out
