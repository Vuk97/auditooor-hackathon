"""_util.py — shared helpers for bellperson_wave1 regex-based detectors.

Bellperson (https://github.com/zkcrypto/bellman / Filecoin fork) is the
Groth16 R1CS implementation used by Zcash and Filecoin. These helpers
extract Bellperson-specific shape info from Rust source WITHOUT requiring
tree-sitter-rust.

Key Bellperson API surfaces detected:
  - cs.alloc(|| "<label>", || Ok(<value>)) -> Variable
  - cs.alloc_input(|| "<label>", || Ok(<value>)) -> Variable
  - cs.enforce(|| "<label>", |lc| ..., |lc| ..., |lc| ...)
  - AllocatedNum::alloc(cs.namespace(|| "..."), || Ok(...))
  - AllocatedBit::alloc(cs.namespace(|| "..."), Some(...))
"""
from __future__ import annotations

import re

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    return _COMMENT_RE.sub("", source)


def line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def block_end(source: str, open_brace_offset: int) -> int:
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


def is_bellperson_file(source: str) -> bool:
    """Heuristic: Bellperson sources import bellperson:: or use ConstraintSystem."""
    if re.search(r"\buse\s+bellperson\s*::", source):
        return True
    if re.search(r"\buse\s+bellman\s*::", source):
        return True
    if re.search(r"\bConstraintSystem\s*<", source):
        return True
    if re.search(r"\bAllocatedNum\s*::\s*alloc\b", source):
        return True
    if re.search(r"\bSynthesisError\b", source):
        return True
    return False


def find_alloc_sites(source: str) -> list[tuple[str, int]]:
    """Return list of (var_name, offset) for all cs.alloc / alloc_input
    let-binding sites in `source`."""
    results: list[tuple[str, int]] = []
    pat = re.compile(
        r"\blet\s+(?:mut\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?:cs\s*\.\s*(?:alloc|alloc_input)|AllocatedNum\s*::\s*alloc|"
        r"AllocatedBit\s*::\s*alloc)\s*\(",
        re.M,
    )
    for m in pat.finditer(source):
        results.append((m.group("name"), m.start()))
    return results


def find_enforce_blobs(source: str) -> str:
    """Return concatenation of all cs.enforce(...) call text."""
    parts: list[str] = []
    pat = re.compile(r"\bcs\s*\.\s*enforce\s*\(", re.M)
    for m in pat.finditer(source):
        start = m.start()
        parts.append(source[start : start + 400])
    return "\n".join(parts)
