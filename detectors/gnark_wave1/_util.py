"""_util.py — shared helpers for gnark_wave1 regex-based detectors.

gnark (https://github.com/Consensys/gnark) is Consensys's Go-based ZK
circuit library. These helpers extract gnark-specific shape info from Go
source files WITHOUT requiring go/ast parsing. They operate on raw strings.

Key gnark API surfaces:
  - frontend.API / api.Add, api.Mul, api.AssertIsEqual, api.AssertIsBoolean
  - emulated.Field[T]: NewElement, NewHint, enforceWidthConditional
  - std/math/bits: ToNAF, ToBinary, ToTernary
  - std/math/emulated: Element constructor, Limbs field
  - std/multicommit: MultiCommitter, commitments
  - Circuit definition: type MyCircuit struct { ... } + Define(api ...)
"""
from __future__ import annotations

import re

_LINE_COMMENT_RE = re.compile(r"//.*?$", re.M)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    s = _LINE_COMMENT_RE.sub("", source)
    s = _BLOCK_COMMENT_RE.sub("", s)
    return s


def line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def is_gnark_file(source: str) -> bool:
    """Heuristic: gnark sources import gnark packages."""
    if re.search(r'"github\.com/Consensys/gnark', source):
        return True
    if re.search(r'"github\.com/consensys/gnark', source):
        return True
    # Common gnark type identifiers as fallback.
    if re.search(r"\bfrontend\s*\.\s*(?:API|Variable|Circuit)\b", source):
        return True
    if re.search(r"\bemulated\s*\.\s*(?:Field|Element|NewElement|NewHint)\b", source):
        return True
    return False


def find_function_bodies(source: str, fn_name_pat: str) -> list[tuple[int, int]]:
    """Find all function bodies matching fn_name_pat (regex for the func name).
    Returns list of (body_start, body_end) pairs."""
    pat = re.compile(
        rf"\bfunc\s*(?:\([^)]*\)\s*)?(?:{fn_name_pat})\s*\([^){{]*\)[^{{]*\{{",
        re.M | re.S,
    )
    results: list[tuple[int, int]] = []
    for m in pat.finditer(source):
        # Find the opening brace
        open_brace_idx = source.rfind("{", m.start(), m.end())
        if open_brace_idx < 0:
            continue
        # Balance-match
        depth = 0
        end = open_brace_idx
        for i in range(open_brace_idx, len(source)):
            c = source[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        results.append((open_brace_idx + 1, end - 1))
    return results
