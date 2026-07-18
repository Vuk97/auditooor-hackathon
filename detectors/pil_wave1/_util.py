"""_util.py — shared helpers for pil_wave1 regex-based detectors.

PIL (Polynomial Identity Language, https://github.com/0xPolygonHermez/pil2-compiler)
is used by zkEVM implementations (Polygon zkEVM, PIL2-based systems).
These helpers extract PIL-specific shape info from `.pil` files WITHOUT
requiring a full parser.

Key PIL constructs detected:
  - namespace <Name>(<size>): defines a namespace (like a module/chip)
  - col commit <name>: committed column declaration
  - col fixed <name>: fixed (constant) column declaration
  - <col_name>'  (next row reference)
  - <expr> = <expr>: polynomial identity constraint
  - {<col>, ...} in {<col>, ...}: lookup argument
  - is/connect: permutation/connection arguments
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)


def strip_comments(source: str) -> str:
    return _COMMENT_RE.sub("", source)


def line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    col = offset + 1 if last_newline < 0 else offset - last_newline
    return line, col


def is_pil_file(source: str, filepath: str = "") -> bool:
    """Heuristic: PIL files use 'namespace' or 'col commit' or 'col fixed'."""
    if filepath.endswith(".pil"):
        return True
    if re.search(r"\bnamespace\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", source):
        return True
    if re.search(r"\bcol\s+(?:commit|fixed)\b", source):
        return True
    return False


def extract_namespaces(source: str) -> list[tuple[str, int]]:
    """Return list of (namespace_name, offset) for all namespace declarations."""
    results: list[tuple[str, int]] = []
    pat = re.compile(r"\bnamespace\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M)
    for m in pat.finditer(source):
        results.append((m.group("name"), m.start()))
    return results


def extract_col_names_per_namespace(source: str) -> dict[str, list[tuple[str, int]]]:
    """Return {namespace_name: [(col_name, offset), ...]} for all col declarations."""
    stripped = strip_comments(source)
    ns_offsets = extract_namespaces(stripped)
    if not ns_offsets:
        return {}

    # Build namespace spans: from each namespace start to the next (or EOF).
    spans: list[tuple[str, int, int]] = []
    for i, (ns_name, ns_off) in enumerate(ns_offsets):
        end = ns_offsets[i + 1][1] if i + 1 < len(ns_offsets) else len(stripped)
        spans.append((ns_name, ns_off, end))

    col_pat = re.compile(r"\bcol\s+(?:commit|fixed)\s+(?P<col>[A-Za-z_][A-Za-z0-9_]*)", re.M)
    result: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for ns_name, ns_start, ns_end in spans:
        block = stripped[ns_start:ns_end]
        for m in col_pat.finditer(block):
            result[ns_name].append((m.group("col"), ns_start + m.start()))
    return dict(result)
