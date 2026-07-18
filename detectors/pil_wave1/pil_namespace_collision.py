"""pil_namespace_collision.py

Flags PIL column names that are declared in more than one namespace within
the same file. When a column name is reused across namespaces, PIL
compilers that do not enforce strict namespace scoping can silently shadow
the first declaration, causing the wrong column to be used in a constraint.
Depending on the PIL compiler version, the collision may also make
cross-namespace lookup arguments reference the wrong column set.

Background: PIL organizes columns into namespaces (similar to modules in
a hardware description language). If two namespaces declare a column with
the same local name, and a constraint referencing the name appears at a
scope where both are visible, the first matching declaration wins (or the
second, depending on compiler version). This ambiguity is the "namespace
collision" class in the PIL 2-bug corpus.

Detection (regex-only):
  1. File must look like PIL (namespace / col commit / col fixed keywords).
  2. Extract all (namespace, column_name) pairs.
  3. For each column_name that appears in >= 2 different namespaces,
     emit a finding.

Known limitations:
  - Local-column masking is intentional in some PIL macro patterns
    (parameterized sub-components reuse names by design). Reviewer
    should verify that cross-namespace lookups do not accidentally
    reference the wrong column.
  - In PIL2, namespaces are strictly scoped and the compiler raises an
    error for true ambiguity. This detector is most relevant for PIL1
    and PIL2 files used in zkEVM implementations where the compiler
    may have different scoping rules.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from . import _util
except ImportError:
    import importlib.util as _ilu
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = _ilu.spec_from_file_location("pil_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "pil_namespace_collision"


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_pil_file(source, filepath):
        return []

    col_by_ns = _util.extract_col_names_per_namespace(source)
    if not col_by_ns:
        return []

    # Build reverse map: col_name -> list of (namespace, offset)
    col_to_ns: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for ns_name, cols in col_by_ns.items():
        for col_name, offset in cols:
            col_to_ns[col_name].append((ns_name, offset))

    hits: list[dict[str, Any]] = []
    for col_name, ns_list in col_to_ns.items():
        if len(ns_list) < 2:
            continue
        # Emit one finding per collision, anchored to the second declaration.
        ns_names = [ns for ns, _ in ns_list]
        offset = ns_list[1][1]
        line, col = _util.line_col(source, offset)
        snippet = source[offset : offset + 180].replace("\n", " ")
        hits.append({
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": line,
            "col": col,
            "severity": "medium",
            "message": (
                f"Column `{col_name}` is declared in multiple namespaces: "
                f"{ns_names}. Cross-namespace name collision can cause the "
                "PIL compiler to silently use the wrong column in a "
                "constraint or lookup argument, depending on scoping rules. "
                "Rename one of the columns or qualify all cross-namespace "
                "references explicitly."
            ),
            "snippet": snippet,
        })
    return hits
