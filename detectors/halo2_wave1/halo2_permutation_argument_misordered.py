"""halo2_permutation_argument_misordered.py

Flags Halo2 `meta.enable_equality(...)` (or `meta.permutation`) calls
that include only one side of a value pair that the chip later copies
between regions. The result is that one cell can be assigned freely
while the other is range/value-constrained — a classic
"Missing Input Constraints" bug shape: e.g. zkBugs
"ChainId is not mapped to it's corresponding RLP Tag in Tx Circuit"
where two columns SHOULD be permutation-coupled but only one was
enabled for equality.

Heuristic (regex-only):
  1. Collect every column passed to `meta.enable_equality(...)`. These
     columns are flagged as `eq_enabled = True`.
  2. Find every `region.constrain_equal(<lhs_cell>, <rhs_cell>)` and
     `cell.copy_advice(|| ..., region, <col>, offset)`. Extract the
     column identifiers used in copy_advice / constrain_equal.
  3. For each column used in a copy that is NOT eq-enabled, emit a
     finding.

Conservative: emits at Medium because Halo2 has multiple equivalent
APIs (`region.assign_advice_from_constant`, copy via
`region.constrain_equal`, instance-column copies). The detector
focuses on the most common shape.

Known FPs:
  - Columns enabled via a helper macro/function (e.g. `chip.enable_eq(meta)`)
    that internally calls `meta.enable_equality`. The detector cannot
    follow helper indirection.
  - Instance columns (column<Instance>) which Halo2 enables for equality
    by default (the detector excludes columns matching `\\binstance\\b`).

Reference: zkBugs class "Missing Input Constraints" — examples
"ChainId is not mapped" and "Missing constraint for the first tx_id".
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util  # type: ignore
except ImportError:  # pragma: no cover
    import importlib.util
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = importlib.util.spec_from_file_location("halo2_wave1__util_pam", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "halo2_permutation_argument_misordered"

_ENABLE_EQ_RE = re.compile(
    r"\bmeta\s*\.\s*enable_equality\s*\(\s*(?P<col>[A-Za-z_][A-Za-z0-9_.<>:\s]*)\s*\)",
    re.M | re.S,
)

# region.constrain_equal(lhs.cell(), rhs.cell())
_CONSTRAIN_EQ_RE = re.compile(
    r"\bregion\s*\.\s*constrain_equal\s*\(", re.M
)

# `cell.copy_advice(|| ..., &mut region, <col_expr>, offset)`
_COPY_ADVICE_RE = re.compile(
    r"\bcopy_advice\s*\(\s*\|\|\s*[^,]+,\s*&?mut\s+region\s*,\s*"
    r"(?P<col>[A-Za-z_][A-Za-z0-9_.<>:\s]*)\s*,",
    re.M | re.S,
)


def _last_ident(expr: str) -> str:
    parts = re.split(r"[.\s]+", expr.strip())
    parts = [p for p in parts if p]
    return parts[-1] if parts else ""


def find_misordered_permutation(source: str) -> list[dict[str, Any]]:
    if not _util.is_halo2_file(source):
        return []
    stripped = _util.strip_comments(source)

    eq_enabled: set[str] = set()
    for m in _ENABLE_EQ_RE.finditer(stripped):
        ident = _last_ident(m.group("col"))
        if ident:
            eq_enabled.add(ident.lower())

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for m in _COPY_ADVICE_RE.finditer(stripped):
        ident = _last_ident(m.group("col"))
        if not ident or ident in seen:
            continue
        seen.add(ident)
        # Instance columns are eq-enabled by default
        if "instance" in ident.lower():
            continue
        if ident.lower() in eq_enabled:
            continue
        findings.append(
            {
                "offset": m.start(),
                "col": ident,
            }
        )
    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_misordered_permutation(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 220].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "permutation_column": f["col"],
                "severity": "medium",
                "message": (
                    f"Column `{f['col']}` is used in a copy_advice call "
                    "but never appears in any meta.enable_equality "
                    "declaration in this file. The copy will compile "
                    "but the permutation argument silently lacks the "
                    "necessary cell, so the copy is unconstrained at "
                    "proof time. zkBugs 'Missing Input Constraints' "
                    "class."
                ),
                "snippet": snippet,
            }
        )
    return hits
