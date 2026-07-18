"""noir_array_index_oob.py

Flags Noir array index operations where a runtime-variable index is used
without a preceding bounds check (`assert(index < array.len())` or
`assert(index < ARRAY_SIZE)`). Noir compiles circuits with static sizes;
at proving time an out-of-bounds access panics the prover (DoS) and may
produce undefined behavior in some backends.

Detection (regex-only):
  1. File must look like Noir.
  2. Identify array type declarations: `let X: [T; N]` or `let X: [T]`.
  3. Find index operations: `X[idx]` where `idx` is not a literal integer.
  4. Scan backward in the same function body for `assert(idx < ...)` or
     `assert(idx <= ...)` within the preceding N statements (N=10 heuristic).
  5. If no bounds check found, emit a finding.

Known FPs:
  - Loop variables provably bounded by the loop range (`for i in 0..N { arr[i] }`).
    The detector exempts `for`-loop variables by detecting `for <var> in`.
  - Constant folding / compile-time known indices that are disguised as
    variables (e.g. `let idx: u32 = 3;`). Not detected as safe by regex.

Reference: Noir runtime panics on OOB array access; zkBugs "Missing Range
Check" class. CVE-analog: Barretenberg ACIR proving panic.
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
    _spec = importlib.util.spec_from_file_location("noir_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "noir_array_index_oob"

# Array index: `name[expr]` where expr is NOT a plain integer literal
_ARRAY_INDEX_RE = re.compile(
    r"\b(?P<arr>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(?P<idx>[^0-9\]\s][^\]]*)\]",
    re.M,
)

# Bounds check pattern: assert(idx < ...) or assert(idx <= ...)
_BOUNDS_CHECK_TEMPLATE = r"\b(?:assert|constrain)\s*\(\s*{idx}\s*[<>]=?\s*"

# For-loop variable detection: `for idx in 0..N` — variable is loop-bounded
_FOR_LOOP_RE = re.compile(
    r"\bfor\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+",
    re.M,
)


def _is_loop_var(var: str, body: str) -> bool:
    """Return True if `var` is a for-loop iteration variable in `body`."""
    for m in _FOR_LOOP_RE.finditer(body):
        if m.group("var") == var:
            return True
    return False


def _has_bounds_check(idx_expr: str, body_before: str) -> bool:
    """Check if a bounds assert appears in `body_before` for `idx_expr`."""
    # Only handle simple identifiers in idx_expr
    ident = idx_expr.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ident):
        return False  # complex expressions — not checked, no FP
    pat = re.compile(
        _BOUNDS_CHECK_TEMPLATE.format(idx=re.escape(ident)),
        re.M,
    )
    return bool(pat.search(body_before))


def find_oob_accesses(source: str) -> list[dict[str, Any]]:
    """Return findings for potentially unbounded array index accesses."""
    if not _util.is_noir_file(source):
        return []
    stripped = _util.strip_comments(source)

    findings: list[dict[str, Any]] = []

    for fn_name, _is_unconstrained, body_start, body_end in _util.iter_fns(stripped):
        body = stripped[body_start:body_end]
        # Collect for-loop variables (they are range-bounded)
        loop_vars = set()
        for m in _FOR_LOOP_RE.finditer(body):
            loop_vars.add(m.group("var"))

        for m in _ARRAY_INDEX_RE.finditer(body):
            arr = m.group("arr")
            idx = m.group("idx").strip()

            # Skip literal integer indices
            if re.fullmatch(r"\d+", idx):
                continue
            # Skip loop variables (bounded by range)
            if idx in loop_vars:
                continue
            # Skip if a bounds check appears before this access
            body_before = body[: m.start()]
            if _has_bounds_check(idx, body_before):
                continue

            findings.append(
                {
                    "arr": arr,
                    "idx": idx,
                    "fn_name": fn_name,
                    "offset": body_start + m.start(),
                }
            )

    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_oob_accesses(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 200].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "array": f["arr"],
                "index_expr": f["idx"],
                "fn_name": f["fn_name"],
                "severity": "medium",
                "message": (
                    f"Array `{f['arr']}` indexed with `{f['idx']}` in fn "
                    f"`{f['fn_name']}` without a preceding bounds check "
                    f"(`assert({f['idx']} < {f['arr']}.len())`). "
                    "An out-of-bounds index panics the Noir prover (DoS) and "
                    "may produce undefined circuit behavior in some backends."
                ),
                "snippet": snippet,
            }
        )
    return hits
