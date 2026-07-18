"""halo2_selector_inactive_constraint_leak.py

Flags Halo2 `meta.create_gate` constraints where a selector is queried
via `meta.query_selector` but the returned vec!-of-constraints contains
at least one expression that does NOT multiply by that selector. The
effect is that the constraint applies on ALL rows (including rows where
the selector is disabled), causing unsatisfiable proofs in honest
witnesses OR enabling forged proofs depending on the surrounding gate
logic.

This is the "Incorrect Custom Gates" / "Selector inactive constraint
leak" zkBugs class — example: "The OneHot encoding gadget has
incorrect constraints" where one of three constraints applied
regardless of the OneHot selector state.

Heuristic (regex-only):
  1. Inside each `meta.create_gate(... |meta| { ... })` body, find the
     selector identifier from `let s = meta.query_selector(<col>)`.
  2. Find the returned `vec![ expr1, expr2, ... ]` (last `vec!` block).
  3. For each `expr_i`, check that the selector identifier appears
     somewhere in the expression text. If NOT → finding.

Known FPs:
  - Constraints written as `Constraints::with_selector(s, vec![...])`
    where the wrapper applies the selector externally. The detector
    treats this construct as safe (presence of
    `Constraints::with_selector` in the gate body suppresses the
    finding).
  - Constraints that compose multiple selector identifiers via boolean
    products (e.g. `s_active * s_subcase * (...)`). The detector
    counts any selector reference as sufficient; correctness of the
    composite is left to reviewer.

Reference: zkBugs class "Incorrect Custom Gates"; canonical example
"The OneHot encoding gadget has incorrect constraints".
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
    _spec = importlib.util.spec_from_file_location("halo2_wave1__util_sicl", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "halo2_selector_inactive_constraint_leak"

_CREATE_GATE_RE = re.compile(
    r"\bmeta\s*\.\s*create_gate\s*\(\s*(?:&?\"[^\"]*\"|\w+)\s*,\s*\|\s*[A-Za-z_][A-Za-z0-9_]*\s*\|\s*\{",
    re.M | re.S,
)

_QUERY_SELECTOR_RE = re.compile(
    r"\blet\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*meta\s*\.\s*query_selector\s*\(",
    re.M,
)

_CONSTRAINTS_WITH_SELECTOR_RE = re.compile(
    r"\bConstraints\s*::\s*with_selector\s*\(", re.M
)

_VEC_OPEN_RE = re.compile(r"\bvec!\s*\[", re.M)


def _split_vec_expressions(vec_body: str) -> list[str]:
    """Split a vec! body into top-level expressions by commas, respecting
    paren/bracket depth."""
    exprs: list[str] = []
    depth = 0
    start = 0
    for i, c in enumerate(vec_body):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            chunk = vec_body[start:i].strip()
            if chunk:
                exprs.append(chunk)
            start = i + 1
    tail = vec_body[start:].strip()
    if tail:
        exprs.append(tail)
    return exprs


def find_selector_leaks(source: str) -> list[dict[str, Any]]:
    if not _util.is_halo2_file(source):
        return []
    stripped = _util.strip_comments(source)

    findings: list[dict[str, Any]] = []
    for m in _CREATE_GATE_RE.finditer(stripped):
        open_brace = m.end() - 1
        end = _util.block_end(stripped, open_brace)
        body = stripped[open_brace + 1: end - 1]

        # If the gate uses Constraints::with_selector, it's safe by construction
        if _CONSTRAINTS_WITH_SELECTOR_RE.search(body):
            continue

        sel_names = [sm.group("name") for sm in _QUERY_SELECTOR_RE.finditer(body)]
        if not sel_names:
            # Handled by gate_polynomial_degree_mismatch detector
            continue

        # Find the LAST vec! block in body (the return)
        last_vec_open = None
        for vm in _VEC_OPEN_RE.finditer(body):
            last_vec_open = vm
        if last_vec_open is None:
            continue
        depth = 1
        i = last_vec_open.end()
        vec_end = -1
        while i < len(body):
            c = body[i]
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    vec_end = i
                    break
            i += 1
        if vec_end < 0:
            continue
        vec_body = body[last_vec_open.end():vec_end]
        exprs = _split_vec_expressions(vec_body)

        leaky: list[str] = []
        for expr in exprs:
            mentions = any(
                re.search(rf"\b{re.escape(name)}\b", expr) for name in sel_names
            )
            if not mentions:
                leaky.append(expr[:120].replace("\n", " "))
        if leaky:
            findings.append(
                {
                    "offset": m.start(),
                    "selector_names": sel_names,
                    "leaky_count": len(leaky),
                    "leaky_preview": leaky[0],
                }
            )
    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_selector_leaks(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 220].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "selector_names": f["selector_names"],
                "leaky_constraint_count": f["leaky_count"],
                "severity": "high",
                "message": (
                    f"meta.create_gate body queries selector(s) "
                    f"{f['selector_names']} but {f['leaky_count']} returned "
                    "constraint expression(s) do not multiply by the "
                    "selector. The constraint applies on all rows "
                    "regardless of selector state. Wrap with "
                    "Constraints::with_selector or multiply each "
                    "expression by the selector explicitly. zkBugs "
                    "'Incorrect Custom Gates' class."
                ),
                "snippet": snippet,
            }
        )
    return hits
