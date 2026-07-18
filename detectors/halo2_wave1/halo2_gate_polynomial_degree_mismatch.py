"""halo2_gate_polynomial_degree_mismatch.py

Flags Halo2 `meta.create_gate(...)` blocks whose constraint expression
multiplies selector(s) by a polynomial of degree that exceeds the
chip's documented / declared maximum degree (or where the Constraints
builder lacks the documented `with_selector` gate-degree contract).

Heuristic shape (regex-only — coarse by design):
  1. Inside a `meta.create_gate("...", |meta| { ... })` body, look for
     a `vec![ <expr_1>, <expr_2>, ... ]` or a `Constraints::with_selector(
     selector, vec![ ... ])` return.
  2. Count the maximum chained `*` multiplications in any single
     expression (proxy for polynomial degree).
  3. If the chained-multiplication count exceeds 3 (Halo2 default
     maximum degree for a 2-row gate is 5; chips that don't declare
     a custom max-degree typically aim for ≤3 to leave headroom for
     the selector multiplier), flag.
  4. Additionally flag any `meta.create_gate` body whose returned vec!
     contains an expression where a selector multiplier is NOT applied
     (the gate is effectively always-on regardless of selector state).

This maps to the zkBugs "Wrong Translation of Logic into Constraints"
class (18 of 35 Halo2 bugs — the broadest cluster). Examples include
scroll-tech/zkevm-circuits bugs "ExpCircuit has a under-constrained
exponentiation algorithm" and "Incorrect constraints in configure_nonce".

Known FPs:
  - Custom Chips that explicitly declare `meta.degree() = 5+` via a
    higher-degree gate constraint legitimately use degree ≥4. The
    detector emits Medium (not Critical/High) by default; reviewer
    should grep `meta.set_minimum_degree(` to dismiss.
  - Expressions wrapped in helper closures (e.g. `polynomial(...)`)
    bypass the multiplication-count heuristic — this is a known
    false-negative escape.

Reference: zkBugs cluster "Wrong Translation of Logic into Constraints"
(18/35 Halo2 bugs).
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
    _spec = importlib.util.spec_from_file_location("halo2_wave1__util_gpdm", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "halo2_gate_polynomial_degree_mismatch"

_DEGREE_THRESHOLD = 3  # Anything > threshold gets flagged

_CREATE_GATE_RE = re.compile(
    r"\bmeta\s*\.\s*create_gate\s*\(\s*(?:&?\"[^\"]*\"|\w+)\s*,\s*\|\s*[A-Za-z_][A-Za-z0-9_]*\s*\|\s*\{",
    re.M | re.S,
)

_SELECTOR_QUERY_RE = re.compile(
    r"\bmeta\s*\.\s*query_selector\s*\(", re.M
)


def _count_chained_muls(expr: str) -> int:
    """Count the maximum number of `*` chained in a single sub-expression,
    ignoring `*` inside string literals or doc-comments. Conservative:
    one expression like `a * b * c * d` returns 3."""
    # Strip strings cheaply
    cleaned = re.sub(r'"[^"]*"', '""', expr)
    # Split on `+` / `-` / `,` / `;` to get sub-expressions
    chunks = re.split(r"[+\-,;]", cleaned)
    max_count = 0
    for chunk in chunks:
        n = chunk.count("*")
        if n > max_count:
            max_count = n
    return max_count


def find_gate_degree_violations(source: str) -> list[dict[str, Any]]:
    if not _util.is_halo2_file(source):
        return []
    stripped = _util.strip_comments(source)

    findings: list[dict[str, Any]] = []
    for m in _CREATE_GATE_RE.finditer(stripped):
        open_brace = m.end() - 1
        end = _util.block_end(stripped, open_brace)
        body = stripped[open_brace + 1: end - 1]
        # Find the returned vec![ ... ] expressions
        for vm in re.finditer(r"vec!\s*\[", body):
            # Balance-match the [ ]
            depth = 1
            i = vm.end()
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
            vec_body = body[vm.end():vec_end]
            degree = _count_chained_muls(vec_body)
            has_selector_mult = _SELECTOR_QUERY_RE.search(body) is not None
            if degree > _DEGREE_THRESHOLD or not has_selector_mult:
                findings.append(
                    {
                        "offset": m.start(),
                        "degree": degree,
                        "has_selector": has_selector_mult,
                    }
                )
                break  # one finding per gate is enough
    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_gate_degree_violations(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 220].replace("\n", " ")
        if f["degree"] > _DEGREE_THRESHOLD:
            msg = (
                f"meta.create_gate body contains a polynomial expression "
                f"with chained-multiplication count {f['degree']} (> "
                f"threshold {_DEGREE_THRESHOLD}). Verify the chip declares "
                "a sufficient minimum degree via meta.set_minimum_degree; "
                "otherwise the proving system silently rejects the gate."
            )
        else:
            msg = (
                "meta.create_gate body has no meta.query_selector call: "
                "the gate is effectively always-on regardless of selector "
                "state. Wrap each constraint in `selector * (...)` or use "
                "Constraints::with_selector. zkBugs 'Wrong Translation of "
                "Logic into Constraints' class."
            )
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "gate_degree": f["degree"],
                "has_selector_multiplier": f["has_selector"],
                "severity": "medium",
                "message": msg,
                "snippet": snippet,
            }
        )
    return hits
