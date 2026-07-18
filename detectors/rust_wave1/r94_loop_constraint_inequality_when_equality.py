"""
r94_loop_constraint_inequality_when_equality.py

Flags ZK/circuit balancing checks that use a weak inequality (`<=`/`>=`)
where a conservation/equality constraint is expected.

Class: constraint-inequality-when-equality (rust_only).
Source: Solodit #60158 / Quantstamp Hinkal Protocol, generalized from the
Circom "balancing inequality allows undistributed funds" pattern into Rust
circuit implementations.

Heuristic:
  1. Inspect Rust functions with circuit/constraint/verification context.
  2. Require ZK-ish body vocabulary (constraint system, layouter, region,
     witness, public input, r1cs, halo2, arkworks, bellperson, etc.).
  3. Flag `assert!` / `debug_assert!` / `require!` / `constrain(...)` /
     `enforce_constraint(...)` calls whose predicate compares flow/balance
     totals with `<=` or `>=`.

This intentionally does not flag ordinary business-logic bounds checks or
range checks: both the function/body context and the compared identifier names
must look like a balancing equation.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
)


_FN_CONTEXT_RE = re.compile(
    r"(?i)(circuit|constraint|constrain|synthesize|verify|prove|assign|"
    r"balance|settle|distribute)"
)

_BODY_CONTEXT_RE = re.compile(
    r"(?i)(constraint_system|constraintsystem|layouter|region|assignedcell|"
    r"public_input|witness|r1cs|halo2|arkworks|bellperson|bellman|circom|"
    r"plonk|groth|proof|prover|verifier|constrain|constraint)"
)

_FLOW_TERM = (
    r"(?:sum|total|amount|balance|input|output|inflow|outflow|debit|credit|"
    r"asset|liability|distributed|distribution|withdraw|deposit|note|fund)"
)

_WEAK_BALANCE_RE = re.compile(
    rf"(?P<call>\b(?:assert|debug_assert|require)!\s*\(|"
    rf"\b(?:constrain|enforce_constraint|require_constraint)\s*\()"
    rf"(?P<expr>[^;\n)]*{_FLOW_TERM}[\w\.]*\s*(?:<=|>=)\s*"
    rf"[\w\.]*{_FLOW_TERM}[^;\n)]*)",
    re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn in function_items(root):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not (_FN_CONTEXT_RE.search(name) or _FN_CONTEXT_RE.search(body_nc)):
            continue
        if not _BODY_CONTEXT_RE.search(body_nc):
            continue

        m = _WEAK_BALANCE_RE.search(body_nc)
        if m is None:
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"ZK/circuit function `{name}` constrains a balancing "
                f"equation with a weak inequality (`{m.group('expr').strip()}`) "
                f"instead of equality. Conservation/public-input balance "
                f"checks should use `==`/`assert_eq!`/equality constraints so "
                f"provers cannot leave value undistributed."
            ),
        })
    return hits
