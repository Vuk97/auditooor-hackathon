"""noir_unconstrained_fn_unsafe_use.py

Flags uses of `unconstrained fn` return values inside constrained functions
WITHOUT a subsequent `assert` or explicit constraint on the returned value.

In Noir, `unconstrained fn` functions run outside the ZK circuit (like Solidity's
`view` hint). Their return values are NOT verified by the circuit unless the
caller explicitly constrains them (e.g. `assert(result == expected_expr)`).
Using an unconstrained result directly as a circuit input or returning it
from a constrained function is a soundness hole: the prover can return any
value the hint computes, without ZK proof.

Detection (regex-only):
  1. File must look like Noir.
  2. Identify all `unconstrained fn <name>` definitions and record their names.
  3. In constrained functions (non-unconstrained fn bodies), find calls to
     unconstrained functions: `let X = unconstrained_fn_name(...)`.
  4. Check whether X is immediately used in an `assert(X == ...)` or
     `assert_eq!(X, ...)` call within the same function body.
  5. If X flows into a `return` statement, another function call, or an
     arithmetic expression WITHOUT any assert, flag it.

Known FPs:
  - Unconstrained results used as loop bounds (intentional non-constrained hint).
  - Inline unconstrained closures (rare in Noir). Document with
    `// noir-unconstrained-ok` to suppress.

Reference: Noir docs "Unconstrained Functions"; zkBugs analog: Circom
"Under-constrained signals" class.
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


DETECTOR_ID = "noir_unconstrained_fn_unsafe_use"

_UNCONSTRAINED_DEF_RE = re.compile(
    r"\bunconstrained\s+(?:pub\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
    re.M,
)

_LET_CALL_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<fn>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.M,
)

_ASSERT_RE = re.compile(
    r"\b(?:assert|assert_eq\s*!|constrain)\s*\(",
    re.M,
)

_SUPPRESS_RE = re.compile(r"noir-unconstrained-ok", re.I)


def _has_assert_on_var(var: str, body_after: str) -> bool:
    """Check if `var` appears in an assert/assert_eq call after its definition."""
    for m in _ASSERT_RE.finditer(body_after):
        # grab the assertion arguments (up to the matching paren)
        depth = 1
        i = m.end()
        arg_buf = []
        while i < len(body_after) and depth > 0:
            c = body_after[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            arg_buf.append(c)
            i += 1
        arg_text = "".join(arg_buf)
        if re.search(rf"\b{re.escape(var)}\b", arg_text):
            return True
    return False


def find_unconstrained_unsafe_uses(source: str) -> list[dict[str, Any]]:
    """Return findings for unconstrained fn results used without constraint."""
    if not _util.is_noir_file(source):
        return []
    stripped = _util.strip_comments(source)

    # Collect unconstrained function names
    unconstrained_fns: set[str] = set()
    for m in _UNCONSTRAINED_DEF_RE.finditer(stripped):
        unconstrained_fns.add(m.group("name"))

    if not unconstrained_fns:
        return []

    findings: list[dict[str, Any]] = []

    # Scan constrained functions for calls to unconstrained fns
    for fn_name, is_unconstrained, body_start, body_end in _util.iter_fns(stripped):
        if is_unconstrained:
            continue  # skip unconstrained-calling-unconstrained
        body = stripped[body_start:body_end]
        for m in _LET_CALL_RE.finditer(body):
            called_fn = m.group("fn")
            if called_fn not in unconstrained_fns:
                continue
            var = m.group("var")

            # Check for suppress annotation
            line_start = body.rfind("\n", 0, m.start()) + 1
            line_end = body.find("\n", m.end())
            if line_end < 0:
                line_end = len(body)
            if _SUPPRESS_RE.search(body[line_start:line_end]):
                continue

            body_after = body[m.end():]
            if _has_assert_on_var(var, body_after):
                continue

            findings.append(
                {
                    "var": var,
                    "called_fn": called_fn,
                    "caller_fn": fn_name,
                    "offset": body_start + m.start(),
                }
            )

    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_unconstrained_unsafe_uses(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 200].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "var": f["var"],
                "called_fn": f["called_fn"],
                "caller_fn": f["caller_fn"],
                "severity": "high",
                "message": (
                    f"Result `{f['var']}` of unconstrained fn `{f['called_fn']}` "
                    f"used in constrained fn `{f['caller_fn']}` without a subsequent "
                    "assert/assert_eq constraint. The prover can set any witness value "
                    "for this variable without ZK proof of correctness. "
                    "Add `assert({f['var']} == <expected_expression>)` before use."
                ),
                "snippet": snippet,
            }
        )
    return hits
