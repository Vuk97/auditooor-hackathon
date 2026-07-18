"""noir_assert_eq_missing_constraint.py

Flags Noir code where `assert_eq!` is called inside an `unconstrained fn`
body. In Noir, `assert_eq!` DOES generate a circuit constraint — but only
when called from a constrained context. When called from an `unconstrained fn`,
the macro's constraint is silently dropped (it becomes a runtime check only,
equivalent to a Rust `debug_assert!`). The circuit has no enforcing constraint.

This is the "assert_eq inside unconstrained fn" anti-pattern: developers
from Rust backgrounds expect `assert_eq!` to always be enforced, but in
Noir the enforcement depends on the calling context.

Also detects: `constrain` keyword (deprecated Noir alias for `assert`) used
inside an unconstrained function (same issue).

Detection (regex-only):
  1. File must look like Noir.
  2. Find all `unconstrained fn` bodies.
  3. Within each unconstrained fn body, find `assert_eq!(...)` or
     `constrain(...)` calls.
  4. Flag each — these calls do NOT generate circuit constraints.

Known FPs:
  - `assert_eq!` used deliberately as a runtime sanity check inside an
    unconstrained fn (pre-condition), not as a constraint. Annotate with
    `// noir-assert-ok` to suppress.

Reference: Noir docs "Unconstrained Functions" vs "assert"; zkBugs
"Missing Constraint" class. Analog: Circom signal assignment without
constraint (`<--` vs `<==`).
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


DETECTOR_ID = "noir_assert_eq_missing_constraint"

_ASSERT_EQ_RE = re.compile(r"\bassert_eq\s*!\s*\(", re.M)
_CONSTRAIN_RE = re.compile(r"\bconstrain\s*\(", re.M)
_SUPPRESS_RE = re.compile(r"noir-assert-ok", re.I)


def find_assert_eq_in_unconstrained(source: str) -> list[dict[str, Any]]:
    """Return findings for assert_eq!/constrain inside unconstrained fn bodies."""
    if not _util.is_noir_file(source):
        return []
    stripped = _util.strip_comments(source)

    findings: list[dict[str, Any]] = []

    for fn_name, is_unconstrained, body_start, body_end in _util.iter_fns(stripped):
        if not is_unconstrained:
            continue
        body = stripped[body_start:body_end]

        for pattern_re, call_kind in [
            (_ASSERT_EQ_RE, "assert_eq!"),
            (_CONSTRAIN_RE, "constrain"),
        ]:
            for m in pattern_re.finditer(body):
                # Check suppress annotation
                line_start = body.rfind("\n", 0, m.start()) + 1
                line_end = body.find("\n", m.end())
                if line_end < 0:
                    line_end = len(body)
                if _SUPPRESS_RE.search(body[line_start:line_end]):
                    continue
                findings.append(
                    {
                        "call_kind": call_kind,
                        "fn_name": fn_name,
                        "offset": body_start + m.start(),
                    }
                )

    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_assert_eq_in_unconstrained(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 200].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "call_kind": f["call_kind"],
                "fn_name": f["fn_name"],
                "severity": "high",
                "message": (
                    f"`{f['call_kind']}` inside unconstrained fn `{f['fn_name']}` "
                    "does NOT generate a ZK circuit constraint. "
                    "In Noir, assert_eq! and constrain only produce constraints "
                    "when called from a constrained function context. "
                    "This check is a runtime-only assertion; a malicious prover "
                    "can bypass it. Move the constraint to a constrained fn or "
                    "add a separate constrained wrapper that calls this fn and asserts."
                ),
                "snippet": snippet,
            }
        )
    return hits
