"""risc0_guest_panic_via_unwrap_in_zkvm.py

Flags `.unwrap()` / `.expect(...)` / `unwrap_or_else(|_| panic!(...))` /
`panic!(...)` calls in RISC Zero guest code (files that import
`risc0_zkvm::*` or use `env::read` / `env::commit`).

Background: in the RISC Zero zkVM, a `panic!` in guest code causes the
prover to abort with an unprovable execution. Unlike normal Rust programs
where a panic produces a readable error, in zkVM context the host receives
a proof failure with minimal diagnostics. A malicious input can trigger a
panic in a guest that uses `.unwrap()` on user-supplied data, causing a
selective liveness failure (the prover cannot generate a valid proof for
that input) or allowing the prover to choose whether to proceed (if the
panic is on a value the prover controls).

This is distinct from the standard Clippy `.unwrap()` warning because the
zkVM context amplifies the impact: the soundness guarantee relies on every
valid input producing a proof; a panic breaks this invariant.

Detection (regex-only):
  1. File must look like RISC Zero guest code.
  2. Find every `.unwrap()` / `.expect(` / `panic!(` / `unwrap_or_else`
     call in the file body.
  3. Emit a finding for each one with severity medium (soundness: the
     prover can selectively refuse to prove inputs, but cannot forge a
     proof for an incorrect output).

Known limitations / FP sources:
  - `.unwrap()` after a documented infallible operation (e.g. parsing a
    compile-time constant) is a benign FP; reviewer should grep the
    surrounding context.
  - `panic!("unreachable")` in an unreachable branch is accepted Rust
    style; also a benign FP. Use `#[allow(clippy::unwrap_used)]` to
    document intentional usage.

Reference: risc0 3-bug corpus subset (RISC Zero security advisories +
community audit findings on guest liveness).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util
except ImportError:
    import importlib.util as _ilu
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = _ilu.spec_from_file_location("risc0_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "risc0_guest_panic_via_unwrap_in_zkvm"

_PANIC_PAT = re.compile(
    r"(?P<op>"
    r"\.unwrap\s*\(\s*\)"
    r"|\.expect\s*\("
    r"|unwrap_or_else\s*\(\s*\|[^|]*\|\s*panic\s*!"
    r"|panic\s*!\s*\("
    r")",
    re.M,
)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_risc0_guest_file(source):
        return []
    stripped = _util.strip_comments(source)

    hits: list[dict[str, Any]] = []
    for m in _PANIC_PAT.finditer(stripped):
        offset = m.start()
        op_text = m.group("op").strip()
        line, col = _util.line_col(source, offset)
        snippet = source[offset : offset + 180].replace("\n", " ")
        hits.append({
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": line,
            "col": col,
            "severity": "medium",
            "message": (
                f"`{op_text}` in RISC Zero guest code causes the prover "
                "to abort with no proof if triggered. In a zkVM context, "
                "a panic on user-supplied data enables selective liveness "
                "failure: a malicious prover can refuse to prove any input "
                "that reaches this branch. Replace with explicit error "
                "handling (`match` / `?`) and commit a descriptive error "
                "code to the journal instead of panicking."
            ),
            "snippet": snippet,
        })
    return hits
