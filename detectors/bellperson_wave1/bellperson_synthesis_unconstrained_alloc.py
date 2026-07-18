"""bellperson_synthesis_unconstrained_alloc.py

Flags Bellperson `cs.alloc(...)` and `cs.alloc_input(...)` calls inside
a `synthesize` method whose resulting variable is NEVER passed to a
`cs.enforce(...)` constraint in the same function body. A variable
allocated to the R1CS without a constraint is a classic "Assigned but
Unconstrained" bug: the prover can set it to any value and the verifier
accepts the proof.

This detector is BROADER than the existing
`detectors/rust_wave1/zkbugs_bellperson_unconstrained_zero_default.py`
(which specifically targets the AllocatedNum::alloc default-zero trick).
This detector catches any alloc/alloc_input binding whose identifier
never appears in a cs.enforce block.

Detection (regex-only):
  1. File must look like Bellperson (imports bellperson:: / bellman:: or
     uses ConstraintSystem<>).
  2. Find every `let <name> = cs.alloc(...)` / `cs.alloc_input(...)` /
     `AllocatedNum::alloc(...)` / `AllocatedBit::alloc(...)` in scope.
  3. Collect all `cs.enforce(...)` call bodies.
  4. For each allocated name, check it appears in any enforce body.
     If not — emit a finding.

Known limitations / FP sources:
  - Variables used only via `.get_value()` for witness computation
    (not in enforce) ARE constrained if they appear in other R1CS gates
    constructed with `lc![]` macros. The lc![] macro usage is a known
    false-negative escape for this regex-based detector.
  - AllocatedNum / AllocatedBit higher-level methods (`.assert_nonzero()`,
    `.conditionally_select()`) call enforce internally; if the call is
    name-based, the variable will appear in those method calls and the
    detector will correctly suppress.

Reference: zkBugs class "Assigned but Unconstrained"; Bellperson 7-bug
corpus subset (zksecurity + Filecoin audits).
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
    _spec = _ilu.spec_from_file_location("bellperson_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "bellperson_synthesis_unconstrained_alloc"

# Find the synthesize fn body.
_SYNTH_RE = re.compile(
    r"\bfn\s+synthesize\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?:->[^{]*)?\{",
    re.M | re.S,
)


def _synth_body(source: str) -> str | None:
    m = _SYNTH_RE.search(source)
    if not m:
        return None
    open_brace = m.end() - 1
    end = _util.block_end(source, open_brace)
    return source[open_brace + 1 : end - 1]


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_bellperson_file(source):
        return []
    stripped = _util.strip_comments(source)
    body = _synth_body(stripped)
    if body is None:
        # Fall back to whole file if no synthesize found (could be
        # a helper function with inline alloc).
        body = stripped

    alloc_sites = _util.find_alloc_sites(body)
    if not alloc_sites:
        return []
    enforce_blob = _util.find_enforce_blobs(body)

    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, local_offset in alloc_sites:
        if name in seen:
            continue
        seen.add(name)
        pat = re.compile(rf"\b{re.escape(name)}\b")
        if pat.search(enforce_blob):
            continue
        # Find offset in original source for error reporting.
        global_m = re.search(
            rf"\blet\s+(?:mut\s+)?{re.escape(name)}\s*=\s*"
            rf"(?:cs\s*\.\s*(?:alloc|alloc_input)|AllocatedNum\s*::\s*alloc|"
            rf"AllocatedBit\s*::\s*alloc)\s*\(",
            stripped,
        )
        offset = global_m.start() if global_m else 0
        line, col = _util.line_col(source, offset)
        snippet = source[offset : offset + 220].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "severity": "high",
                "message": (
                    f"Variable `{name}` is allocated via `cs.alloc` / "
                    "`cs.alloc_input` / `AllocatedNum::alloc` but never "
                    "referenced from any `cs.enforce(...)` constraint in "
                    "the synthesize scope. Classic Bellperson "
                    "'Assigned but Unconstrained' shape. Verify the "
                    "variable is constrained via enforce or a higher-level "
                    "method that wraps enforce internally."
                ),
                "snippet": snippet,
            }
        )
    return hits
