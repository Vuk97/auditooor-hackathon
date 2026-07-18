"""cairo_hint_decomposition_unconstrained.py

Flags Cairo hint blocks (%{ ... %}) that perform numeric decomposition
(bit extraction, NAF decomposition, range splitting) without a corresponding
assertion in the surrounding Cairo code that constrains the decomposed result.

In Cairo, hints are executed by the prover but NOT verified by the STARK proof.
A hint that decomposes a value into bits or limbs provides these as "advice" —
the circuit must then ASSERT that the pieces reconstruct the original value.
If the assert is missing, a malicious prover can supply an incorrect decomposition.

This mirrors the gnark "naf-decomposition-missing-no-adjacent-nonzero-constraint"
class from the zkBugs corpus.

Detection (regex-only):
  1. File must look like Cairo.
  2. Find every %{ ... %} hint block.
  3. Within each hint block, look for decomposition patterns:
     - `ids.X = ids.Y & 1` (bit extraction)
     - `ids.X = ids.Y >> N` (right shift = bit slicing)
     - `ids.X = divmod(ids.Y, N)` (range splitting)
     - `ids.X = ids.Y // N` or `ids.X = ids.Y % N`
  4. For each decomposition found, scan the Cairo code AFTER the hint block
     (up to the next func boundary) for an `assert` that references the
     decomposed variable name.
  5. If no assert found, flag it.

Known FPs:
  - Decompositions where the constraint is implicit (e.g. the value is
    immediately range-checked by a subsequent builtin call like
    `range_check_ptr`). Annotate with `# cairo-decomp-ok` to suppress.

Reference: gnark zkBugs "naf-decomposition-missing-no-adjacent-nonzero-constraint";
Cairo hint security; StarkWare "Verifying Cairo programs" docs.
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
    _spec = importlib.util.spec_from_file_location("cairo_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "cairo_hint_decomposition_unconstrained"

# Patterns that indicate decomposition inside a hint block
_DECOMP_PATTERNS = [
    # bit extraction: ids.X = ids.Y & 1  or  ids.X = ids.Y & mask
    re.compile(r"\bids\.(?P<out>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*ids\.\w+\s*&\s*\d+", re.M),
    # right shift: ids.X = ids.Y >> N
    re.compile(r"\bids\.(?P<out>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*ids\.\w+\s*>>\s*\d+", re.M),
    # floor division: ids.X = ids.Y // N  or  ids.X = ids.Y // ids.Z
    re.compile(r"\bids\.(?P<out>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*ids\.\w+\s*//\s*\S+", re.M),
    # modulo: ids.X = ids.Y % N
    re.compile(r"\bids\.(?P<out>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*ids\.\w+\s*%\s*\d+", re.M),
    # divmod: ids.X, ids.Y = divmod(...)
    re.compile(
        r"\bids\.(?P<out>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*\S+\s*=\s*divmod\s*\(",
        re.M,
    ),
]

# Cairo assert patterns: `assert X = Y` (0.x) or `assert!(X == Y)` (1.x)
_ASSERT_RE = re.compile(r"\bassert\s*[!(]?\s*\b", re.M)

_SUPPRESS_RE = re.compile(r"cairo-decomp-ok", re.I)


def find_unconstrained_decompositions(source: str) -> list[dict[str, Any]]:
    """Return findings for hint decompositions without follow-up assertions."""
    if not _util.is_cairo_file(source):
        return []
    stripped = _util.strip_comments(source)

    findings: list[dict[str, Any]] = []

    for hint_start, hint_end, hint_body in _util.find_hint_blocks(stripped):
        # Check suppress
        if _SUPPRESS_RE.search(hint_body):
            continue

        for pat in _DECOMP_PATTERNS:
            for dm in pat.finditer(hint_body):
                out_var = dm.group("out")
                # Look for an assert referencing `out_var` after the hint block
                code_after = stripped[hint_end:]
                # Search up to the next %{ or end of current func (~500 chars heuristic)
                search_window = code_after[:800]
                # Does any assert mention out_var?
                for am in _ASSERT_RE.finditer(search_window):
                    # Grab up to 120 chars after the assert keyword
                    snip = search_window[am.start(): am.start() + 120]
                    if re.search(rf"\b{re.escape(out_var)}\b", snip):
                        break
                else:
                    findings.append(
                        {
                            "out_var": out_var,
                            "hint_pattern": dm.group().strip(),
                            "offset": hint_start,
                        }
                    )

    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_unconstrained_decompositions(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 200].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "out_var": f["out_var"],
                "hint_pattern": f["hint_pattern"],
                "severity": "high",
                "message": (
                    f"Cairo hint block decomposes value into `{f['out_var']}` "
                    f"({f['hint_pattern']!r}) but no `assert` on `{f['out_var']}` "
                    "found in the following code. "
                    "Hints are prover-only; a malicious prover can supply an "
                    "incorrect decomposition without the STARK proof detecting it. "
                    "Add `assert ids.X_low + ids.X_high * 2^N = ids.original_value;` "
                    "or equivalent after the hint block."
                ),
                "snippet": snippet,
            }
        )
    return hits
