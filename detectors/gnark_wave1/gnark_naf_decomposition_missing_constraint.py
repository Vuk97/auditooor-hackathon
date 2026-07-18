"""gnark_naf_decomposition_missing_constraint.py

Flags gnark `ToNAF(...)` / `bits.ToNAF(...)` call sites where the
resulting NAF digits are consumed (e.g. in a scalar multiplication loop)
WITHOUT a visible adjacent-nonzero constraint in the surrounding code.

Background (corpus references gnark-zksecurity-09 and gnark-zksecurity-0a):
  `ToNAF` returns the non-adjacent form decomposition of a value supplied
  via prover hint. The function constrains the bits to sum to `v` and each
  bit to be in {-1, 0, 1}, but does NOT enforce the defining NAF property:
  "non-zero values cannot be adjacent". A malicious prover can supply a
  representation with adjacent non-zero digits, which is no longer unique
  and may poison downstream scalar-multiplication or exponentiation routines
  that assume canonical NAF (gnark-zksecurity-09).

  Additionally, `ToNAF`-based algorithms that do not encode the original
  input length are vulnerable to length-extension if called with
  variable-length inputs (gnark-zksecurity-0a extension).

The canonical fix is to add an explicit constraint after `ToNAF`:
  for i in range(len(naf)-1):
      api.AssertIsEqual(api.Mul(naf[i], naf[i+1]), 0)

Detection (regex-only, Go files):
  1. File must look like gnark.
  2. Find all `ToNAF(` / `bits.ToNAF(` call sites.
  3. Within 600 chars AFTER the call, look for the adjacent-pair constraint
     pattern: `Mul(naf[i], naf[i+1])` or `api.Mul` followed by
     `AssertIsEqual` involving NAF slice indexing.
  4. If not found — emit a finding.

Known limitations:
  - The constraint may be in a helper function called after ToNAF; the
    detector cannot trace call-graph.
  - Some uses of ToNAF where the caller guarantees canonical input (e.g.
    reduced scalar from a previous step) may be safe; flag for review.

Reference: corpus gnark-zksecurity-09 (primary) + 0a (extension).
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
    _spec = _ilu.spec_from_file_location("gnark_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "gnark_naf_decomposition_missing_constraint"

_TONAF_RE = re.compile(
    r"\b(?:bits\s*\.\s*)?ToNAF\s*\(",
    re.M,
)

# The adjacent-pair constraint looks like:
#   api.AssertIsEqual(api.Mul(naf[i], naf[i+1]), 0)
# or a loop with api.Mul + api.AssertIsEqual where naf slice indices appear.
_ADJACENT_CONSTRAINT_RE = re.compile(
    r"(?:"
    r"Mul\s*\(\s*\w+\s*\[\s*\w+\s*\]\s*,\s*\w+\s*\[\s*\w+\s*[+]\s*1\s*\]"
    r"|AssertIsEqual\s*\([^)]*Mul[^)]*\)"
    r"|no.?adjacent"
    r"|naf.*adjacent"
    r")",
    re.M | re.I,
)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_gnark_file(source):
        return []
    stripped = _util.strip_comments(source)

    hits: list[dict[str, Any]] = []
    for m in _TONAF_RE.finditer(stripped):
        offset = m.start()
        after = stripped[offset : offset + 600]
        if _ADJACENT_CONSTRAINT_RE.search(after):
            continue
        line, col = _util.line_col(source, offset)
        snippet = source[offset : offset + 200].replace("\n", " ")
        hits.append({
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": line,
            "col": col,
            "severity": "high",
            "message": (
                "`ToNAF(...)` call without visible adjacent-nonzero "
                "constraint in the following 600 characters. "
                "`ToNAF` constrains bits to sum to `v` and be in "
                "{-1, 0, 1} but does NOT enforce the NAF property "
                "(no adjacent non-zeros). A malicious prover can "
                "supply a non-canonical NAF with adjacent non-zeros, "
                "poisoning downstream scalar multiplication. "
                "Add: `for i := range naf[:len(naf)-1] { "
                "api.AssertIsEqual(api.Mul(naf[i], naf[i+1]), 0) }` "
                "(corpus refs: gnark-zksecurity-09, gnark-zksecurity-0a)."
            ),
            "snippet": snippet,
        })
    return hits
