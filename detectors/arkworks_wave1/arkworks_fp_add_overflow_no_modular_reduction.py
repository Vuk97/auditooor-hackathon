"""arkworks_fp_add_overflow_no_modular_reduction.py

Flags Arkworks field arithmetic using raw `+` / `.add` on `Fp` / `Fr` /
`Fq` / `BigInteger` types in contexts where no explicit modular reduction
(`% modulus`, `.reduce()`, `into_repr().reduce()`, or `.normalize()`) is
visible in the surrounding code block.

Background: Arkworks `Fp256` / `Fp384` arithmetic operators implement
Montgomery-form reduction internally in most APIs, but low-level
`BigInteger` / `repr_` arithmetic does NOT automatically reduce. A common
bug in manual field arithmetic is adding two `BigInteger` values and
forgetting that the result may exceed the prime modulus, producing an
element that is not in the canonical field representation.

Detection (regex-only):
  1. File must look like Arkworks (imports ark_ff/ark_ec).
  2. Find raw `+` between identifiers in a context that mentions
     Fp256/Fp384/BigInteger/FpVar/Fr/Fq types.
  3. If no `reduce` / `% ` / `.into_repr()` call appears within
     a 400-char window AFTER the addition, emit a finding.

Known limitations:
  - High FP rate: `+` on high-level Fp types (FpVar, Fp256 direct)
    IS automatically reduced by the operator impl; these are flagged
    but should be reviewed. Only BigInteger raw arithmetic is a real
    missing-reduction bug.
  - Context window is heuristic; multi-statement chains may confuse
    the proximity check.
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
    _spec = _ilu.spec_from_file_location("arkworks_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "arkworks_fp_add_overflow_no_modular_reduction"

_REDUCE_RE = re.compile(
    r"\b(?:reduce|normalize|into_canonical|sub_noborrow|sub_with_borrow"
    r"|% |mod\s+P|MODULUS|if\s+&?\w+\s*>=\s*\w*[Mm]odulus)\b",
    re.M,
)

_BIGINT_ADD_RE = re.compile(
    r"(?P<lhs>[A-Za-z_][A-Za-z0-9_\.]*)\s*\.\s*add(?:_nocarry|_with_carry)?\s*\("
    r"|(?P<lhs2>[A-Za-z_][A-Za-z0-9_\.]*)\s*\+\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_\.]*)\s*;",
    re.M,
)

_BIGINT_CTX_RE = re.compile(
    r"\b(?:BigInteger|BigInteger256|BigInteger384|repr_)\b",
)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_arkworks_file(source):
        return []
    stripped = _util.strip_comments(source)

    hits: list[dict[str, Any]] = []
    for m in _BIGINT_ADD_RE.finditer(stripped):
        offset = m.start()
        # Check that BigInteger types are mentioned nearby.
        ctx_before = stripped[max(0, offset - 300) : offset]
        if not _BIGINT_CTX_RE.search(ctx_before):
            continue
        # Check if a reduce / normalize call follows within 400 chars.
        after = stripped[offset : offset + 400]
        if _REDUCE_RE.search(after):
            continue
        line, col = _util.line_col(source, offset)
        snippet = source[offset : offset + 180].replace("\n", " ")
        hits.append({
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": line,
            "col": col,
            "severity": "medium",
            "message": (
                "Field arithmetic operation (`+` / `.add`) on a "
                "BigInteger / Fp type without visible modular reduction "
                "in the surrounding code. If using low-level BigInteger "
                "arithmetic, the result may exceed the prime modulus, "
                "producing a non-canonical field element. Ensure "
                "`.reduce()` or equivalent is called after addition."
            ),
            "snippet": snippet,
        })
    return hits
