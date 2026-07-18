"""arkworks_pairing_input_validation_missing.py

Flags Arkworks pairing / miller_loop / final_exponentiation calls where
the curve-point inputs are NOT validated on the curve (no
`is_on_curve()`, `is_in_correct_subgroup_assuming_on_curve()`, or
`check()` call) within a 400-character window before the pairing call.

Background: the twisted-curve pairing attack (invalid-curve attack)
allows a malicious prover to supply a point NOT on the expected curve
as a pairing argument. Pairings with off-curve points can produce
incorrect results without raising an error, breaking the security of
Groth16 and other pairing-based SNARK verifiers. Arkworks does NOT
always check curve membership automatically; callers of `E::pairing`,
`E::miller_loop`, and `pairing_product` must validate their inputs.

Detection (regex-only):
  1. File must look like Arkworks (imports ark_ec / PairingEngine).
  2. Find all `E::pairing(...)` / `miller_loop(...)` /
     `pairing_product(...)` call sites.
  3. Check if `is_on_curve` / `is_in_correct_subgroup_assuming_on_curve`
     / `check` / `is_valid` appears within 400 chars before the call.
  4. If not — emit a finding.

Known limitations:
  - Validation may happen in a called function upstream (a common
    pattern: a `validate_inputs()` helper early in the fn). This
    detector cannot trace call-graph; reviewer must check callees.
  - `AffineCurve::check()` validates both on-curve and subgroup
    membership in one call and is the recommended API. If callers
    use this, the FP is suppressed.
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


DETECTOR_ID = "arkworks_pairing_input_validation_missing"

_PAIRING_RE = re.compile(
    r"\b(?:[A-Z][A-Za-z0-9_]*\s*::\s*)?(?:pairing|miller_loop|final_exponentiation"
    r"|pairing_product)\s*\(",
    re.M,
)

_CURVE_CHECK_RE = re.compile(
    r"\b(?:is_on_curve|is_in_correct_subgroup_assuming_on_curve|"
    r"check\s*\(\s*\)|is_valid|assert_on_curve|into_affine\s*\(\s*\)"
    r"\s*\.\s*check)\b",
    re.M,
)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_arkworks_file(source):
        return []
    stripped = _util.strip_comments(source)

    hits: list[dict[str, Any]] = []
    for m in _PAIRING_RE.finditer(stripped):
        offset = m.start()
        ctx_before = stripped[max(0, offset - 400) : offset]
        if _CURVE_CHECK_RE.search(ctx_before):
            continue
        line, col = _util.line_col(source, offset)
        snippet = source[offset : offset + 180].replace("\n", " ")
        hits.append({
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": line,
            "col": col,
            "severity": "high",
            "message": (
                f"Pairing / miller_loop call at line {line} without "
                "visible `is_on_curve()` / "
                "`is_in_correct_subgroup_assuming_on_curve()` / "
                "`check()` guard on inputs within the preceding 400 "
                "characters. Supplying off-curve points to an Arkworks "
                "pairing can produce incorrect results without error, "
                "enabling the invalid-curve attack against SNARK "
                "verifiers. Validate all pairing inputs before use."
            ),
            "snippet": snippet,
        })
    return hits
