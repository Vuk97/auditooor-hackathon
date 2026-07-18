"""gnark_emulated_field_overflow.py

Flags gnark emulated field Element constructors (`NewHint`, `NewElement`,
direct `Element[T]{Limbs: ...}` struct literal, or circuit input fields of
type `emulated.Element[T]`) that appear WITHOUT a preceding
`enforceWidthConditional` / `EnforceWidth` / `field.EnforceWidthConditional`
call in the same function body.

Background (corpus reference gnark-zksecurity-0b):
  `Element[T]` foreign-field variables can be created via `NewHint` or as
  private circuit inputs without their limbs being constrained to the
  correct bitlength. Functions consuming these elements (`checkZero`,
  `Reduce`, `Select`, `mulMod`, `ToBits`, etc.) are individually
  responsible for calling `enforceWidthConditional`. Any caller function
  or stdlib addition that forgets this call introduces a soundness gap;
  gnark's compiler does not enforce constructor-time validation.

Detection (regex-only, Go files):
  1. File must look like gnark (imports Consensys/gnark packages).
  2. Find all `NewHint(...)` / `NewElement(...)` /
     `Element[...]{Limbs:` / `api.FromBinary(...)` call sites.
  3. Check if `enforceWidthConditional` / `EnforceWidth` appears within
     a 600-char window AFTER each site, OR anywhere in the same function
     body.
  4. If not — emit a finding.

Known limitations:
  - Width enforcement that happens in a called sub-function (common in
    gnark stdlib) is a known FP source. Reviewer should trace callee.
  - The 'won't fix' design-tradeoff documented by Linea team means many
    legit usages intentionally defer enforcement. This detector flags for
    review, not automatic rejection.

Reference: corpus gnark-zksecurity-0b.
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


DETECTOR_ID = "gnark_emulated_field_overflow"

_ELEMENT_CTOR_RE = re.compile(
    r"\b(?:field\s*\.\s*NewHint|NewHint\s*\(|field\s*\.\s*NewElement"
    r"|emulated\s*\.\s*ValueOf|Element\s*\[(?:[^\]]+)\]\s*\{\s*Limbs\s*:)",
    re.M,
)

_ENFORCE_WIDTH_RE = re.compile(
    r"\b(?:enforceWidthConditional|EnforceWidth|EnforceWidthConditional"
    r"|AssertLimbsAdmissible)\s*\(",
    re.M,
)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_gnark_file(source):
        return []
    stripped = _util.strip_comments(source)

    hits: list[dict[str, Any]] = []
    for m in _ELEMENT_CTOR_RE.finditer(stripped):
        offset = m.start()
        # Check within 600 chars after the constructor call.
        after = stripped[offset : offset + 600]
        if _ENFORCE_WIDTH_RE.search(after):
            continue
        # Also check 600 chars before (maybe enforced before creation).
        before = stripped[max(0, offset - 600) : offset]
        if _ENFORCE_WIDTH_RE.search(before):
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
                "gnark emulated field element constructed via "
                f"`{m.group(0).strip()}` without a visible "
                "`enforceWidthConditional` / `EnforceWidth` call "
                "in the surrounding 600-character context. "
                "Limbs of emulated elements are not automatically "
                "constrained to the correct bitlength by gnark's "
                "compiler; callers must call `enforceWidthConditional` "
                "before operations like `checkZero`, `Reduce`, `mulMod`. "
                "Omitting this check is a soundness gap "
                "(corpus ref: gnark-zksecurity-0b)."
            ),
            "snippet": snippet,
        })
    return hits
