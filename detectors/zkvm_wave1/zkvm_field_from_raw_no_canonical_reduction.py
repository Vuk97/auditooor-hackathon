from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util
except ImportError:
    import importlib.util as _ilu
    import sys
    _UTIL = Path(__file__).resolve().parent / "_util.py"
    _spec = _ilu.spec_from_file_location("zkvm_wave1__util", _UTIL)
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)

DETECTOR_ID = "zkvm_field_from_raw_no_canonical_reduction"

_RAW = re.compile(r"\b(from_canonical_unchecked|new_unchecked|from_raw|from_u32_unchecked|assume_canonical|from_montgomery)\s*\(")
_REDUCE = re.compile(r"(reduce|to_canonical|montgomery_reduce|MODULUS|\bORDER(?:_U[0-9]+)?\b|\bPRIME\b|%\s|assert)", re.I)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_field_file(source):
        return []
    src = _util.strip_comments(source)
    hits: list[dict[str, Any]] = []
    for m in _RAW.finditer(src):
        window = src[max(0, m.start() - 200): m.start() + 320]
        if _REDUCE.search(window):
            continue
        line, col = _util.line_col(source, m.start())
        hits.append({
            "detector_id": DETECTOR_ID,
            "line": line, "col": col, "severity": "medium",
            "message": (
                f"`{m.group(1)}` constructs a field element from a raw/unchecked value with no "
                f"visible canonical reduction (% MODULUS / reduce / `< MODULUS` assert) within "
                f"320 chars. A non-canonical (>= p) element can be verifier-observable and break "
                f"field-arithmetic soundness. Confirm the input is already canonical."),
            "snippet": _util.snippet_at(src, m.start()),
        })
    return hits
