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

DETECTOR_ID = "zkvm_unsafe_transmute_in_field_packing"

_UNSAFE_CAST = re.compile(r"(transmute(?:_copy)?\s*::|from_raw_parts(?:_mut)?\s*\(|\bas\s+\*(?:const|mut)\b|\.cast::<|core::mem::transmute)")
_PACKING_PATH = re.compile(r"(pack|simd|avx|neon|sse|monty|field|extension)", re.I)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    fp_low = (filepath or "").lower()
    if not (_PACKING_PATH.search(fp_low) or _util.is_field_file(source)):
        return []
    src = source  # keep offsets aligned with original for unsafe detection
    hits: list[dict[str, Any]] = []
    for m in _UNSAFE_CAST.finditer(src):
        # require an `unsafe` within 200 chars before the cast (Rust requires it)
        pre = src[max(0, m.start() - 200): m.start()]
        if "unsafe" not in pre and "unsafe" not in src[m.start():m.start() + 40]:
            continue
        line, col = _util.line_col(source, m.start())
        hits.append({
            "detector_id": DETECTOR_ID,
            "line": line, "col": col, "severity": "medium",
            "message": (
                f"unsafe pointer-cast / transmute in field/packing/SIMD code "
                f"(`{m.group(0).strip()}`). If the SIMD-packed representation diverges from the "
                f"scalar field representation, the result is verifier-observable corruption; if "
                f"layout/length assumptions are wrong it is memory-unsafe. Confirm layout + bounds."),
            "snippet": _util.snippet_at(source, m.start()),
        })
    return hits
