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

DETECTOR_ID = "zkvm_tweakable_hash_tweak_unused"

_FN_WITH_TWEAK = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)")
_TWEAK_PARAM = re.compile(r"\b(\w*tweak\w*)\s*:")


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_tweak_file(source):
        return []
    src = _util.strip_comments(source)
    hits: list[dict[str, Any]] = []
    for name, start, end, body in _util.fn_blocks(src):
        # extract the param list for this fn
        sig = src[start:start + (body and src.find("{", start) - start or 0)]
        pm = _TWEAK_PARAM.search(sig)
        if not pm:
            continue
        param = pm.group(1)
        # body uses of the tweak param (exclude the signature itself)
        if re.search(r"\b" + re.escape(param) + r"\b", body):
            continue
        line, col = _util.line_col(source, start)
        hits.append({
            "detector_id": DETECTOR_ID,
            "line": line, "col": col, "severity": "high",
            "message": (
                f"fn `{name}` declares a tweak parameter `{param}` but never uses it in the body. "
                f"A dropped tweak collapses domain separation across chain/tree/message contexts, "
                f"enabling a tweakable-hash collision / forgery. Confirm the tweak is fed into the "
                f"permutation."),
            "snippet": _util.snippet_at(src, start),
        })
    return hits
