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

DETECTOR_ID = "zkvm_sumcheck_round_missing_sum_binding"

_REJECT = re.compile(r"(return\s+false|return\s+Err|bail!|ensure!|assert|debug_assert|!=|==|ProofError|VerifyError)")
_VERIFY_FN = re.compile(r"verify|check|validate", re.I)


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_sumcheck_file(source):
        return []
    src = _util.strip_comments(source)
    hits: list[dict[str, Any]] = []
    for name, start, end, body in _util.fn_blocks(src):
        if not _VERIFY_FN.search(name):
            continue
        # a sumcheck verify fn that draws a challenge / consumes a round poly
        if "claim" not in body and "round" not in body and "eval" not in body.lower():
            continue
        if _REJECT.search(body):
            continue  # has some rejection / binding comparison: ok
        line, col = _util.line_col(source, start)
        hits.append({
            "detector_id": DETECTOR_ID,
            "line": line, "col": col, "severity": "high",
            "message": (
                f"sumcheck verifier fn `{name}` consumes round data but contains no rejection "
                f"or binding comparison (no `==`/assert/return false/Err). A sumcheck round must "
                f"enforce g(0)+g(1) == previous_claim; a verifier that never rejects is unsound. "
                f"Confirm the round-sum binding check is present (possibly in a callee)."),
            "snippet": _util.snippet_at(src, start),
        })
    return hits
