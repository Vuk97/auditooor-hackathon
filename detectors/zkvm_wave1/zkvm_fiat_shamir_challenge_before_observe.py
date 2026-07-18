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

DETECTOR_ID = "zkvm_fiat_shamir_challenge_before_observe"

_SAMPLE = re.compile(r"\.\s*(sample|sample_vec|sample_many|sample_in_range|squeeze|get_challenge|challenge|draw_challenge)\s*\(")
_OBSERVE = re.compile(r"\.\s*(observe|observe_many|observe_scalars|absorb|append|append_message|append_scalars)\s*\(")


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_fs_file(source):
        return []
    src = _util.strip_comments(source)
    hits: list[dict[str, Any]] = []
    for name, start, end, body in _util.fn_blocks(src):
        sm = _SAMPLE.search(body)
        if not sm:
            continue
        # find the offset of the first sample call within the whole source
        first_sample = start + body.find(sm.group(0))
        # observe calls in this fn BEFORE the first sample
        pre = body[:body.find(sm.group(0))]
        if _OBSERVE.search(pre):
            continue  # at least one absorb precedes the challenge: ok shape
        if _OBSERVE.search(body):
            continue  # observes somewhere in fn (interleaved); lower-signal, skip
        line, col = _util.line_col(source, first_sample if first_sample < len(source) else start)
        hits.append({
            "detector_id": DETECTOR_ID,
            "line": line, "col": col, "severity": "high",
            "message": (
                f"fn `{name}` samples a Fiat-Shamir challenge ({sm.group(1)}) but never "
                f"observes/absorbs any prover message in this function. If the challenge is "
                f"not bound to the data it should commit to, the transcript may be forgeable "
                f"(soundness). Verify the absorb happens on the shared transcript before this draw."),
            "snippet": _util.snippet_at(src, first_sample),
        })
    return hits
