"""plonky3_lookup_table_argument_mismatch.py

Flags Plonky3 lookup argument call sites where the number of values
sent by `builder.send(...)` does not visibly match the width declared
in a `builder.receive(...)` or the table definition on the same lookup
channel. A width mismatch allows a malicious prover to supply a lookup
witness that is never checked against the actual table, breaking soundness.

Detection (regex-only):
  1. The file must look like Plonky3.
  2. Locate pairs of `builder.send(<channel>, <values>)` and
     `builder.receive(<channel>, <values>)` in the same file.
  3. Extract the arity (number of comma-separated arguments in the
     values array/tuple literal) for each call site.
  4. If any send-arity != receive-arity on the same channel name, emit
     a finding.
  5. If a send is present with no matching receive (or vice versa),
     also flag as a potential width-orphan.

Known limitations:
  - Arity extraction is heuristic (comma count inside the values arg).
    Nested tuples with internal commas may over-count.
  - The channel identifier may be a constant or a computed value;
    name-based matching only catches literal identifier matches.

Reference: zkBugs class "Lookup Table Argument Mismatch"; applicable
to Plonky3's LogUp / Lasso lookup argument as seen in the Plonky3
corpus (lookup multiplicity and table-width consistency bugs).
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from . import _util
except ImportError:
    import importlib.util as _ilu
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = _ilu.spec_from_file_location("plonky3_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = _ilu.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "plonky3_lookup_table_argument_mismatch"

# Matches builder.send(channel, values, multiplicity) or
# builder.receive(channel, values, multiplicity) where values is a
# slice/vec literal: &[a, b, c] or vec![a, b, c]
_LOOKUP_CALL_RE = re.compile(
    r"\bbuilder\s*\.\s*(?P<dir>send|receive)\s*\("
    r"\s*(?P<channel>[A-Za-z_][A-Za-z0-9_:]*(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\s*,\s*"
    r"(?:&\s*\[|vec!\s*\[)(?P<values>[^\]]*)\]",
    re.M | re.S,
)


def _arity(values_str: str) -> int:
    """Estimate the number of entries in a comma-separated list.
    Strips trailing whitespace; returns 1 for non-empty, 0 for empty."""
    v = values_str.strip()
    if not v:
        return 0
    # Count top-level commas (don't recurse into nested parens)
    depth = 0
    count = 1
    for c in v:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            count += 1
    return count


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _util.is_plonky3_file(source):
        return []
    stripped = _util.strip_comments(source)

    # channel -> list of (dir, arity, offset)
    by_channel: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
    for m in _LOOKUP_CALL_RE.finditer(stripped):
        ch = m.group("channel").strip()
        direction = m.group("dir")
        arity = _arity(m.group("values"))
        by_channel[ch].append((direction, arity, m.start()))

    hits: list[dict[str, Any]] = []
    for channel, entries in by_channel.items():
        sends = [(a, o) for d, a, o in entries if d == "send"]
        receives = [(a, o) for d, a, o in entries if d == "receive"]

        if sends and not receives:
            offset = sends[0][1]
            line, col = _util.line_col(source, offset)
            hits.append({
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "severity": "medium",
                "message": (
                    f"Lookup channel `{channel}`: `builder.send` found "
                    "but no matching `builder.receive` in this file. "
                    "Unpaired lookup send may indicate a missing table "
                    "constraint or a cross-file mismatch to verify."
                ),
                "snippet": source[offset : offset + 180].replace("\n", " "),
            })
            continue

        if receives and not sends:
            offset = receives[0][1]
            line, col = _util.line_col(source, offset)
            hits.append({
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "severity": "medium",
                "message": (
                    f"Lookup channel `{channel}`: `builder.receive` found "
                    "but no matching `builder.send` in this file. "
                    "Unpaired lookup receive may indicate a missing witness "
                    "constraint or a cross-file mismatch to verify."
                ),
                "snippet": source[offset : offset + 180].replace("\n", " "),
            })
            continue

        # Both present — check arity mismatch
        for s_arity, s_off in sends:
            for r_arity, r_off in receives:
                if s_arity != r_arity:
                    line, col = _util.line_col(source, s_off)
                    hits.append({
                        "detector_id": DETECTOR_ID,
                        "file": filepath,
                        "line": line,
                        "col": col,
                        "severity": "high",
                        "message": (
                            f"Lookup channel `{channel}`: send arity={s_arity} "
                            f"vs receive arity={r_arity}. Width mismatch allows "
                            "a malicious prover to supply a lookup witness that "
                            "is never checked against the actual table, breaking "
                            "soundness."
                        ),
                        "snippet": source[s_off : s_off + 180].replace("\n", " "),
                    })
    return hits
