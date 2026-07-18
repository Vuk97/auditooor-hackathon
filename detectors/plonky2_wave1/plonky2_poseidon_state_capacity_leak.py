"""plonky2_poseidon_state_capacity_leak.py

Flags Plonky2 Poseidon sponge usage where the rate elements are consumed
past the rate boundary, accessing capacity elements (positions >= RATE in
an WIDTH=12, RATE=8 sponge). This allows the prover to leak or manipulate
the internal sponge state, breaking the one-way property of the hash.

The Poseidon permutation used in Plonky2 has:
  - WIDTH = 12 (total sponge state elements)
  - RATE = 8  (elements in the "rate" portion, indices 0..7)
  - CAPACITY = 4 (elements in the "capacity" portion, indices 8..11)

A circuit that directly indexes into sponge state at positions >= RATE
(e.g. `state[8]`, `state[9]`, ...) is accessing the capacity portion,
which must remain opaque to the circuit. Reading or writing capacity
elements breaks the security argument.

Detection (regex-only):
  1. File must look like Plonky2.
  2. Find uses of poseidon_hash_one_field / PoseidonHash / poseidon_two_to_one.
  3. Detect array/slice indexing on names that look like sponge state
     (e.g. `state[8]`, `sponge.state[8]`, `inputs[8]`) with literal index >= 8.
  4. Also detect `RATE` constant redefinitions that set a value < the
     Plonky2 default (8), which would silently shrink the rate boundary.

Known FPs:
  - Non-Poseidon contexts where an array named `state` is indexed at positions
    >= 8 (rare; the Plonky2 heuristic filter reduces but doesn't eliminate).
  - Custom Poseidon instantiations with different RATE values that are
    legitimately smaller (annotate with `// plonky2-capacity-ok` to suppress).

Reference: Poseidon hash paper (Grassi et al.); Plonky2 book capacity security.
zkBugs analog: Cairo "hint decomposition without complementary constraint"
(capacity-lane confusion class).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from . import _util  # type: ignore
except ImportError:  # pragma: no cover
    import importlib.util
    import sys

    _UTIL_PATH = Path(__file__).resolve().parent / "_util.py"
    _spec = importlib.util.spec_from_file_location("plonky2_wave1__util", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "plonky2_poseidon_state_capacity_leak"

# Plonky2 RATE = 8, CAPACITY starts at index 8 (0-indexed)
PLONKY2_RATE = 8

_POSEIDON_USE_RE = re.compile(
    r"\b(?:poseidon_hash|PoseidonHash|poseidon_two_to_one|"
    r"PoseidonPermutation|POSEIDON_RATE|PoseidonSponge)\b",
    re.M,
)

# Match: <state_ish_name>[<literal_integer_>=_8>]
_CAPACITY_INDEX_RE = re.compile(
    r"\b(?P<arr>[A-Za-z_][A-Za-z0-9_.]*)\s*\[\s*(?P<idx>\d+)\s*\]",
    re.M,
)

# Matches state-like names: state, sponge_state, inputs (for Poseidon inputs array)
_STATE_NAME_RE = re.compile(r"\bstate\b|\bsponge\b|\bperm\b", re.I)

# Detect RATE constant being set to a value < 8
_RATE_OVERRIDE_RE = re.compile(
    r"\bconst\s+RATE\s*:\s*usize\s*=\s*(?P<val>\d+)\s*;",
    re.M,
)

_SUPPRESS_RE = re.compile(r"plonky2-capacity-ok", re.I)


def find_capacity_leaks(source: str) -> list[dict[str, Any]]:
    """Return findings for Poseidon state capacity lane accesses."""
    if not _util.is_plonky2_file(source):
        return []
    stripped = _util.strip_comments(source)

    # Only scan files that actually use Poseidon
    if not _POSEIDON_USE_RE.search(stripped):
        return []

    findings: list[dict[str, Any]] = []

    # Check 1: array indexing into capacity region (index >= RATE)
    for m in _CAPACITY_INDEX_RE.finditer(stripped):
        arr = m.group("arr")
        idx = int(m.group("idx"))
        if idx < PLONKY2_RATE:
            continue
        if not _STATE_NAME_RE.search(arr):
            continue
        # Check suppress annotation on the same line
        line_start = stripped.rfind("\n", 0, m.start()) + 1
        line_end = stripped.find("\n", m.end())
        if line_end < 0:
            line_end = len(stripped)
        line_text = source[line_start:line_end]
        if _SUPPRESS_RE.search(line_text):
            continue
        findings.append(
            {
                "kind": "capacity_index_access",
                "arr": arr,
                "index": idx,
                "offset": m.start(),
            }
        )

    # Check 2: RATE constant redefined below 8
    for m in _RATE_OVERRIDE_RE.finditer(stripped):
        val = int(m.group("val"))
        if val < PLONKY2_RATE:
            findings.append(
                {
                    "kind": "rate_constant_narrowed",
                    "declared_rate": val,
                    "expected_min": PLONKY2_RATE,
                    "offset": m.start(),
                }
            )

    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_capacity_leaks(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 200].replace("\n", " ")
        if f["kind"] == "capacity_index_access":
            msg = (
                f"Poseidon sponge state array `{f['arr']}` indexed at position "
                f"{f['index']} which is >= RATE ({PLONKY2_RATE}). This accesses the "
                "CAPACITY portion of the sponge state. Direct circuit access to "
                "capacity elements breaks the one-way security property of the "
                "Poseidon hash. Only indices 0..(RATE-1) should be read by the circuit."
            )
        else:
            msg = (
                f"Poseidon RATE constant redefined to {f['declared_rate']} "
                f"(Plonky2 default is {PLONKY2_RATE}). Narrowing RATE increases the "
                "CAPACITY boundary exposure: circuits using the original RATE indexing "
                "will silently access capacity elements. Verify this override is intentional."
            )
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "kind": f["kind"],
                "severity": "high",
                "message": msg,
                "snippet": snippet,
            }
        )
    return hits
