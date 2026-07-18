"""halo2_lookup_table_missing_complement.py

Flags Halo2 `meta.lookup(...)` declarations whose lookup-input expression
exceeds the row-count of the underlying lookup table (i.e., the table is
range-checking N bits but the input expression has range > 2^N). This
maps to the zkBugs class "Missing range check for byte values in RLP
Circuit" / "Missing range checks for the LtChip" / "Missing range check
for address values in MPT Circuit" — 3 of the 6 "Missing Input
Constraints" bugs cluster around this exact shape.

Heuristic (regex-only):
  1. Parse `meta.lookup_table_column()` / `meta.lookup_table_chunk()`
     declarations to discover declared table sizes (when present in
     literal form e.g. `1 << 8`, `1 << 16`, `1 << K`).
  2. For each `meta.lookup(|meta| { ... })` body, extract the
     `lookup_input` expression(s) — the LHS of `(input, table)` tuples.
  3. Flag any lookup whose input is multi-byte (e.g. references `bytes`
     or `word` or `u64`) and is looked up against a single-byte table
     (size `1 << 8`). This is the canonical "missing range complement"
     shape: half the input bits are unconstrained.

Conservative: emits at Medium severity because exact bit-width inference
from Rust source is fundamentally lossy in a regex pass. Reviewer
should confirm with a Halo2-aware AST tool if found.

Known FPs:
  - Lookups that chain multiple lookups across complementary byte
    ranges (lookup `lo_byte` and `hi_byte` separately) achieve the same
    coverage. The detector cannot easily prove chain-completeness; it
    will flag the first lookup as suspicious. Reviewer override via
    `grep -B5 lookup_table_chunk` recommended.
  - Lookups inside test fixtures where the table is intentionally
    truncated for unit-test economy.

Reference: zkBugs Halo2 bugs "Missing range checks for the LtChip" and
"Missing range check for byte values in RLP Circuit".
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
    _spec = importlib.util.spec_from_file_location("halo2_wave1__util_ltmc", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "halo2_lookup_table_missing_complement"

_LOOKUP_OPEN_RE = re.compile(
    r"\bmeta\s*\.\s*lookup(?:_any)?\s*\(\s*(?:&?\"[^\"]*\"\s*,\s*)?\|\s*[A-Za-z_][A-Za-z0-9_]*\s*\|\s*\{",
    re.M | re.S,
)

# Indicators that the input expression operates on multi-byte (> 8 bit) values
_MULTI_BYTE_HINTS = re.compile(
    r"\b(?:word|u16|u32|u64|u128|bytes\s*\[|rlc|RLC|address|account_addr|nonce|balance)\b"
)

# Indicators that the table is single-byte-sized
_BYTE_TABLE_HINTS = re.compile(
    r"\b(?:1\s*<<\s*8|byte_table|u8_table|range_8|256\s*usize|256u64|2\s*\.\s*pow\(\s*8\s*\))"
)


def find_lookup_missing_complement(source: str) -> list[dict[str, Any]]:
    if not _util.is_halo2_file(source):
        return []
    stripped = _util.strip_comments(source)

    findings: list[dict[str, Any]] = []
    for m in _LOOKUP_OPEN_RE.finditer(stripped):
        open_brace = m.end() - 1
        end = _util.block_end(stripped, open_brace)
        body = stripped[open_brace + 1: end - 1]
        if _MULTI_BYTE_HINTS.search(body) and _BYTE_TABLE_HINTS.search(body):
            findings.append(
                {
                    "offset": m.start(),
                    "body_preview": body[:160].replace("\n", " "),
                }
            )
    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_lookup_missing_complement(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 220].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "severity": "medium",
                "message": (
                    "meta.lookup body references a multi-byte input "
                    "expression (word / u16+ / bytes / RLC) but looks it "
                    "up against a single-byte table (1 << 8 / 256). Half "
                    "the input bits are unconstrained unless the chip "
                    "chains complementary lookups. Verify all byte-chunks "
                    "are looked up. zkBugs 'Missing range checks' class."
                ),
                "snippet": snippet,
            }
        )
    return hits
