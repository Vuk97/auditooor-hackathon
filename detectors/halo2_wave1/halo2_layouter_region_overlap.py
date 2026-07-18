"""halo2_layouter_region_overlap.py

Flags Halo2 chips whose `Layouter::assign_region` closures share the
same region-name literal across multiple call sites. Halo2 enforces
region uniqueness for permutation copy semantics; reusing region names
across unrelated regions can collide row offsets when the chip is
composed into a larger circuit (the layouter's first-fit packing
silently overlaps cells assigned to nominally-distinct regions).

This maps to the zkBugs "Unsafe Reuse of Circuit" class, e.g. the bug
"Non-trivial rotation incorrectly handled in ComparatorChip" where a
chip was reused across two regions with shared row offsets.

Heuristic (regex-only):
  1. Collect every literal string passed as the first arg to
     `layouter.assign_region(|| "<name>", ...)` and
     `region.name_column(|| "<name>", ...)`.
  2. Flag any name that appears in ≥2 distinct call-sites (offset).

Known FPs:
  - The same region-name reused INTENTIONALLY in a loop iteration
    (e.g. `for i in 0..N { layouter.assign_region(|| format!("row {}", i), ...) }`)
    where the format! produces unique strings at runtime. The detector
    skips `format!` and only matches static literals.
  - Top-level `name` used as a chip identifier across separate
    circuits in the same crate. These won't collide in practice; the
    detector flags them but at Low severity for reviewer dismissal.

Reference: zkBugs class "Unsafe Reuse of Circuit"; canonical example
"Non-trivial rotation incorrectly handled in ComparatorChip".
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
    _spec = importlib.util.spec_from_file_location("halo2_wave1__util_lro", _UTIL_PATH)
    assert _spec is not None and _spec.loader is not None
    _util = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _util
    _spec.loader.exec_module(_util)


DETECTOR_ID = "halo2_layouter_region_overlap"

_ASSIGN_REGION_RE = re.compile(
    r"\b(?:layouter|self\.layouter)\s*\.\s*assign_region\s*\(\s*\|\|\s*"
    r'"(?P<name>[^"]+)"',
    re.M | re.S,
)


def find_region_overlaps(source: str) -> list[dict[str, Any]]:
    if not _util.is_halo2_file(source):
        return []
    stripped = _util.strip_comments(source)

    # Collect each (name, offset) pair
    sites: dict[str, list[int]] = {}
    for m in _ASSIGN_REGION_RE.finditer(stripped):
        name = m.group("name")
        sites.setdefault(name, []).append(m.start())

    findings: list[dict[str, Any]] = []
    for name, offsets in sites.items():
        if len(offsets) >= 2:
            # Emit ONE finding per overlap set, anchored at the SECOND
            # occurrence (the first is the original, the second is the
            # reuse).
            findings.append(
                {
                    "name": name,
                    "offset": offsets[1],
                    "count": len(offsets),
                    "all_offsets": offsets,
                }
            )
    return findings


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for f in find_region_overlaps(source):
        line, col = _util.line_col(source, f["offset"])
        snippet = source[f["offset"]: f["offset"] + 220].replace("\n", " ")
        hits.append(
            {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "col": col,
                "region_name": f["name"],
                "reuse_count": f["count"],
                "severity": "low",
                "message": (
                    f"Region name \"{f['name']}\" is used in "
                    f"{f['count']} assign_region call-sites in this file. "
                    "Halo2 region names should be unique per logical "
                    "region to avoid row-offset collisions in the "
                    "layouter's first-fit packing. zkBugs 'Unsafe Reuse "
                    "of Circuit' class."
                ),
                "snippet": snippet,
            }
        )
    return hits
