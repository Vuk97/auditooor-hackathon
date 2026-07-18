"""noir_wave1 — regex-based detectors for Noir circuits.

Wave-6 Track K-zkBugs, step K-Z.10b. Targets Noir (Aztec's circuit DSL).
Each detector is regex-only by design and scans `.nr` files that use the
Noir type system (`Field`, `unconstrained fn`, `use dep::`, etc.).

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names.
DETECTOR_MODULES = [
    "noir_unconstrained_fn_unsafe_use",
    "noir_array_index_oob",
    "noir_assert_eq_missing_constraint",
]
