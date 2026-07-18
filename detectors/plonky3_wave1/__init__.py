"""plonky3_wave1 — regex-based detectors for Plonky3 circuits.

Wave-7 Track K-zkBugs minor frameworks. Targets Plonky3 (Polygon's
next-generation STARK/AIR framework). Each detector is regex-only by
design (no tree-sitter-rust dependency) and scans Rust sources that
import `p3_air::*` or implement `Air<AB>`.

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names.
DETECTOR_MODULES = [
    "plonky3_air_constraint_unused_advice",
    "plonky3_lookup_table_argument_mismatch",
]
