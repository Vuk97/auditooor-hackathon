"""halo2_wave1 — regex-based detectors for Halo2 circuits.

Wave-5 Track K-zkBugs, steps 6-8. Targets the 35-bug Halo2 subset of the
zkBugs corpus (zksecurity dataset + 0xPARC dataset). Each detector is
regex-only by design (no tree-sitter-rust dependency) and scans Rust
sources that import `halo2_proofs::*` or `halo2::*`.

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}` (plus optional Halo2-specific keys).
"""
from __future__ import annotations

# Public detector module names (mirrors rust_wave1 convention).
DETECTOR_MODULES = [
    "halo2_chip_unconstrained_advice",
    "halo2_gate_polynomial_degree_mismatch",
    "halo2_lookup_table_missing_complement",
    "halo2_layouter_region_overlap",
    "halo2_permutation_argument_misordered",
    "halo2_selector_inactive_constraint_leak",
]
