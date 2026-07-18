"""plonky2_wave1 — regex-based detectors for Plonky2 circuits.

Wave-6 Track K-zkBugs, step K-Z.10a. Targets Plonky2 (Polygon's recursive
ZK framework). Each detector is regex-only by design (no tree-sitter-rust
dependency) and scans Rust sources that import `plonky2::*` or use
`CircuitBuilder<F,D>`.

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names (mirrors halo2_wave1 convention).
DETECTOR_MODULES = [
    "plonky2_circuit_builder_unconstrained_target",
    "plonky2_recursion_witness_mismatch",
    "plonky2_poseidon_state_capacity_leak",
]
