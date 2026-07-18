"""cairo_wave1 — regex-based detectors for Cairo circuits.

Wave-6 Track K-zkBugs, step K-Z.10c. Targets Cairo (StarkWare's ZK-VM
language). Each detector is regex-only by design and scans `.cairo` files
that use felt/felt252 types, hint blocks (%{...%}), or starknet imports.

Supports Cairo 0.x (func, felt, hints) and Cairo 1.x (fn, felt252, use starknet::).

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names.
DETECTOR_MODULES = [
    "cairo_hint_decomposition_unconstrained",
    "cairo_storage_var_aliasing",
]
