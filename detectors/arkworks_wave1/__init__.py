"""arkworks_wave1 — regex-based detectors for Arkworks circuits.

Wave-7 Track K-zkBugs minor frameworks. Targets Arkworks (the Rust ZK
library ecosystem at https://github.com/arkworks-rs). Each detector is
regex-only by design and scans Rust sources that import `ark_*` crates
or use `ConstraintSynthesizer`.

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names.
DETECTOR_MODULES = [
    "arkworks_fp_add_overflow_no_modular_reduction",
    "arkworks_pairing_input_validation_missing",
]
