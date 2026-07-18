"""bellperson_wave1 — regex-based detectors for Bellperson circuits.

Wave-7 Track K-zkBugs minor frameworks. Targets Bellperson (Zcash/Filecoin's
Groth16 implementation). Each detector is regex-only by design and scans
Rust sources that import `bellperson::*` or use `ConstraintSystem`.

Note: the existing `detectors/rust_wave1/zkbugs_bellperson_unconstrained_zero_default.py`
covers the specific case of `AllocatedNum::alloc(|| Ok(Scalar::zero()))` used
as a selector without enforcement. This wave adds a broader detector covering
all `cs.alloc(...)` / `cs.alloc_input(...)` calls with no downstream constraint.

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names.
DETECTOR_MODULES = [
    "bellperson_synthesis_unconstrained_alloc",
]
