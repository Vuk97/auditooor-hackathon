"""risc0_wave1 — regex-based detectors for RISC Zero guest circuits.

Wave-7 Track K-zkBugs minor frameworks. Targets RISC Zero zkVM guest code
(https://github.com/risc0/risc0). Each detector is regex-only by design
and scans Rust guest sources that import `risc0_zkvm::*` or use
`env::read` / `env::commit`.

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names.
DETECTOR_MODULES = [
    "risc0_guest_panic_via_unwrap_in_zkvm",
]
