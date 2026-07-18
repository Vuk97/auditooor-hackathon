"""pil_wave1 — regex-based detectors for PIL (Polynomial Identity Language).

Wave-7 Track K-zkBugs minor frameworks. Targets PIL (used by zkEVM
implementations, notably Polygon's PIL/PIL2 framework). Each detector
is regex-only and scans `.pil` files.

Detector contract: each module exposes `run_text(source: str, filepath: str)`
returning a list of dicts with keys `{detector_id, file, line, col,
severity, message, snippet}`.
"""
from __future__ import annotations

# Public detector module names.
DETECTOR_MODULES = [
    "pil_namespace_collision",
]
