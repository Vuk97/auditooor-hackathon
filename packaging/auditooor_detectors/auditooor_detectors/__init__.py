"""auditooor-detectors — verified Tier-S/A/B custom detector pack.

The bundled detectors are validated by the auditooor pipeline at packaging
time (``smoke_test_clean_hits == 0`` and ``smoke_test_vuln_hits >= 1`` against
the curated fixture pair). Tier classification means smoke-test passed, NOT a
zero-FP guarantee on production code. Calibrate against your codebase before
relying on results — see the README for guidance.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

__version__ = "0.2.20260504"

__all__ = ["__version__", "load_registry", "detectors_dir"]


def load_registry() -> dict[str, Any]:
    """Return the parsed slim registry shipped inside the package."""
    with resources.files(__name__).joinpath("registry.json").open("r") as fh:
        return json.load(fh)


def detectors_dir() -> Path:
    """Return on-disk path to the bundled detector payload directory."""
    return Path(str(resources.files(__name__).joinpath("detectors")))
