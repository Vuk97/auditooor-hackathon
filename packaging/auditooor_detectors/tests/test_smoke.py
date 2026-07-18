"""Minimal smoke tests for the auditooor-detectors package."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest


def test_package_imports() -> None:
    import auditooor_detectors

    assert auditooor_detectors.__version__
    # Accept the legacy 0.1.x series and the v2 strict-only 0.2.x series.
    assert auditooor_detectors.__version__.startswith(("0.1.", "0.2."))


def test_load_registry() -> None:
    from auditooor_detectors import load_registry

    reg = load_registry()
    # schema_version 1 = legacy registry-only contract,
    # schema_version 2 = strict-smoke trust contract.
    assert reg["schema_version"] in (1, 2)
    assert reg["detector_count"] >= 1
    assert len(reg["detectors"]) == reg["detector_count"]
    for r in reg["detectors"]:
        assert r["tier"] in ("S", "A", "B")
        assert r["argument"]
        assert r["py_file"]


def test_detectors_dir_exists() -> None:
    from auditooor_detectors import detectors_dir, load_registry

    base = detectors_dir()
    assert base.exists() and base.is_dir()
    reg = load_registry()
    # Spot-check first 5 detector files exist on disk inside the package.
    for r in reg["detectors"][:5]:
        assert (base / r["py_file"]).exists(), r["py_file"]


def test_cli_runs() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "auditooor_detectors.list", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["count"] >= 1
    assert "detectors" in payload


@pytest.mark.parametrize("tier", ["S", "A", "B"])
def test_cli_tier_filter(tier: str) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "auditooor_detectors.list", "--tier", tier, "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    for r in payload["detectors"]:
        assert r["tier"] == tier
