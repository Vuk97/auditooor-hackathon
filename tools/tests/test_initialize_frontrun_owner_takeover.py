#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
WAVE19 = REPO / "detectors" / "wave19"
FIXTURES = REPO / "detectors" / "fixtures" / "solidity"
DETECTOR = "initialize_frontrun_owner_takeover"


def _load(module_name: str):
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = WAVE19 / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader, f"failed to load {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class InitializeFrontrunOwnerTakeoverTest(unittest.TestCase):
    def test_positive_fires_and_clean_is_silent(self) -> None:
        mod = _load(DETECTOR)

        positive = _read(FIXTURES / DETECTOR / "vulnerable.sol")
        positive_findings = mod.scan(positive, "vulnerable.sol")
        self.assertGreaterEqual(len(positive_findings), 1)
        finding = positive_findings[0]
        self.assertEqual(finding.detector, "initialize-frontrun-owner-takeover")
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.function.lower(), "initialize")

        clean = _read(FIXTURES / DETECTOR / "clean.sol")
        clean_findings = mod.scan(clean, "clean.sol")
        self.assertEqual(clean_findings, [])


if __name__ == "__main__":
    unittest.main()
