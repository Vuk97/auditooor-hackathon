#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
WAVE19 = REPO / "detectors" / "wave19"
FIXTURES = REPO / "detectors" / "fixtures" / "solidity"
DETECTOR = "upgrade_implementation_initializers_not_disabled"


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


class UpgradeImplementationInitializersNotDisabledTest(unittest.TestCase):
    def test_positive_fires(self) -> None:
        mod = _load(DETECTOR)
        positive = _read(FIXTURES / DETECTOR / "vulnerable.sol")

        findings = mod.scan(positive, "vulnerable.sol")

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].detector, "upgrade-implementation-initializers-not-disabled"
        )
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[0].function, "VaultUpgradeable")

    def test_inherited_disable_initializers_is_clean(self) -> None:
        mod = _load(DETECTOR)
        clean = _read(FIXTURES / DETECTOR / "inherited_clean.sol")

        findings = mod.scan(clean, "inherited_clean.sol")

        self.assertEqual(findings, [])

    def test_abstract_upgradeable_contract_is_clean(self) -> None:
        mod = _load(DETECTOR)
        clean = _read(FIXTURES / DETECTOR / "abstract_clean.sol")

        findings = mod.scan(clean, "abstract_clean.sol")

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
