from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = (
    REPO
    / "detectors"
    / "wave17"
    / "storage_namespace_first_caller_authority_init_fire15.py"
)
FIXTURE_DIR = (
    REPO
    / "detectors"
    / "fixtures"
    / "solidity"
    / "storage_namespace_first_caller_authority_init_fire15"
)


def _load_detector():
    module_name = "storage_namespace_first_caller_authority_init_fire15"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read_fixture(name: str) -> str:
    return (FIXTURE_DIR / name).read_text(encoding="utf-8")


class StorageNamespaceFirstCallerAuthorityInitFire15Test(unittest.TestCase):
    def test_fires_on_namespace_authority_first_caller_init(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read_fixture("vulnerable.sol"), "vulnerable.sol")

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding.detector,
            "storage-namespace-first-caller-authority-init-fire15",
        )
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.function, "initializeNamespace")
        self.assertIn("namespace authority", finding.message)

    def test_skips_factory_bound_namespace_init(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read_fixture("clean.sol"), "clean.sol")

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
