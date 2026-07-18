"""Focused tests for registry-disk fixture resolution."""

from __future__ import annotations

import importlib.util
import tempfile
import types
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "registry-disk-consistency-check.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("registry_disk_consistency_check", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DetectorLocalFixtureResolutionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.t = _load_module()

    def test_explicit_owned_detector_local_fixture_dir_resolves_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "detectors" / "_fixtures" / "owned_detector"
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "Alpha_vulnerable.sol").write_text("// vuln\n", encoding="utf-8")
            (fixture_dir / "Alpha_clean.sol").write_text("// clean\n", encoding="utf-8")
            (fixture_dir / "Beta_vulnerable.sol").write_text("// other vuln\n", encoding="utf-8")
            (fixture_dir / "Beta_clean.sol").write_text("// other clean\n", encoding="utf-8")

            tests_dir = root / "tools" / "tests"
            tests_dir.mkdir(parents=True)
            (tests_dir / "test_owned_detector.py").write_text(
                'FIXTURE_DIR = REPO / "detectors" / "_fixtures" / "owned_detector"\n',
                encoding="utf-8",
            )

            original_repo = self.t.REPO
            self.t.REPO = root
            try:
                vuln, clean = self.t.find_fixtures(
                    "owned-detector",
                    {
                        "fixture_pair": "detectors/_fixtures/owned_detector",
                        "smoke_test_command": (
                            "python3 detectors/run_custom.py --tier=ALL "
                            "detectors/_fixtures/owned_detector/Beta_vulnerable.sol "
                            "owned-detector"
                        ),
                    },
                )
            finally:
                self.t.REPO = original_repo

            self.assertEqual(vuln.resolve(), (fixture_dir / "Beta_vulnerable.sol").resolve())
            self.assertEqual(clean.resolve(), (fixture_dir / "Beta_clean.sol").resolve())

    def test_detector_local_fixture_dir_requires_focused_owner_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "detectors" / "_fixtures" / "unowned_detector"
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "Alpha_vulnerable.sol").write_text("// vuln\n", encoding="utf-8")
            (fixture_dir / "Alpha_clean.sol").write_text("// clean\n", encoding="utf-8")

            original_repo = self.t.REPO
            self.t.REPO = root
            try:
                vuln, clean = self.t.find_fixtures(
                    "unowned-detector",
                    {"fixture_pair": "detectors/_fixtures/unowned_detector"},
                )
            finally:
                self.t.REPO = original_repo

            self.assertIsNone(vuln)
            self.assertIsNone(clean)


if __name__ == "__main__":
    unittest.main()
