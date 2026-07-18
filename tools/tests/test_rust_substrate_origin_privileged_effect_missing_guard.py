from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust-substrate-origin-privileged-effect-missing-guard.py"
FIXTURE_DIR = (
    REPO_ROOT
    / "detectors"
    / "fixtures"
    / "rust-substrate-origin-privileged-effect-missing-guard"
)


def _load_detector():
    spec = importlib.util.spec_from_file_location(
        "rust_substrate_origin_privileged_effect_missing_guard",
        DETECTOR_PATH,
    )
    assert spec and spec.loader, f"cannot load detector at {DETECTOR_PATH}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class RustSubstrateOriginPrivilegedEffectMissingGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_detector()

    def test_positive_fixture_flags_missing_and_signed_only_guards(self) -> None:
        hits = self.mod.scan_file(str(FIXTURE_DIR / "positive.rs"))

        self.assertEqual(len(hits), 2, hits)
        messages = "\n".join(hit["message"] for hit in hits)
        self.assertIn("guard state is `missing`", messages)
        self.assertIn("guard state is `signed-only`", messages)
        self.assertTrue(all(hit["detector_id"] == self.mod.DETECTOR_ID for hit in hits))

    def test_xcm_positive_fixture_flags_unfiltered_converted_origin(self) -> None:
        hits = self.mod.scan_file(str(FIXTURE_DIR / "xcm_positive.rs"))

        self.assertEqual(len(hits), 1, hits)
        self.assertIn("without a visible location or junction filter", hits[0]["message"])
        self.assertEqual(hits[0]["detector_id"], self.mod.DETECTOR_ID)

    def test_clean_fixture_is_silent(self) -> None:
        hits = self.mod.scan_file(str(FIXTURE_DIR / "clean.rs"))
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
