"""
Tests for rust_substrate_origin_privileged_effect_missing_guard.

Run with:
    python3 -m unittest tools.tests.test_rust_wave1_substrate_origin_privileged_effect_missing_guard
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
WAVE1_DIR = REPO_ROOT / "detectors" / "rust_wave1"
FIXTURES_DIR = WAVE1_DIR / "test_fixtures"

if str(WAVE1_DIR) not in sys.path:
    sys.path.insert(0, str(WAVE1_DIR))

DETECTOR_NAME = "rust_substrate_origin_privileged_effect_missing_guard"
DETECTOR_ID = f"rust_wave1.{DETECTOR_NAME}"


def _load_detector(name: str = DETECTOR_NAME):
    script = WAVE1_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestRustSubstrateOriginPrivilegedEffectMissingGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector()

    def _run_fixture(self, fixture_name: str, mod=None) -> list[dict]:
        fixture = FIXTURES_DIR / fixture_name
        self.assertTrue(fixture.exists(), f"Fixture missing: {fixture}")
        if mod is self.mod or mod is None:
            return self.mod.scan_file(str(fixture))
        source = fixture.read_text(encoding="utf-8")
        return mod._scan_source_text(source, str(fixture))

    def test_fires_on_ignored_origin_privileged_bridge_route_write(self):
        hits = self._run_fixture(f"{DETECTOR_NAME}_positive.rs")
        self.assertEqual(len(hits), 1, hits)
        hit = hits[0]
        self.assertEqual(hit["detector_id"], DETECTOR_ID)
        self.assertEqual(hit["fn_name"], "refresh_route")
        self.assertEqual(hit["write_target"], "BridgeIngressAllowed")
        self.assertIn("ignores `origin`", hit["message"])

    def test_silent_on_root_and_signed_owner_guards(self):
        hits = self._run_fixture(f"{DETECTOR_NAME}_negative.rs")
        self.assertEqual(hits, [])

    def test_scan_file_matches_run_contract(self):
        fixture = FIXTURES_DIR / f"{DETECTOR_NAME}_positive.rs"
        hits = self.mod.scan_file(str(fixture))
        self.assertEqual(len(hits), 1, hits)
        self.assertEqual(hits[0]["detector_id"], DETECTOR_ID)


if __name__ == "__main__":
    unittest.main()
