"""
test_rust_wave1_anchor_serialize_invariant_break.py

Tests for anchor_serialize_invariant_break detector.

Run with:
    python3 -m unittest tools.tests.test_rust_wave1_anchor_serialize_invariant_break
"""
from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
WAVE1_DIR = REPO_ROOT / "detectors" / "rust_wave1"
FIXTURES_DIR = WAVE1_DIR / "test_fixtures"

if str(WAVE1_DIR) not in sys.path:
    sys.path.insert(0, str(WAVE1_DIR))

DETECTOR_NAME = "anchor_serialize_invariant_break"
DETECTOR_ID = f"rust_wave1.{DETECTOR_NAME}"


def _load_detector():
    script = WAVE1_DIR / f"{DETECTOR_NAME}.py"
    spec = importlib.util.spec_from_file_location(DETECTOR_NAME, script)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[DETECTOR_NAME] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestAnchorSerializeInvariantBreak(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector()

    def _scan_fixture(self, fixture_name: str) -> list[dict]:
        fixture = FIXTURES_DIR / fixture_name
        self.assertTrue(fixture.exists(), f"Fixture missing: {fixture}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(fixture, Path(tmp) / "fixture.rs")
            return self.mod.scan(Path(tmp))

    def test_fires_on_positive_1(self):
        """Fires on `let _ = state.try_to_vec()` — discarded result."""
        hits = self._scan_fixture(f"{DETECTOR_NAME}_positive_1.rs")
        self.assertGreaterEqual(len(hits), 1, f"Expected >=1 hit, got: {hits}")

    def test_fires_on_positive_2(self):
        """Fires on bare `config.try_serialize(buf)` without ? propagation."""
        hits = self._scan_fixture(f"{DETECTOR_NAME}_positive_2.rs")
        self.assertGreaterEqual(len(hits), 1, f"Expected >=1 hit, got: {hits}")

    def test_silent_on_negative_1(self):
        """Silent when try_to_vec() is propagated with ?."""
        hits = self._scan_fixture(f"{DETECTOR_NAME}_negative_1.rs")
        self.assertEqual(len(hits), 0, f"Expected 0 hits, got: {hits}")

    def test_silent_on_negative_2(self):
        """Silent when try_to_vec() result is checked with match."""
        hits = self._scan_fixture(f"{DETECTOR_NAME}_negative_2.rs")
        self.assertEqual(len(hits), 0, f"Expected 0 hits, got: {hits}")

    def test_scan_file_returns_required_fields(self):
        """scan_file() hit has detector_id, severity=HIGH, method field."""
        fixture = FIXTURES_DIR / f"{DETECTOR_NAME}_positive_1.rs"
        if not fixture.exists():
            self.skipTest("positive_1 missing")
        hits = self.mod.scan_file(str(fixture))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual(h["detector_id"], DETECTOR_ID)
        self.assertEqual(h["severity"], "HIGH")
        self.assertIn("method", h)

    def test_scan_file_emits_util_fields(self):
        """scan_file() emits module_path or crate_name (best-effort)."""
        fixture = FIXTURES_DIR / f"{DETECTOR_NAME}_positive_1.rs"
        if not fixture.exists():
            self.skipTest("positive_1 missing")
        hits = self.mod.scan_file(str(fixture))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        has_util = "module_path" in h or "crate_name" in h or "call_line" in h
        self.assertTrue(has_util, f"Expected util field: {h}")


if __name__ == "__main__":
    unittest.main()
