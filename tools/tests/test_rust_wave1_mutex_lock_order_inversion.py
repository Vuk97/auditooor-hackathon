"""
test_rust_wave1_mutex_lock_order_inversion.py

Tests for the mutex_lock_order_inversion detector (rust_wave1 package).

Detector: detectors/rust_wave1/mutex_lock_order_inversion.py
Fixtures: detectors/rust_wave1/test_fixtures/mutex_lock_order_inversion_{positive,negative}_{1,2}.rs

Run with:
    python3 -m unittest tools.tests.test_rust_wave1_mutex_lock_order_inversion
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


def _load_detector(name: str):
    script = WAVE1_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec and spec.loader, f"Cannot load spec for {script}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestMutexLockOrderInversion(unittest.TestCase):
    """Detector: mutex_lock_order_inversion"""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector("mutex_lock_order_inversion")
        cls.DETECTOR_ID = "rust_wave1.mutex_lock_order_inversion"

    # ------------------------------------------------------------------
    # 1. Fires on positive_1 (std Mutex ABBA inversion)
    # ------------------------------------------------------------------
    def test_fires_on_positive_1(self):
        """Detector fires on classic std::Mutex ABBA lock-order inversion."""
        pos = FIXTURES_DIR / "mutex_lock_order_inversion_positive_1.rs"
        self.assertTrue(pos.exists(), f"Fixture missing: {pos}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(pos, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertGreaterEqual(
            len(hits), 1,
            f"Expected >=1 hit on positive_1 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 2. Fires on positive_2 (parking_lot RwLock inversion)
    # ------------------------------------------------------------------
    def test_fires_on_positive_2(self):
        """Detector fires on parking_lot::RwLock read/write order inversion."""
        pos = FIXTURES_DIR / "mutex_lock_order_inversion_positive_2.rs"
        self.assertTrue(pos.exists(), f"Fixture missing: {pos}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(pos, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertGreaterEqual(
            len(hits), 1,
            f"Expected >=1 hit on positive_2 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 3. Silent on negative_1 (both fns use same lock order)
    # ------------------------------------------------------------------
    def test_silent_on_negative_1(self):
        """Detector is silent when both functions acquire locks in the same order."""
        neg = FIXTURES_DIR / "mutex_lock_order_inversion_negative_1.rs"
        self.assertTrue(neg.exists(), f"Fixture missing: {neg}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(neg, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertEqual(
            len(hits), 0,
            f"Expected 0 hits on negative_1 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 4. Silent on negative_2 (only one lock per function)
    # ------------------------------------------------------------------
    def test_silent_on_negative_2(self):
        """Detector is silent when each function acquires only one lock."""
        neg = FIXTURES_DIR / "mutex_lock_order_inversion_negative_2.rs"
        self.assertTrue(neg.exists(), f"Fixture missing: {neg}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(neg, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertEqual(
            len(hits), 0,
            f"Expected 0 hits on negative_2 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 5. scan_file() returns dicts with required fields on positive_1
    # ------------------------------------------------------------------
    def test_scan_file_dict_fields(self):
        """scan_file() dicts include detector_id, fn_name, lock_a, lock_b, severity=HIGH."""
        pos = FIXTURES_DIR / "mutex_lock_order_inversion_positive_1.rs"
        if not pos.exists():
            self.skipTest("positive_1 fixture missing")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual(h["detector_id"], self.DETECTOR_ID)
        self.assertIn("fn_name", h)
        self.assertEqual(h["severity"], "HIGH")
        self.assertIn("lock_a", h)
        self.assertIn("lock_b", h)
        self.assertIn("message", h)

    # ------------------------------------------------------------------
    # 6. Both functions in the inverted pair are reported
    # ------------------------------------------------------------------
    def test_both_functions_reported(self):
        """scan_file() reports hits for both functions in the inverted pair."""
        pos = FIXTURES_DIR / "mutex_lock_order_inversion_positive_1.rs"
        if not pos.exists():
            self.skipTest("positive_1 fixture missing")
        hits = self.mod.scan_file(str(pos))
        fn_names = {h["fn_name"] for h in hits}
        # Both transfer and reconcile should appear
        self.assertGreaterEqual(len(fn_names), 2,
                                f"Expected both inverted fns reported, got: {fn_names}")

    # ------------------------------------------------------------------
    # 7. module_path or fn_signature present (util field enrichment)
    # ------------------------------------------------------------------
    def test_util_fields_present(self):
        """Hits include module_path or fn_signature from _util enrichment."""
        pos = FIXTURES_DIR / "mutex_lock_order_inversion_positive_1.rs"
        if not pos.exists():
            self.skipTest("positive_1 fixture missing")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        has_util = "module_path" in h or "fn_signature" in h
        self.assertTrue(has_util, f"Expected util field in hit: {h}")


if __name__ == "__main__":
    unittest.main()
