"""
test_rust_wave1_async_await_after_lock.py

Tests for the async_await_after_lock detector (rust_wave1 package).

Detector: detectors/rust_wave1/async_await_after_lock.py
Fixtures: detectors/rust_wave1/test_fixtures/async_await_after_lock_{positive,negative}_{1,2}.rs

Run with:
    python3 -m unittest tools.tests.test_rust_wave1_async_await_after_lock
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

# Ensure _util is importable
if str(WAVE1_DIR) not in sys.path:
    sys.path.insert(0, str(WAVE1_DIR))


def _load_detector(name: str):
    """Load a detector module by script name (without .py)."""
    script = WAVE1_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec and spec.loader, f"Cannot load spec for {script}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestAsyncAwaitAfterLock(unittest.TestCase):
    """Detector: async_await_after_lock"""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector("async_await_after_lock")
        cls.DETECTOR_ID = "rust_wave1.async_await_after_lock"

    # ------------------------------------------------------------------
    # 1. Fires on positive_1 (tokio Mutex guard held across .await)
    # ------------------------------------------------------------------
    def test_fires_on_positive_1(self):
        """Detector fires on async fn holding tokio::Mutex guard across .await."""
        pos = FIXTURES_DIR / "async_await_after_lock_positive_1.rs"
        self.assertTrue(pos.exists(), f"Fixture missing: {pos}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(pos, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertGreaterEqual(
            len(hits), 1,
            f"Expected >=1 hit on positive_1 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 2. Fires on positive_2 (parking_lot RwLock read guard across .await)
    # ------------------------------------------------------------------
    def test_fires_on_positive_2(self):
        """Detector fires on parking_lot::RwLock read guard held across .await."""
        pos = FIXTURES_DIR / "async_await_after_lock_positive_2.rs"
        self.assertTrue(pos.exists(), f"Fixture missing: {pos}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(pos, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertGreaterEqual(
            len(hits), 1,
            f"Expected >=1 hit on positive_2 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 3. Silent on negative_1 (guard dropped in inner block before .await)
    # ------------------------------------------------------------------
    def test_silent_on_negative_1(self):
        """Detector is silent when guard is dropped in inner block before .await."""
        neg = FIXTURES_DIR / "async_await_after_lock_negative_1.rs"
        self.assertTrue(neg.exists(), f"Fixture missing: {neg}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(neg, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertEqual(
            len(hits), 0,
            f"Expected 0 hits on negative_1 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 4. Silent on negative_2 (only .await is on lock() itself)
    # ------------------------------------------------------------------
    def test_silent_on_negative_2(self):
        """Detector is silent when .await is only on lock() — the safe pattern."""
        neg = FIXTURES_DIR / "async_await_after_lock_negative_2.rs"
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
        """scan_file() returns dicts with detector_id, fn_name, severity=HIGH."""
        pos = FIXTURES_DIR / "async_await_after_lock_positive_1.rs"
        if not pos.exists():
            self.skipTest("positive_1 fixture missing")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual(h["detector_id"], self.DETECTOR_ID)
        self.assertIn("fn_name", h)
        self.assertEqual(h["severity"], "HIGH")
        self.assertIn("lock_method", h)
        self.assertIn("message", h)

    # ------------------------------------------------------------------
    # 6. scan_file() emits crate_name / module_path / fn_signature fields
    # ------------------------------------------------------------------
    def test_scan_file_util_fields_present(self):
        """scan_file() emits module_path and fn_signature on positive fixture."""
        pos = FIXTURES_DIR / "async_await_after_lock_positive_1.rs"
        if not pos.exists():
            self.skipTest("positive_1 fixture missing")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        # module_path or fn_signature should be present (best-effort)
        has_util_field = ("module_path" in h or "fn_signature" in h)
        self.assertTrue(
            has_util_field,
            f"Expected at least one of module_path/fn_signature in hit: {h}",
        )

    # ------------------------------------------------------------------
    # Type-guard gating (FP precision) tests
    # ------------------------------------------------------------------
    def test_spin_lock_not_flagged(self):
        """spin::Mutex guard across .await is NOT flagged (non-yielding lock)."""
        neg = FIXTURES_DIR / "async_await_after_lock_negative_spin.rs"
        self.assertTrue(neg.exists(), f"Fixture missing: {neg}")
        hits = self.mod.scan_file(str(neg))
        self.assertEqual(
            len(hits), 0,
            f"Expected 0 hits on spin:: fixture (non-yielding lock), got: {hits}",
        )

    def test_ambiguous_read_without_blocking_import_not_flagged(self):
        """`.read()` with no blocking-lock type in evidence is NOT flagged."""
        neg = FIXTURES_DIR / "async_await_after_lock_negative_ambiguous_read.rs"
        self.assertTrue(neg.exists(), f"Fixture missing: {neg}")
        hits = self.mod.scan_file(str(neg))
        self.assertEqual(
            len(hits), 0,
            f"Expected 0 hits on ambiguous .read() fixture (no blocking lock "
            f"type in evidence), got: {hits}",
        )

    def test_tokio_mutex_still_flagged_high(self):
        """TRUE POSITIVE preserved: tokio::sync::Mutex across .await still HIGH.

        The whole point is precision, not silencing — the canonical tokio
        deadlock (positive_1) must keep firing at HIGH severity because the
        file imports a blocking lock type.
        """
        pos = FIXTURES_DIR / "async_await_after_lock_positive_1.rs"
        self.assertTrue(pos.exists(), f"Fixture missing: {pos}")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(
            len(hits), 1,
            f"TRUE POSITIVE regressed: tokio Mutex-across-await must still "
            f"fire, got: {hits}",
        )
        self.assertEqual(
            hits[0]["severity"], "HIGH",
            f"tokio Mutex (blocking type resolved) must stay HIGH: {hits[0]}",
        )
        self.assertTrue(
            hits[0].get("type_resolved_blocking"),
            f"tokio Mutex should resolve to a blocking type: {hits[0]}",
        )

    def test_parking_lot_rwlock_read_still_flagged(self):
        """TRUE POSITIVE preserved: parking_lot RwLock read guard still fires.

        positive_2 uses `.read()` but imports `parking_lot::RwLock`, so the
        blocking-lock type IS in evidence and the `.read()` must still flag.
        """
        pos = FIXTURES_DIR / "async_await_after_lock_positive_2.rs"
        self.assertTrue(pos.exists(), f"Fixture missing: {pos}")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(
            len(hits), 1,
            f"TRUE POSITIVE regressed: parking_lot RwLock read guard must "
            f"still fire (blocking import present), got: {hits}",
        )


if __name__ == "__main__":
    unittest.main()
