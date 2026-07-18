"""
test_rust_wave1_refcell_borrow_mut_panic.py

Tests for the refcell_borrow_mut_panic detector (rust_wave1 package).

Detector: detectors/rust_wave1/refcell_borrow_mut_panic.py
Fixtures: detectors/rust_wave1/test_fixtures/refcell_borrow_mut_panic_{positive,negative}_{1,2}.rs

Run with:
    python3 -m unittest tools.tests.test_rust_wave1_refcell_borrow_mut_panic
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


class TestRefcellBorrowMutPanic(unittest.TestCase):
    """Detector: refcell_borrow_mut_panic"""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector("refcell_borrow_mut_panic")
        cls.DETECTOR_ID = "rust_wave1.refcell_borrow_mut_panic"

    # ------------------------------------------------------------------
    # 1. Fires on positive_1 (borrow() then borrow_mut() on same cell)
    # ------------------------------------------------------------------
    def test_fires_on_positive_1(self):
        """Detector fires when borrow() guard is live at borrow_mut() call."""
        pos = FIXTURES_DIR / "refcell_borrow_mut_panic_positive_1.rs"
        self.assertTrue(pos.exists(), f"Fixture missing: {pos}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(pos, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertGreaterEqual(
            len(hits), 1,
            f"Expected >=1 hit on positive_1 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 2. Fires on positive_2 (double borrow_mut() on same RefCell)
    # ------------------------------------------------------------------
    def test_fires_on_positive_2(self):
        """Detector fires on double borrow_mut() — second call panics."""
        pos = FIXTURES_DIR / "refcell_borrow_mut_panic_positive_2.rs"
        self.assertTrue(pos.exists(), f"Fixture missing: {pos}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(pos, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertGreaterEqual(
            len(hits), 1,
            f"Expected >=1 hit on positive_2 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 3. Silent on negative_1 (borrow in inner block, dropped before borrow_mut)
    # ------------------------------------------------------------------
    def test_silent_on_negative_1(self):
        """Detector is silent when borrow guard is dropped in inner block."""
        neg = FIXTURES_DIR / "refcell_borrow_mut_panic_negative_1.rs"
        self.assertTrue(neg.exists(), f"Fixture missing: {neg}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(neg, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertEqual(
            len(hits), 0,
            f"Expected 0 hits on negative_1 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 4. Silent on negative_2 (try_borrow_mut() — not panicking)
    # ------------------------------------------------------------------
    def test_silent_on_negative_2(self):
        """Detector is silent when try_borrow_mut() is used instead."""
        neg = FIXTURES_DIR / "refcell_borrow_mut_panic_negative_2.rs"
        self.assertTrue(neg.exists(), f"Fixture missing: {neg}")
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(neg, Path(tmp) / "fixture.rs")
            hits = self.mod.scan(tmp)
        self.assertEqual(
            len(hits), 0,
            f"Expected 0 hits on negative_2 fixture, got: {hits}",
        )

    # ------------------------------------------------------------------
    # 5. scan_file() dict fields correct on positive_1
    # ------------------------------------------------------------------
    def test_scan_file_dict_fields(self):
        """scan_file() returns dicts with detector_id, receiver, severity=MEDIUM."""
        pos = FIXTURES_DIR / "refcell_borrow_mut_panic_positive_1.rs"
        if not pos.exists():
            self.skipTest("positive_1 fixture missing")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual(h["detector_id"], self.DETECTOR_ID)
        self.assertIn("fn_name", h)
        self.assertEqual(h["severity"], "MEDIUM")
        self.assertIn("receiver", h)
        self.assertIn("borrow_line", h)
        self.assertIn("borrow_mut_line", h)

    # ------------------------------------------------------------------
    # 6. borrow_mut_line > borrow_line in positive_1 hit
    # ------------------------------------------------------------------
    def test_line_ordering(self):
        """borrow_mut_line is after borrow_line in the reported hit."""
        pos = FIXTURES_DIR / "refcell_borrow_mut_panic_positive_1.rs"
        if not pos.exists():
            self.skipTest("positive_1 fixture missing")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        self.assertGreater(
            h["borrow_mut_line"], h["borrow_line"],
            f"borrow_mut_line should be after borrow_line: {h}",
        )

    # ------------------------------------------------------------------
    # 7. module_path or fn_signature present (util field enrichment)
    # ------------------------------------------------------------------
    def test_util_fields_present(self):
        """Hits include module_path or fn_signature from _util enrichment."""
        pos = FIXTURES_DIR / "refcell_borrow_mut_panic_positive_1.rs"
        if not pos.exists():
            self.skipTest("positive_1 fixture missing")
        hits = self.mod.scan_file(str(pos))
        self.assertGreaterEqual(len(hits), 1)
        h = hits[0]
        has_util = "module_path" in h or "fn_signature" in h
        self.assertTrue(has_util, f"Expected util field in hit: {h}")


if __name__ == "__main__":
    unittest.main()
