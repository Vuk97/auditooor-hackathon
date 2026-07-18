"""Tests for the three wave-2 FROST-derived standalone detectors.

Each detector lives at::

    detectors/rust_wave2/<id>.py

and exposes a ``scan(root: str) -> list[tuple[str, int, str]]`` function
that walks ``.rs`` files under ``root`` and returns ``(filepath, line, message)``
tuples.

Tests:
  1. ``frost_nonce_reuse_risk_unscoped_secret`` — fires on positive fixture
     (sign fn with SigningNonces but no freshness guard), silent on negative.
  2. ``frost_threshold_check_against_active_set_only`` — fires on positive
     (raw signers.len() >= threshold), silent on negative (HashSet dedup).
  3. ``frost_keypackage_serialization_unauthenticated`` — fires on positive
     (KeyPackage::deserialize without digest check), silent on negative.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
WAVE2_DIR = REPO_ROOT / "detectors" / "rust_wave2"
FIXTURES_DIR = WAVE2_DIR / "test_fixtures"


def _load_detector(name: str):
    """Load a wave-2 detector module by script name (without .py)."""
    script = WAVE2_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec and spec.loader, f"cannot load spec for {script}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class TestFrostNonceReuseRiskUnscopedSecret(unittest.TestCase):
    """Detector: frost_nonce_reuse_risk_unscoped_secret"""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector("frost_nonce_reuse_risk_unscoped_secret")

    def test_fires_on_positive_fixture(self):
        """Detector must find >=1 hit in the positive fixture."""
        pos_fixture = FIXTURES_DIR / "frost_nonce_reuse_risk_unscoped_secret_pos.rs"
        self.assertTrue(pos_fixture.exists(), f"positive fixture missing: {pos_fixture}")
        hits = self.mod.scan(str(FIXTURES_DIR / "frost_nonce_reuse_risk_unscoped_secret_pos.rs"))
        # The scan() function takes a directory; run on the parent dir but
        # filter to only the positive file's hits.
        all_hits = self.mod.scan(str(FIXTURES_DIR))
        pos_hits = [
            h for h in all_hits
            if "pos" in Path(h[0]).name
            and "nonce_reuse" in Path(h[0]).name
        ]
        self.assertGreaterEqual(
            len(pos_hits), 1,
            f"expected >=1 hit on positive fixture, got {pos_hits}",
        )

    def test_silent_on_negative_fixture(self):
        """Detector must return 0 hits for the negative (guarded) fixture."""
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(
                FIXTURES_DIR / "frost_nonce_reuse_risk_unscoped_secret_neg.rs",
                Path(tmp) / "fixture.rs",
            )
            hits = self.mod.scan(tmp)
        self.assertEqual(
            len(hits), 0,
            f"expected 0 hits on negative fixture, got {hits}",
        )


class TestFrostThresholdCheckAgainstActiveSetOnly(unittest.TestCase):
    """Detector: frost_threshold_check_against_active_set_only"""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector("frost_threshold_check_against_active_set_only")

    def test_fires_on_positive_fixture(self):
        """Detector must find >=1 hit in the positive fixture."""
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(
                FIXTURES_DIR / "frost_threshold_check_against_active_set_only_pos.rs",
                Path(tmp) / "fixture.rs",
            )
            hits = self.mod.scan(tmp)
        self.assertGreaterEqual(
            len(hits), 1,
            f"expected >=1 hit on positive fixture, got {hits}",
        )

    def test_silent_on_negative_fixture(self):
        """Detector must return 0 hits for the negative (deduped) fixture."""
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(
                FIXTURES_DIR / "frost_threshold_check_against_active_set_only_neg.rs",
                Path(tmp) / "fixture.rs",
            )
            hits = self.mod.scan(tmp)
        self.assertEqual(
            len(hits), 0,
            f"expected 0 hits on negative fixture, got {hits}",
        )


class TestFrostKeypackageSerializationUnauthenticated(unittest.TestCase):
    """Detector: frost_keypackage_serialization_unauthenticated"""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_detector("frost_keypackage_serialization_unauthenticated")

    def test_fires_on_positive_fixture(self):
        """Detector must find >=1 hit in the positive fixture."""
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(
                FIXTURES_DIR / "frost_keypackage_serialization_unauthenticated_pos.rs",
                Path(tmp) / "fixture.rs",
            )
            hits = self.mod.scan(tmp)
        self.assertGreaterEqual(
            len(hits), 1,
            f"expected >=1 hit on positive fixture, got {hits}",
        )

    def test_silent_on_negative_fixture(self):
        """Detector must return 0 hits for the negative (digest-verified) fixture."""
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(
                FIXTURES_DIR / "frost_keypackage_serialization_unauthenticated_neg.rs",
                Path(tmp) / "fixture.rs",
            )
            hits = self.mod.scan(tmp)
        self.assertEqual(
            len(hits), 0,
            f"expected 0 hits on negative fixture, got {hits}",
        )


if __name__ == "__main__":
    unittest.main()
