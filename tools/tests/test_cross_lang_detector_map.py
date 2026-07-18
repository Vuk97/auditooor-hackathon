"""
test_cross_lang_detector_map.py

Tests for reference/cross_lang_detector_map.yaml and
tools/cross-lang-detector-map-check.py.

Run with:
    python3 -m unittest tools.tests.test_cross_lang_detector_map
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
MAP_PATH = REPO_ROOT / "reference" / "cross_lang_detector_map.yaml"
CHECK_TOOL = REPO_ROOT / "tools" / "cross-lang-detector-map-check.py"

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class TestCrossLangDetectorMap(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.map_path = MAP_PATH
        cls.check_tool = CHECK_TOOL

    # ------------------------------------------------------------------
    # 1. YAML file exists and parses without error
    # ------------------------------------------------------------------
    def test_yaml_file_exists(self):
        """cross_lang_detector_map.yaml exists."""
        self.assertTrue(
            self.map_path.exists(),
            f"Map not found: {self.map_path}"
        )

    @unittest.skipUnless(HAS_YAML, "PyYAML not installed")
    def test_yaml_parses(self):
        """YAML parses to a dict with 'mappings' key."""
        with open(self.map_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        self.assertIsInstance(data, dict, "Top-level should be a dict")
        self.assertIn("mappings", data, "Must have 'mappings' key")
        self.assertIsInstance(data["mappings"], list, "'mappings' must be a list")
        self.assertGreaterEqual(len(data["mappings"]), 8,
                                "Must have at least 8 cross-lang pairs")

    # ------------------------------------------------------------------
    # 2. All rust_wave1.* IDs resolve to disk files
    # ------------------------------------------------------------------
    @unittest.skipUnless(HAS_YAML, "PyYAML not installed")
    def test_rust_wave1_ids_resolve(self):
        """All non-planned rust_wave1.* detector IDs exist on disk."""
        import re
        with open(self.map_path, encoding="utf-8") as fh:
            raw = fh.read()
        data = yaml.safe_load(raw)
        rust_wave1_dir = REPO_ROOT / "detectors" / "rust_wave1"
        missing = []
        for entry in data.get("mappings", []):
            for det_id in entry.get("rust", []):
                if not det_id.startswith("rust_wave1."):
                    continue
                name = det_id[len("rust_wave1."):]
                path = rust_wave1_dir / f"{name}.py"
                if not path.exists():
                    missing.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(
            missing, [],
            f"Missing rust_wave1 detectors: {missing}"
        )

    # ------------------------------------------------------------------
    # 3. All rust_wave2.* IDs resolve to disk files
    # ------------------------------------------------------------------
    @unittest.skipUnless(HAS_YAML, "PyYAML not installed")
    def test_rust_wave2_ids_resolve(self):
        """All rust_wave2.* detector IDs exist on disk."""
        with open(self.map_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        rust_wave2_dir = REPO_ROOT / "detectors" / "rust_wave2"
        missing = []
        for entry in data.get("mappings", []):
            for det_id in entry.get("rust", []):
                if not det_id.startswith("rust_wave2."):
                    continue
                name = det_id[len("rust_wave2."):]
                path = rust_wave2_dir / f"{name}.py"
                if not path.exists():
                    missing.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(
            missing, [],
            f"Missing rust_wave2 detectors: {missing}"
        )

    # ------------------------------------------------------------------
    # 4. --query returns the correct entry
    # ------------------------------------------------------------------
    def test_query_missing_authority_check(self):
        """--query missing-authority-check-on-msg-server returns the entry."""
        result = subprocess.run(
            [sys.executable, str(self.check_tool),
             "--query", "missing-authority-check-on-msg-server"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0,
                         f"Query returned non-zero: {result.stderr}")
        self.assertIn("missing-authority-check-on-msg-server", result.stdout)
        self.assertIn("rust_wave1.anchor_owner_check_missing_on_authority",
                      result.stdout)

    # ------------------------------------------------------------------
    # 5. --validate exits 0 (all present IDs resolve; planned ones skipped)
    # ------------------------------------------------------------------
    def test_validate_exits_zero(self):
        """--validate exits 0 when all non-planned IDs exist on disk."""
        result = subprocess.run(
            [sys.executable, str(self.check_tool), "--validate"],
            capture_output=True, text=True
        )
        self.assertEqual(
            result.returncode, 0,
            f"--validate failed with errors:\n{result.stderr}\n{result.stdout}"
        )
        self.assertIn("PASS", result.stdout)

    # ------------------------------------------------------------------
    # 6. --query-by-detector returns entries for a known detector
    # ------------------------------------------------------------------
    def test_query_by_detector_finds_rust_wave1(self):
        """--query-by-detector rust_wave1.mutex_lock_order_inversion returns entry."""
        result = subprocess.run(
            [sys.executable, str(self.check_tool),
             "--query-by-detector", "rust_wave1.mutex_lock_order_inversion"],
            capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0,
                         f"Query-by-detector failed: {result.stderr}")
        self.assertIn("mutex-lock-order-inversion", result.stdout)

    # ------------------------------------------------------------------
    # 7. Schema field check: each entry has bug_class + empirical_anchor
    # ------------------------------------------------------------------
    @unittest.skipUnless(HAS_YAML, "PyYAML not installed")
    def test_all_entries_have_required_fields(self):
        """Each mapping entry has bug_class, empirical_anchor, severity_class_match."""
        with open(self.map_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        missing_fields = []
        for i, entry in enumerate(data.get("mappings", [])):
            for field in ("bug_class", "empirical_anchor", "severity_class_match"):
                if field not in entry or not entry[field]:
                    missing_fields.append(f"entry[{i}].{field}")
        self.assertEqual(
            missing_fields, [],
            f"Entries missing required fields: {missing_fields}"
        )


if __name__ == "__main__":
    unittest.main()
