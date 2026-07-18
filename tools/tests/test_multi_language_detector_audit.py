"""test_multi_language_detector_audit.py — unit tests for Phase H audit tool.

Tests:
  (a) report generates non-empty results for >= 3 languages
  (b) report flags a missing / zero-runner language as a gap
  (c) JSON format is parseable and matches schema
  (d) --lang filter restricts output to exactly one language
  (e) per-language dicts have the required keys
  (f) top3_gap_languages is populated when gaps exist
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

# Load the module under test directly (avoids __init__ dependency)
_TOOL_PATH = Path(__file__).resolve().parent.parent / "multi-language-detector-audit.py"

spec = importlib.util.spec_from_file_location("multi_language_detector_audit", _TOOL_PATH)
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)

run_audit = _mod.run_audit
format_md = _mod.format_md
LANGUAGE_SPECS = _mod.LANGUAGE_SPECS

REQUIRED_KEYS = {
    "language",
    "description",
    "detector_count",
    "fixture_count",
    "test_count",
    "runner_wired",
    "solodit_pattern_count",
    "gap_count",
    "gaps",
}

REQUIRED_REPORT_KEYS = {
    "schema",
    "generated",
    "languages_audited",
    "total_gap_count",
    "languages_without_runner",
    "languages_without_tests",
    "top3_gap_languages",
    "prioritized_gaps",
    "per_language",
}


class TestMultiLanguageDetectorAudit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Run full audit once; reuse across all tests."""
        cls.report = run_audit()
        cls.per_lang = {r["language"]: r for r in cls.report["per_language"]}

    # ------------------------------------------------------------------
    # (a) Report covers >= 3 languages with non-empty results
    # ------------------------------------------------------------------

    def test_report_covers_at_least_three_languages(self):
        self.assertGreaterEqual(
            self.report["languages_audited"],
            3,
            "Audit must cover at least 3 languages",
        )

    def test_per_language_list_non_empty(self):
        self.assertGreater(len(self.report["per_language"]), 0)

    # ------------------------------------------------------------------
    # (b) Missing runner languages appear in gaps / languages_without_runner
    # ------------------------------------------------------------------

    def test_vyper_missing_runner_flagged(self):
        """Vyper has no runner tool — must appear in languages_without_runner."""
        self.assertIn(
            "vyper",
            self.report["languages_without_runner"],
            "Vyper should be flagged as missing a runner",
        )

    def test_cairo_missing_runner_flagged(self):
        """Cairo has no runner tool — must appear in languages_without_runner."""
        self.assertIn(
            "cairo",
            self.report["languages_without_runner"],
            "Cairo should be flagged as missing a runner",
        )

    def test_sway_missing_runner_flagged(self):
        """Sway has no runner tool — must appear in languages_without_runner."""
        self.assertIn(
            "sway",
            self.report["languages_without_runner"],
            "Sway should be flagged as missing a runner",
        )

    def test_missing_runner_language_has_positive_gap_count(self):
        """Every language in languages_without_runner must have gap_count > 0."""
        for lang in self.report["languages_without_runner"]:
            row = self.per_lang.get(lang)
            self.assertIsNotNone(row, f"No row for {lang}")
            self.assertGreater(
                row["gap_count"],
                0,
                f"{lang} has no runner but gap_count == 0",
            )

    # ------------------------------------------------------------------
    # (c) JSON format is parseable and matches schema
    # ------------------------------------------------------------------

    def test_schema_field_present(self):
        self.assertIn("schema", self.report)
        self.assertIn("auditooor.multi_language_detector_audit", self.report["schema"])

    def test_report_is_json_serializable(self):
        dumped = json.dumps(self.report)
        loaded = json.loads(dumped)
        self.assertEqual(loaded["schema"], self.report["schema"])

    def test_all_required_report_keys_present(self):
        missing = REQUIRED_REPORT_KEYS - set(self.report.keys())
        self.assertEqual(missing, set(), f"Report missing keys: {missing}")

    def test_per_language_rows_have_required_keys(self):
        for row in self.report["per_language"]:
            missing = REQUIRED_KEYS - set(row.keys())
            self.assertEqual(
                missing,
                set(),
                f"Row for '{row.get('language', '?')}' missing keys: {missing}",
            )

    def test_generated_date_is_string(self):
        self.assertIsInstance(self.report["generated"], str)
        self.assertRegex(self.report["generated"], r"^\d{4}-\d{2}-\d{2}$")

    def test_total_gap_count_equals_sum_of_per_language(self):
        expected = sum(r["gap_count"] for r in self.report["per_language"])
        self.assertEqual(self.report["total_gap_count"], expected)

    # ------------------------------------------------------------------
    # (d) --lang filter restricts to exactly one language
    # ------------------------------------------------------------------

    def test_lang_filter_rust_returns_one_row(self):
        filtered = run_audit(lang_filter="rust")
        self.assertEqual(filtered["languages_audited"], 1)
        self.assertEqual(len(filtered["per_language"]), 1)
        self.assertEqual(filtered["per_language"][0]["language"], "rust")

    def test_lang_filter_go_returns_one_row(self):
        filtered = run_audit(lang_filter="go")
        self.assertEqual(filtered["languages_audited"], 1)
        self.assertEqual(filtered["per_language"][0]["language"], "go")

    def test_lang_filter_unknown_raises(self):
        with self.assertRaises(ValueError):
            run_audit(lang_filter="cobol")

    # ------------------------------------------------------------------
    # (e) Wired languages have correct runner_wired value
    # ------------------------------------------------------------------

    def test_rust_runner_wired(self):
        self.assertTrue(
            self.per_lang["rust"]["runner_wired"],
            "Rust must have runner_wired=True (rust-detector-runner.py exists)",
        )

    def test_go_runner_wired(self):
        self.assertTrue(
            self.per_lang["go"]["runner_wired"],
            "Go must have runner_wired=True (go-detector-runner.py exists)",
        )

    def test_circom_runner_wired(self):
        self.assertTrue(
            self.per_lang["circom"]["runner_wired"],
            "Circom must have runner_wired=True (circom-detect.py exists)",
        )

    def test_vyper_runner_not_wired(self):
        self.assertFalse(
            self.per_lang["vyper"]["runner_wired"],
            "Vyper must have runner_wired=False (no runner tool yet)",
        )

    # ------------------------------------------------------------------
    # (f) top3_gap_languages is populated
    # ------------------------------------------------------------------

    def test_top3_gap_languages_non_empty(self):
        self.assertGreater(
            len(self.report["top3_gap_languages"]),
            0,
            "top3_gap_languages should have entries",
        )

    def test_prioritized_gaps_have_required_fields(self):
        for p in self.report["prioritized_gaps"]:
            self.assertIn("rank", p)
            self.assertIn("language", p)
            self.assertIn("gap_count", p)

    # ------------------------------------------------------------------
    # (g) Markdown formatter produces non-empty output
    # ------------------------------------------------------------------

    def test_format_md_non_empty(self):
        md = format_md(self.report)
        self.assertIn("Multi-Language Detector Audit", md)
        self.assertIn("| Language |", md)
        self.assertGreater(len(md), 200)

    def test_format_md_contains_rust(self):
        md = format_md(self.report)
        self.assertIn("rust", md)

    # ------------------------------------------------------------------
    # (h) High-coverage languages have positive detector counts
    # ------------------------------------------------------------------

    def test_solidity_has_many_detectors(self):
        """Solidity is the dominant language — expect hundreds of detectors."""
        sol = self.per_lang["solidity"]
        self.assertGreater(sol["detector_count"], 100)

    def test_rust_has_many_detectors(self):
        rust = self.per_lang["rust"]
        self.assertGreater(rust["detector_count"], 10)

    def test_rust_has_fixtures(self):
        rust = self.per_lang["rust"]
        self.assertGreater(rust["fixture_count"], 0)

    def test_go_has_fixtures(self):
        go = self.per_lang["go"]
        self.assertGreater(go["fixture_count"], 0)


if __name__ == "__main__":
    unittest.main()
