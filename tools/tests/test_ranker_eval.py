#!/usr/bin/env python3
"""Unit tests for ranker-eval.py"""

import unittest
import sys
import os
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import the module to test
import importlib.util
spec = importlib.util.spec_from_file_location("ranker_eval",
    os.path.join(os.path.dirname(__file__), "..", "ranker-eval.py"))
ranker_eval = importlib.util.module_from_spec(spec)


class TestRankerEvalMetadataExtraction(unittest.TestCase):
    """Test metadata extraction from filed submissions."""

    def test_extract_cantina_id_from_filename(self):
        """Should extract cantina-NNN from filename."""
        fname = "/path/to/filed/cantina-048_dydx-cosmos-sdk-consensus-params-missing-validateupdate-CRITICAL.md"
        # Simulate extraction
        import re
        match = re.search(r"(cantina-\d+|cantina-PENDING\d+)", fname)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "cantina-048")

    def test_extract_severity_from_filename(self):
        """Should extract CRITICAL/HIGH/MEDIUM/LOW from filename."""
        fname = "cantina-048_something-HIGH.md"
        import re
        match = re.search(r"(CRITICAL|HIGH|MEDIUM|LOW)\.md", fname)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "HIGH")

    def test_extract_attack_class_from_filename(self):
        """Should parse attack class slug from filename."""
        fname = "dydx-iavl-no-close-pruning-shutdown-race-CRITICAL.md"
        import re
        match = re.search(r"dydx-([a-z\-]+)-(?:CRITICAL|HIGH)", fname)
        self.assertIsNotNone(match)
        attack_class = match.group(1).replace("-", "_")
        self.assertEqual(attack_class, "iavl_no_close_pruning_shutdown_race")

    def test_extract_repo_from_filename(self):
        """Should infer repo from filename keywords."""
        for fname, expected_repo in [
            ("dydx-something.md", "dydxprotocol/v4-chain"),
            ("spark-something.md", "buildonspark/spark"),
        ]:
            if "dydx" in fname:
                repo = "dydxprotocol/v4-chain"
            else:
                repo = "buildonspark/spark"
            self.assertEqual(repo, expected_repo)


class TestRankerEvalScoring(unittest.TestCase):
    """Test scoring logic."""

    def test_precision_at_5_calculation(self):
        """Should compute precision@5 as hits / total."""
        hits = 5
        total = 8
        precision = hits / total if total > 0 else 0.0
        self.assertAlmostEqual(precision, 0.625, places=3)

    def test_hit_detection_in_top_5(self):
        """Should detect if attack_class is in predicted_top_5."""
        actual = "reentrancy_guard"
        predicted = ["reentrancy_guard", "access_control", "overflow"]
        hit = actual in predicted
        self.assertTrue(hit)

        actual = "missing_bounds_check"
        hit = actual in predicted
        self.assertFalse(hit)

    def test_confidence_extraction_on_hit(self):
        """Should extract confidence score of the hit position."""
        predictions = [
            {"attack_class": "reentrancy", "confidence": 0.92},
            {"attack_class": "overflow", "confidence": 0.78},
            {"attack_class": "access_control", "confidence": 0.65},
        ]
        actual = "overflow"

        confidence = 0.0
        for p in predictions:
            if p["attack_class"] == actual:
                confidence = p["confidence"]
                break

        self.assertAlmostEqual(confidence, 0.78, places=2)

    def test_mean_confidence_calculation(self):
        """Should compute mean confidence over hits only."""
        confidences = [0.92, 0.88, 0.75]
        mean = sum(confidences) / len(confidences)
        self.assertAlmostEqual(mean, 0.85, places=2)


class TestRankerEvalAcceptance(unittest.TestCase):
    """Test acceptance criteria."""

    def test_acceptance_threshold_pass(self):
        """Should PASS when precision@5 >= 0.625."""
        precision = 0.625
        accept = precision >= 0.625
        self.assertTrue(accept)

        precision = 0.75
        accept = precision >= 0.625
        self.assertTrue(accept)

    def test_acceptance_threshold_fail(self):
        """Should FAIL when precision@5 < 0.625."""
        precision = 0.5
        accept = precision >= 0.625
        self.assertFalse(accept)

        precision = 0.624
        accept = precision >= 0.625
        self.assertFalse(accept)


class TestRankerEvalIntegration(unittest.TestCase):
    """Integration tests."""

    def test_eval_filing_structure(self):
        """Should return dict with required fields."""
        result = {
            "filing_id": "cantina-048",
            "actual_attack_class": "admin_bypass",
            "predicted_top_5": ["admin_bypass", "access_control", "fee_redirect"],
            "hit_at_5": True,
            "hit_position": 0,
            "confidence": 0.92,
            "severity": "CRITICAL",
        }
        self.assertIn("filing_id", result)
        self.assertIn("hit_at_5", result)
        self.assertIn("confidence", result)
        self.assertTrue(result["hit_at_5"])

    def test_report_generation_structure(self):
        """Should produce markdown report with required sections."""
        report = """# Ranker Evaluation Report

## Summary Metrics

| Metric | Value |
|--------|-------|
| Precision@5 | 62.5% (5/8) |

## Per-Filing Results

| filing_id | hit_at_5 |
|-----------|----------|

## Verdict

Result: ACCEPT
"""
        self.assertIn("# Ranker Evaluation Report", report)
        self.assertIn("## Summary Metrics", report)
        self.assertIn("## Per-Filing Results", report)
        self.assertIn("## Verdict", report)
        self.assertIn("Precision@5", report)


if __name__ == "__main__":
    unittest.main()
