"""Tests for tools/lib/pdf_severity_normalizer.py.

All raw severity strings used here are synthetic_fixture: true examples
derived from the per-firm conventions documented in the module docstring
(Spearbit "Risk" suffix, Zellic/ChainSecurity "Best Practice", OpenZeppelin
"Note", Cyfrin "Gas Optimization", standard tiers). No real-source PDFs
are loaded.
"""
from __future__ import annotations

import unittest

from tools.lib.pdf_severity_normalizer import (
    CANONICAL_SEVERITIES,
    SEVERITY_ALIASES,
    SEVERITY_RANK,
    infer_severity_from_id_prefix,
    is_gas_finding,
    normalize_severity,
    severity_rank,
)


class CanonicalIdentityTests(unittest.TestCase):
    """Each canonical form must round-trip to itself."""

    def test_each_canonical_form_returns_itself(self):
        for sev in CANONICAL_SEVERITIES:
            with self.subTest(sev=sev):
                self.assertEqual(normalize_severity(sev), sev)


class CaseInsensitiveTests(unittest.TestCase):
    def test_lowercase_critical(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("critical"), "Critical")

    def test_uppercase_high(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("HIGH"), "High")

    def test_mixed_case_informational(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("InFoRmAtIoNaL"), "Informational")

    def test_whitespace_stripped(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("  Medium  "), "Medium")


class FirmVariantTests(unittest.TestCase):
    def test_spearbit_critical_risk(self):
        # synthetic_fixture: true (Spearbit "Risk"-suffixed tier)
        self.assertEqual(normalize_severity("Critical Risk"), "Critical")

    def test_spearbit_high_risk(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("High Risk"), "High")

    def test_spearbit_medium_risk(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("Medium Risk"), "Medium")

    def test_spearbit_low_risk(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("Low Risk"), "Low")

    def test_zellic_best_practice(self):
        # synthetic_fixture: true (Zellic/ChainSecurity Best Practice tier)
        self.assertEqual(normalize_severity("Best Practice"), "Informational")

    def test_chainsecurity_best_practices_plural(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("Best Practices"), "Informational")

    def test_openzeppelin_note(self):
        # synthetic_fixture: true (OZ "Note" tier)
        self.assertEqual(normalize_severity("Note"), "Informational")

    def test_cyfrin_gas_optimization(self):
        # synthetic_fixture: true (Cyfrin Gas Optimization tier)
        self.assertEqual(normalize_severity("Gas Optimization"), "Gas")

    def test_cyfrin_gas_optimizations_plural(self):
        # synthetic_fixture: true
        self.assertEqual(normalize_severity("Gas Optimizations"), "Gas")


class TrailingWordToleranceTests(unittest.TestCase):
    def test_trailing_descriptor_after_high_risk(self):
        # synthetic_fixture: true (Spearbit-style with trailing rationale)
        self.assertEqual(
            normalize_severity("High Risk - exploitable"),
            "High",
        )

    def test_trailing_descriptor_after_critical(self):
        # synthetic_fixture: true
        self.assertEqual(
            normalize_severity("Critical / direct fund loss"),
            "Critical",
        )

    def test_trailing_descriptor_after_medium_risk(self):
        # synthetic_fixture: true
        self.assertEqual(
            normalize_severity("Medium Risk (conditional)"),
            "Medium",
        )


class UnknownInputTests(unittest.TestCase):
    def test_unknown_phrase_returns_none(self):
        # synthetic_fixture: true
        self.assertIsNone(normalize_severity("Critical Bug Bonanza"))

    def test_empty_string_returns_none(self):
        self.assertIsNone(normalize_severity(""))

    def test_whitespace_only_returns_none(self):
        self.assertIsNone(normalize_severity("   "))

    def test_none_returns_none(self):
        self.assertIsNone(normalize_severity(None))

    def test_non_string_returns_none(self):
        self.assertIsNone(normalize_severity(123))
        self.assertIsNone(normalize_severity([]))


class IdPrefixInferenceTests(unittest.TestCase):
    def test_critical_prefix(self):
        self.assertEqual(infer_severity_from_id_prefix("C-1"), "Critical")

    def test_high_prefix(self):
        self.assertEqual(infer_severity_from_id_prefix("H-1"), "High")

    def test_medium_prefix(self):
        self.assertEqual(infer_severity_from_id_prefix("M-1"), "Medium")

    def test_low_prefix(self):
        self.assertEqual(infer_severity_from_id_prefix("L-1"), "Low")

    def test_informational_prefix(self):
        self.assertEqual(infer_severity_from_id_prefix("I-1"), "Informational")

    def test_note_prefix_maps_to_informational(self):
        # OZ "N-N" -> Informational
        self.assertEqual(infer_severity_from_id_prefix("N-3"), "Informational")

    def test_gas_prefix(self):
        # Cyfrin "G-N"
        self.assertEqual(infer_severity_from_id_prefix("G-5"), "Gas")

    def test_two_digit_id(self):
        self.assertEqual(infer_severity_from_id_prefix("H-11"), "High")

    def test_three_digit_id(self):
        self.assertEqual(infer_severity_from_id_prefix("M-123"), "Medium")

    def test_chainsecurity_cs_prefix_returns_none(self):
        # CS-N has no encoded tier; severity is in a separate column.
        self.assertIsNone(infer_severity_from_id_prefix("CS-1"))

    def test_unknown_prefix_returns_none(self):
        self.assertIsNone(infer_severity_from_id_prefix("ZZ-1"))

    def test_no_dash_returns_none(self):
        self.assertIsNone(infer_severity_from_id_prefix("C1"))

    def test_empty_returns_none(self):
        self.assertIsNone(infer_severity_from_id_prefix(""))

    def test_none_returns_none(self):
        self.assertIsNone(infer_severity_from_id_prefix(None))


class SeverityRankTests(unittest.TestCase):
    def test_rank_ordering_critical_highest(self):
        self.assertGreater(severity_rank("Critical"), severity_rank("High"))
        self.assertGreater(severity_rank("High"), severity_rank("Medium"))
        self.assertGreater(severity_rank("Medium"), severity_rank("Low"))
        self.assertGreater(severity_rank("Low"), severity_rank("Informational"))
        self.assertGreater(severity_rank("Informational"), severity_rank("Gas"))

    def test_rank_accepts_variant_inputs(self):
        # synthetic_fixture: true - rank should accept aliases too.
        self.assertEqual(severity_rank("Critical Risk"), SEVERITY_RANK["Critical"])
        self.assertEqual(severity_rank("Best Practice"), SEVERITY_RANK["Informational"])
        self.assertEqual(severity_rank("Gas Optimization"), SEVERITY_RANK["Gas"])

    def test_rank_unknown_returns_negative_one(self):
        self.assertEqual(severity_rank("Mysterious"), -1)
        self.assertEqual(severity_rank(None), -1)
        self.assertEqual(severity_rank(""), -1)


class IsGasFindingTests(unittest.TestCase):
    def test_canonical_gas(self):
        self.assertTrue(is_gas_finding("Gas"))

    def test_gas_optimization_alias(self):
        # synthetic_fixture: true
        self.assertTrue(is_gas_finding("Gas Optimization"))

    def test_high_is_not_gas(self):
        self.assertFalse(is_gas_finding("High"))

    def test_none_is_not_gas(self):
        self.assertFalse(is_gas_finding(None))

    def test_unknown_is_not_gas(self):
        self.assertFalse(is_gas_finding("Mysterious"))


class AliasCoverageTests(unittest.TestCase):
    """Every alias value must be a canonical severity."""

    def test_every_alias_maps_to_canonical(self):
        for raw, canonical in SEVERITY_ALIASES.items():
            with self.subTest(raw=raw):
                self.assertIn(canonical, CANONICAL_SEVERITIES)


if __name__ == "__main__":
    unittest.main()
