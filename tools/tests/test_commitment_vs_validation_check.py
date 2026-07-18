"""Tests for tools/commitment-vs-validation-check.py (Rule 29, Check #92).

Covers all verdict branches:
  pass-out-of-scope
  pass-not-multi-party
  pass-commitment-analysis-complete
  ok-rebuttal
  fail-no-analysis-section
  fail-no-commitment-point-citation
  fail-no-gap-class
  fail-no-protection-cardinality
  error
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "commitment_vs_validation_check",
    ROOT / "tools" / "commitment-vs-validation-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]

check = mod.check
SCHEMA_VERSION = mod.SCHEMA_VERSION
GATE = mod.GATE

FIXTURES = Path(__file__).parent / "fixtures" / "r29"


def _check(filename: str, severity: str = "auto", strict: bool = False) -> dict:
    return check(FIXTURES / filename, severity, strict)


class TestOutOfScope(unittest.TestCase):

    def test_low_severity_is_out_of_scope(self) -> None:
        r = _check("low_severity_pass.md")
        self.assertEqual(r["verdict"], "pass-out-of-scope")
        self.assertEqual(r["gate"], GATE)
        self.assertEqual(r["schema"], SCHEMA_VERSION)

    def test_medium_severity_is_out_of_scope(self) -> None:
        r = _check("medium_severity_out_of_scope.md")
        self.assertEqual(r["verdict"], "pass-out-of-scope")

    def test_low_severity_cli_override(self) -> None:
        # Even with cooperative-exit trigger, LOW should pass out-of-scope
        r = _check("cooperative_exit_no_analysis_fail.md", severity="low")
        self.assertEqual(r["verdict"], "pass-out-of-scope")


class TestNotMultiParty(unittest.TestCase):

    def test_single_party_reentrancy_passes(self) -> None:
        r = _check("no_multi_party_pass.md")
        self.assertEqual(r["verdict"], "pass-not-multi-party")

    def test_high_severity_no_trigger_phrases_passes(self) -> None:
        r = _check("no_multi_party_pass.md", severity="high")
        self.assertEqual(r["verdict"], "pass-not-multi-party")


class TestRebuttal(unittest.TestCase):

    def test_valid_rebuttal_accepted(self) -> None:
        r = _check("r29_rebuttal_override.md")
        self.assertEqual(r["verdict"], "ok-rebuttal")
        self.assertIn("r29-rebuttal accepted", r["reason"])

    def test_empty_rebuttal_is_not_accepted(self) -> None:
        """Empty reason -> rebuttal ignored -> falls through to fail verdict."""
        r = _check("rebuttal_empty_reason_fail.md")
        self.assertTrue(r["verdict"].startswith("fail"), msg=f"Got: {r['verdict']}")


class TestPassComplete(unittest.TestCase):

    def test_spark_lead1_v8_complete_pass(self) -> None:
        r = _check("spark_lead1_v8_pass.md")
        self.assertEqual(r["verdict"], "pass-commitment-analysis-complete")
        self.assertTrue(r.get("commitment_point_found"))
        self.assertTrue(r.get("gap_class_found"))
        self.assertTrue(r.get("protection_cardinality_found"))

    def test_atomic_swap_all_fields_pass(self) -> None:
        r = _check("all_three_fields_complete_pass.md")
        self.assertEqual(r["verdict"], "pass-commitment-analysis-complete")


class TestFailNoAnalysisSection(unittest.TestCase):

    def test_coop_exit_no_section_fails(self) -> None:
        r = _check("cooperative_exit_no_analysis_fail.md")
        self.assertEqual(r["verdict"], "fail-no-analysis-section")

    def test_empty_analysis_body_fails_commitment_point(self) -> None:
        """Section present but empty - should fail on missing file:line."""
        r = _check("fail_analysis_section_empty.md")
        # Section is present but has no file:line -> fail-no-commitment-point-citation
        self.assertEqual(r["verdict"], "fail-no-commitment-point-citation")


class TestFailNoCommitmentPoint(unittest.TestCase):

    def test_section_present_but_no_fileline_fails(self) -> None:
        r = _check("fail_no_commitment_point.md")
        self.assertEqual(r["verdict"], "fail-no-commitment-point-citation")


class TestFailNoGapClass(unittest.TestCase):

    def test_missing_gap_class_fails(self) -> None:
        r = _check("fail_no_gap_class.md")
        self.assertEqual(r["verdict"], "fail-no-gap-class")

    def test_partial_analysis_only_field_a_fails(self) -> None:
        """Only field (a) present; (b) and (c) missing -> fail on gap class."""
        r = _check("fail_partial_analysis_missing_bc.md")
        self.assertEqual(r["verdict"], "fail-no-gap-class")


class TestFailNoProtectionCardinality(unittest.TestCase):

    def test_missing_cardinality_fails(self) -> None:
        r = _check("fail_no_protection_cardinality.md")
        self.assertEqual(r["verdict"], "fail-no-protection-cardinality")


class TestStrictMode(unittest.TestCase):

    def test_strict_mode_still_returns_fail_verdict(self) -> None:
        r = _check("cooperative_exit_no_analysis_fail.md", strict=True)
        self.assertEqual(r["verdict"], "fail-no-analysis-section")
        self.assertTrue(r.get("strict"))


class TestError(unittest.TestCase):

    def test_nonexistent_file_returns_error(self) -> None:
        r = check(Path("/nonexistent/path/draft.md"), "auto", False)
        self.assertEqual(r["verdict"], "error")
        self.assertEqual(r["gate"], GATE)


if __name__ == "__main__":
    unittest.main()
