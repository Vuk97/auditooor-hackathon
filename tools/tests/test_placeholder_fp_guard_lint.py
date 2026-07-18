#!/usr/bin/env python3
"""Regression tests for placeholder FP-guard inventory in detector-lint.py."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_PATH = REPO_ROOT / "tools" / "detector-lint.py"


def _load_lint_module():
    spec = importlib.util.spec_from_file_location("detector_lint", LINT_PATH)
    assert spec and spec.loader, f"could not load {LINT_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PlaceholderFpGuardLintTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_lint_module()

    def test_generated_guard_placeholders_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec_dir = root / "drafts_generated"
            spec_dir.mkdir()
            spec = spec_dir / "placeholder.yaml"
            spec.write_text(
                "pattern: placeholder\n"
                "guarded_helper_name: \"_accrue\"\n"
                "guard_var_regex: \".*(balance|amount|total|supply|reserve).*\"\n"
                "guard_require_line: \"require(newVal <= 10000, \\\"cap\\\");\"\n"
            )

            hits = self.mod.placeholder_fp_guard_usages([spec_dir])

        self.assertEqual(len(hits), 3)
        self.assertEqual([hit[2] for hit in hits], [
            "guarded_helper_name",
            "guard_var_regex",
            "guard_require_line",
        ])

    def test_high_tier_placeholder_filter_only_reports_promotion_risk(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec_dir = root / "drafts_generated"
            spec_dir.mkdir()
            (spec_dir / "tier_a.yaml").write_text(
                "pattern: tier-a\n"
                "tier: A\n"
                "guarded_helper_name: \"_accrue\"\n"
            )
            (spec_dir / "tier_d.yaml").write_text(
                "pattern: tier-d\n"
                "tier: D\n"
                "guarded_helper_name: \"_accrue\"\n"
            )
            (spec_dir / "untiered.yaml").write_text(
                "pattern: untiered\n"
                "guarded_helper_name: \"_accrue\"\n"
            )

            hits = self.mod.check_placeholder_fp_guards(
                [spec_dir],
                high_tier_only=True,
            )

        self.assertEqual(len(hits), 1)
        self.assertIn("tier_a.yaml", hits[0])

    def test_specific_guards_do_not_trigger_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            spec_dir = root / "drafts_specific"
            spec_dir.mkdir()
            (spec_dir / "specific.yaml").write_text(
                "pattern: specific\n"
                "guarded_helper_name: \"nonReentrant\"\n"
                "guard_var_regex: \".*(borrowCap|ltv|oracle).*\"\n"
                "guard_require_line: \"require(newLtv <= maxLtv, \\\"ltv\\\");\"\n"
            )

            hits = self.mod.placeholder_fp_guard_usages([spec_dir])

        self.assertEqual(hits, [])

    def test_fail_closed_flag_is_opt_in(self) -> None:
        # Default lint remains advisory, while calibration burn-down lanes can
        # opt in to a non-zero exit until the placeholder cohort is resolved.
        self.mod.check_missing_fixtures = lambda: []
        self.mod.check_script_disk_mismatch = lambda: ([], [])
        self.mod.check_terse_docstrings = lambda: []
        self.mod.check_yaml_missing_fields = lambda: []
        self.mod.check_placeholder_fp_guards = (
            lambda *args, **kwargs: ["placeholder.yaml:2"]
        )
        self.mod.check_high_tier_regex_only = lambda: []
        self.mod.check_parity_gaps = lambda: []
        self.mod.check_bad_wclass = lambda: []
        self.mod.check_function_kind_unknown = lambda: []
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.mod.main([]), 0)
            self.assertEqual(self.mod.main(["--fail-placeholder-fp-guards"]), 1)

    def test_high_tier_fail_closed_flag_is_opt_in(self) -> None:
        self.mod.check_missing_fixtures = lambda: []
        self.mod.check_script_disk_mismatch = lambda: ([], [])
        self.mod.check_terse_docstrings = lambda: []
        self.mod.check_yaml_missing_fields = lambda: []

        def fake_placeholder(*args, **kwargs):
            if kwargs.get("high_tier_only"):
                return ["tier-a.yaml:3"]
            return ["tier-d.yaml:3", "tier-a.yaml:3"]

        self.mod.check_placeholder_fp_guards = fake_placeholder
        self.mod.check_high_tier_regex_only = lambda: []
        self.mod.check_parity_gaps = lambda: []
        self.mod.check_bad_wclass = lambda: []
        self.mod.check_function_kind_unknown = lambda: []
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.mod.main([]), 0)
            self.assertEqual(
                self.mod.main(["--fail-high-tier-placeholder-fp-guards"]),
                1,
            )


class HighTierRegexOnlyLintTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_lint_module()

    def test_high_tier_regex_only_pattern_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dsl_dir = Path(td)
            spec = dsl_dir / "tier-a-regex-only.yaml"
            spec.write_text(
                "pattern: tier-a-regex-only\n"
                "tier: A\n"
                "match:\n"
                "  - function.source_matches_regex: 'transferFrom|safeTransfer'\n"
                "  - function.not_source_matches_regex: '(?i)test|mock'\n"
            )

            hits = self.mod.check_high_tier_regex_only(dsl_dir)

        self.assertEqual(len(hits), 1)
        self.assertIn("tier A uses regex predicates without semantic/AST predicate", hits[0])

    def test_high_tier_with_semantic_predicate_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dsl_dir = Path(td)
            spec = dsl_dir / "tier-a-semantic.yaml"
            spec.write_text(
                "pattern: tier-a-semantic\n"
                "tier: A\n"
                "match:\n"
                "  - function.source_matches_regex: 'transferFrom|safeTransfer'\n"
                "  - function.has_high_level_call_named: 'transferFrom|safeTransfer'\n"
            )

            hits = self.mod.check_high_tier_regex_only(dsl_dir)

        self.assertEqual(hits, [])

    def test_lower_tier_regex_only_pattern_is_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dsl_dir = Path(td)
            spec = dsl_dir / "tier-d-regex-only.yaml"
            spec.write_text(
                "pattern: tier-d-regex-only\n"
                "tier: D\n"
                "match:\n"
                "  - function.body_contains_regex: 'unchecked'\n"
            )

            hits = self.mod.check_high_tier_regex_only(dsl_dir)

        self.assertEqual(hits, [])

    def test_fail_closed_flag_is_opt_in(self) -> None:
        self.mod.check_missing_fixtures = lambda: []
        self.mod.check_script_disk_mismatch = lambda: ([], [])
        self.mod.check_terse_docstrings = lambda: []
        self.mod.check_yaml_missing_fields = lambda: []
        self.mod.check_placeholder_fp_guards = lambda *args, **kwargs: []
        self.mod.check_high_tier_regex_only = lambda: ["tier-a.yaml"]
        self.mod.check_parity_gaps = lambda: []
        self.mod.check_bad_wclass = lambda: []
        self.mod.check_function_kind_unknown = lambda: []
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.mod.main([]), 0)
            self.assertEqual(self.mod.main(["--fail-high-tier-regex-only"]), 1)


if __name__ == "__main__":
    unittest.main()
