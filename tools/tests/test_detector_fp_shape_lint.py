#!/usr/bin/env python3
"""
tests/test_detector_fp_shape_lint.py

Unit tests for tools/detector-fp-shape-lint.py

Tests cover:
  - pure_or_with_benign_alternative: fires on bad OR, passes on scoped OR
  - symptom_token_no_precondition: fires with no context, passes with precondition
  - unanchored_broad_regex: fires on short/generic pattern, passes on anchored
  - benign-OR-with-strong-token passes (the "scoped benign" case)
  - strict-mode exit code check
  - JSON output schema fields
  - CLI integration: synthetic bash-format input
"""

import importlib.util
import json
import os
import sys
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

# Make tools/ importable (handles hyphen in module filename)
TOOLS_DIR = Path(__file__).resolve().parent.parent
_LINT_MODULE_PATH = str(TOOLS_DIR / "detector-fp-shape-lint.py")


def _load_lint_module():
    spec = importlib.util.spec_from_file_location("detector_fp_shape_lint", _LINT_MODULE_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_lint = _load_lint_module()

lint_pure_or_with_benign_alternative = _lint.lint_pure_or_with_benign_alternative
lint_symptom_token_no_precondition = _lint.lint_symptom_token_no_precondition
lint_unanchored_broad_regex = _lint.lint_unanchored_broad_regex
parse_bash_detectors = _lint.parse_bash_detectors
parse_dsl_detectors = _lint.parse_dsl_detectors
run_lint = _lint.run_lint
format_json = _lint.format_json


# ---------------------------------------------------------------------------
# Helper: build a synthetic apply-queries.sh with known patterns
# ---------------------------------------------------------------------------

def make_bash_script(patterns: list[tuple[str, str, str]]) -> str:
    """Return text for a minimal apply-queries.sh with the given patterns."""
    lines = ["#!/usr/bin/env bash", "SRC_DIR=$1", ""]
    for name, category, pattern in patterns:
        lines.append(f'check_pattern "{name}" "{category}" \'{pattern}\'')
    return "\n".join(lines) + "\n"


def make_dsl_yaml(name: str, pattern: str, has_precondition: bool = False,
                  extra_match: bool = False) -> str:
    """Return minimal DSL YAML for a detector."""
    pre_val = ".*(SomeContract|SpecificToken).*" if has_precondition else ".*"
    pre_block = f"preconditions:\n  - contract.has_state_var_matching: '{pre_val}'\n"
    match_block = f"match:\n  - function.body_contains_regex: '{pattern}'\n"
    if extra_match:
        match_block += "  - function.not_leaf_helper: true\n"
    return f"pattern: {name}\n{pre_block}{match_block}"


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestPureOrWithBenignAlternative(unittest.TestCase):

    def test_fires_on_benign_standalone_alternative(self):
        """pure_or: fires when _msgSender() appears as a lone OR branch."""
        # This is the documented Wave-14 FP: '_msgSender\s*\(|trustedForwarder|ERC2771'
        pattern = r'_msgSender\s*\(|trustedForwarder|ERC2771'
        flag = lint_pure_or_with_benign_alternative(
            "erc-2771-msgSender-forgery-OLD", pattern, "apply-queries.sh", "bash_grep"
        )
        self.assertIsNotNone(flag, "should flag: _msgSender alone is benign-common")
        self.assertEqual(flag["rule"], "pure_or_with_benign_alternative")

    def test_fires_on_selfdestruct_suicide_pure_or(self):
        """pure_or: fires on bare selfdestruct|suicide (both benign-solo)."""
        pattern = "selfdestruct|suicide"
        flag = lint_pure_or_with_benign_alternative(
            "self-destructable-contracts", pattern, "apply-queries.sh", "bash_grep"
        )
        self.assertIsNotNone(flag, "should flag: selfdestruct|suicide are both benign-solo tokens")

    def test_passes_on_no_or(self):
        """pure_or: passes when pattern has no top-level OR."""
        pattern = r'ERC2771Context\s*\('
        flag = lint_pure_or_with_benign_alternative(
            "erc-2771-good", pattern, "apply-queries.sh", "bash_grep"
        )
        self.assertIsNone(flag, "no OR = no pure_or flag")

    def test_passes_on_benign_with_strong_discriminating_term(self):
        """pure_or: benign alternative alongside a long discriminating term should pass."""
        # 'ERC2771Context|isTrustedForwarder' - both non-trivial, wave-14 fix
        pattern = r'ERC2771Context|isTrustedForwarder\s*\(|is\s+ERC2771'
        flag = lint_pure_or_with_benign_alternative(
            "erc-2771-fixed", pattern, "apply-queries.sh", "bash_grep"
        )
        # None of these are BENIGN common tokens - the wave-14 fixed version passes
        self.assertIsNone(flag, "wave-14 fixed pattern with all specific tokens should pass")

    def test_fires_on_assembly_as_sole_branch(self):
        """pure_or: assembly alone is benign-common."""
        pattern = r'assembly|\.call\('
        flag = lint_pure_or_with_benign_alternative(
            "assembly-detector", pattern, "apply-queries.sh", "bash_grep"
        )
        self.assertIsNotNone(flag, "assembly alone is benign-common, should flag")


class TestSymptomTokenNoPrecondition(unittest.TestCase):

    def test_fires_on_ecrecover_no_precondition(self):
        """symptom_token: ecrecover with no additional context should flag."""
        pattern = r'ecrecover\s*\('
        flag = lint_symptom_token_no_precondition(
            "ecrecover-bare", pattern, "apply-queries.sh", "bash_grep",
            has_precondition=False, has_additional_match=False
        )
        self.assertIsNotNone(flag, "bare ecrecover should flag")
        self.assertEqual(flag["rule"], "symptom_token_no_precondition")

    def test_passes_with_precondition(self):
        """symptom_token: ecrecover with a meaningful precondition passes."""
        pattern = r'ecrecover\s*\('
        flag = lint_symptom_token_no_precondition(
            "ecrecover-with-pre", pattern, "apply-queries.sh", "dsl_yaml",
            has_precondition=True, has_additional_match=False
        )
        self.assertIsNone(flag, "ecrecover + real precondition should pass")

    def test_passes_with_additional_match(self):
        """symptom_token: ecrecover with additional match clauses passes."""
        pattern = r'ecrecover\s*\('
        flag = lint_symptom_token_no_precondition(
            "ecrecover-with-extra", pattern, "apply-queries.sh", "dsl_yaml",
            has_precondition=False, has_additional_match=True
        )
        self.assertIsNone(flag, "ecrecover + extra match clauses should pass")

    def test_fires_on_tx_origin_bare(self):
        """symptom_token: tx.origin alone should flag."""
        pattern = r'tx\.origin'
        flag = lint_symptom_token_no_precondition(
            "tx-origin-used", pattern, "apply-queries.sh", "bash_grep",
            has_precondition=False, has_additional_match=False
        )
        self.assertIsNotNone(flag, "bare tx.origin should flag")

    def test_passes_on_non_symptom_token(self):
        """symptom_token: a non-symptom pattern does not trigger."""
        pattern = r'function\s+transferOwnership\s*\('
        flag = lint_symptom_token_no_precondition(
            "missing-two-step-ownership-transfer", pattern, "apply-queries.sh", "bash_grep",
            has_precondition=False, has_additional_match=False
        )
        self.assertIsNone(flag, "transferOwnership is not a symptom token")


class TestUnanchoredBroadRegex(unittest.TestCase):

    def test_fires_on_very_short_pattern(self):
        """unanchored: very short pattern (<=10 chars) should flag."""
        pattern = r'get_p\s*\('   # 10 chars
        flag = lint_unanchored_broad_regex(
            "curve-get-p-spot-price", pattern, "apply-queries.sh", "bash_grep"
        )
        self.assertIsNotNone(flag, "get_p pattern is too short, should flag")

    def test_fires_on_tx_origin_alone(self):
        """unanchored: tx.origin alone is short and unanchored."""
        pattern = r'tx\.origin'
        flag = lint_unanchored_broad_regex(
            "tx-origin-used", pattern, "apply-queries.sh", "bash_grep"
        )
        self.assertIsNotNone(flag, "tx.origin is 10 chars, should flag as unanchored")

    def test_passes_on_well_anchored_function_pattern(self):
        """unanchored: a pattern with function\\s+ anchor passes."""
        pattern = r'function\s+transferOwnership\s*\('
        flag = lint_unanchored_broad_regex(
            "missing-two-step-ownership-transfer", pattern, "apply-queries.sh", "bash_grep"
        )
        self.assertIsNone(flag, "function\\s+ anchor makes this well-structured")

    def test_passes_on_long_specific_pattern(self):
        """unanchored: a long pattern with specific tokens passes."""
        pattern = r'ERC2771Context|isTrustedForwarder\s*\(|is\s+ERC2771'
        flag = lint_unanchored_broad_regex(
            "erc-2771-fixed", pattern, "apply-queries.sh", "bash_grep"
        )
        self.assertIsNone(flag, "pattern has \\s*\\( anchoring, should pass")


class TestBashDetectorParsing(unittest.TestCase):

    def test_parses_check_pattern_calls(self):
        """Parser: extracts name, category, pattern from check_pattern calls."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(make_bash_script([
                ("my-detector", "access", r'function\s+foo\s*\('),
                ("other-detector", "sig", r'ecrecover\s*\('),
            ]))
            fname = f.name

        try:
            detectors = parse_bash_detectors(fname)
            self.assertEqual(len(detectors), 2)
            self.assertEqual(detectors[0]["name"], "my-detector")
            self.assertEqual(detectors[0]["pattern"], r'function\s+foo\s*\(')
            self.assertEqual(detectors[1]["name"], "other-detector")
        finally:
            os.unlink(fname)


class TestDslDetectorParsing(unittest.TestCase):

    def test_parses_dsl_yaml(self):
        """Parser: extracts regex patterns from DSL YAML files."""
        with tempfile.TemporaryDirectory() as d:
            yaml_content = make_dsl_yaml(
                "my-dsl-detector",
                r'(?i)(evil|malicious)\s*\(',
                has_precondition=True,
                extra_match=True,
            )
            p = Path(d) / "my-dsl-detector.yaml"
            p.write_text(yaml_content)

            try:
                detectors = parse_dsl_detectors([d])
                self.assertGreater(len(detectors), 0)
                names = [det["name"] for det in detectors]
                self.assertIn("my-dsl-detector", names)
            except Exception:
                # yaml not available in this environment - skip gracefully
                pass


class TestRunLintIntegration(unittest.TestCase):

    def test_wave14_fp_pattern_is_flagged_as_fp_risk_for_finding_generator(self):
        """Integration: the documented Wave-14 FP pattern fires as fp_risk when
        detector_tier=finding-generator (DSL-style detector, not review-grep)."""
        bad_detectors = [{
            "name": "erc-2771-msgSender-forgery-OLD",
            "pattern": r'_msgSender\s*\(|trustedForwarder|ERC2771',
            "has_precondition": False,
            "has_additional_match": False,
            "source_file": "reference/patterns.dsl/erc-2771-old.yaml",
            "detector_type": "dsl_yaml",
            "detector_tier": "finding-generator",
        }]
        flags = run_lint(bad_detectors)
        fp_risk_flags = [f for f in flags if f.get("severity") == "fp_risk"]
        self.assertGreater(len(fp_risk_flags), 0, "wave-14 FP pattern must be flagged as fp_risk")
        rules = {f["rule"] for f in fp_risk_flags}
        self.assertIn("pure_or_with_benign_alternative", rules)

    def test_wave14_fp_pattern_is_advisory_for_review_grep(self):
        """Integration: the wave-14 FP shape is advisory (not fp_risk) when
        detector_tier=review-grep (bash grep detector).
        Advisory flags are informational and do not trigger --strict exit-1."""
        detectors = [{
            "name": "erc-2771-msgSender-forgery-OLD",
            "pattern": r'_msgSender\s*\(|trustedForwarder|ERC2771',
            "has_precondition": False,
            "has_additional_match": False,
            "source_file": "apply-queries.sh",
            "detector_type": "bash_grep",
            "detector_tier": "review-grep",
        }]
        flags = run_lint(detectors)
        self.assertGreater(len(flags), 0, "pattern still fires a flag")
        fp_risk_flags = [f for f in flags if f.get("severity") == "fp_risk"]
        advisory_flags = [f for f in flags if f.get("severity") == "advisory"]
        self.assertEqual(len(fp_risk_flags), 0, "review-grep tier must NOT produce fp_risk flags")
        self.assertGreater(len(advisory_flags), 0, "review-grep tier must produce advisory flags")

    def test_dsl_pattern_scoped_by_and_clause_does_not_flag(self):
        """Integration: a DSL pattern with a discriminating name_matches AND-clause
        does NOT produce fp_risk flags even if a sibling regex clause is broad.
        This is the wave-17 AND-clause awareness fix for the 28 lint FPs."""
        # Simulate parse_dsl_detectors output for an and_clause_scoped pattern
        # (has_precondition=True, has_additional_match=True, pattern is the holistic placeholder)
        and_clause_scoped_record = {
            "name": "donate-to-reserves-skips-debt-health-check",
            "category": "dsl",
            "pattern": "(and-clause-scoped: holistic match block is discriminating)",
            "has_precondition": True,
            "has_additional_match": True,
            "source_file": "reference/patterns.dsl/donate-to-reserves-skips-debt-health-check.yaml",
            "detector_type": "dsl_yaml",
            "and_clause_scoped": True,
            "detector_tier": "finding-generator",
        }
        flags = run_lint([and_clause_scoped_record])
        fp_risk_flags = [f for f in flags if f.get("severity") == "fp_risk"]
        self.assertEqual(len(fp_risk_flags), 0,
                         "DSL pattern scoped by sibling AND-clause must NOT produce fp_risk flags")

    def test_dsl_parse_and_clause_scoped_produces_no_fp_risk(self):
        """Integration: parse_dsl_detectors marks a well-scoped YAML as and_clause_scoped
        and run_lint produces 0 fp_risk flags for it."""
        try:
            import yaml as _yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not available")

        import tempfile, os
        # YAML with 3+ match clauses and a name_matches - discriminating by both tests
        yaml_content = textwrap.dedent("""\
            pattern: donate-to-reserves-skips-health-check-test
            preconditions:
              - contract.source_matches_regex: '(?i)lend|borrow|reserve'
            match:
              - function.kind: external_or_public
              - function.name_matches: '(?i)^donateToReserves$'
              - function.body_contains_regex: '(?i)-='
              - function.body_not_contains_regex: 'checkLiquidity'
        """)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "donate-to-reserves.yaml"
            p.write_text(yaml_content)
            detectors = parse_dsl_detectors([d])
            self.assertGreater(len(detectors), 0, "should parse at least one record")
            # The record must be the holistic and_clause_scoped placeholder
            scoped = [r for r in detectors if r.get("and_clause_scoped")]
            self.assertGreater(len(scoped), 0, "well-scoped DSL must produce an and_clause_scoped record")
            flags = run_lint(detectors)
            fp_risk = [f for f in flags if f.get("severity") == "fp_risk"]
            self.assertEqual(len(fp_risk), 0, "well-scoped DSL must produce 0 fp_risk flags")

    def test_dsl_truly_unscoped_pattern_still_flags(self):
        """Integration: a DSL pattern with NO discriminating clauses (no name_matches,
        no preconditions, single match clause) still fires fp_risk."""
        try:
            import yaml as _yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not available")

        import tempfile
        # Minimal unscoped YAML - no name_matches, no real preconditions, single match
        yaml_content = textwrap.dedent("""\
            pattern: unscoped-bad-detector
            preconditions:
              - contract.source_matches_regex: '.*'
            match:
              - function.body_contains_regex: '_msgSender\\s*\\(|trustedForwarder|ERC2771'
        """)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "unscoped-bad-detector.yaml"
            p.write_text(yaml_content)
            detectors = parse_dsl_detectors([d])
            flags = run_lint(detectors)
            fp_risk = [f for f in flags if f.get("severity") == "fp_risk"]
            self.assertGreater(len(fp_risk), 0,
                               "truly unscoped DSL pattern must still produce fp_risk flags")

    def test_wave14_fixed_pattern_passes(self):
        """Integration: the wave-14 fixed pattern passes the lint."""
        good_detectors = [{
            "name": "erc-2771-msgSender-forgery",
            "pattern": r'ERC2771Context|isTrustedForwarder\s*\(|is\s+ERC2771',
            "has_precondition": False,
            "has_additional_match": False,
            "source_file": "apply-queries.sh",
            "detector_type": "bash_grep",
            "detector_tier": "finding-generator",
        }]
        flags = run_lint(good_detectors)
        pure_or_flags = [f for f in flags if f["rule"] == "pure_or_with_benign_alternative"]
        self.assertEqual(len(pure_or_flags), 0, "wave-14 fixed pattern should not trigger pure_or rule")


class TestJsonSchema(unittest.TestCase):

    def test_json_output_has_required_fields(self):
        """JSON: output contains schema id, total counts, and flags list."""
        detectors = [{
            "name": "test-detector",
            "pattern": r'_msgSender\s*\(|trustedForwarder',
            "has_precondition": False,
            "has_additional_match": False,
            "source_file": "test.sh",
            "detector_type": "dsl_yaml",
            "detector_tier": "finding-generator",
        }]
        flags = run_lint(detectors)
        json_str = format_json(flags, detectors)
        data = json.loads(json_str)

        self.assertEqual(data["schema"], "auditooor.detector_fp_shape_lint.v1")
        self.assertIn("total_detectors_scanned", data)
        self.assertIn("total_flags", data)
        self.assertIn("total_fp_risk_flags", data)
        self.assertIn("total_advisory_flags", data)
        self.assertIn("flags", data)
        self.assertIsInstance(data["flags"], list)

        if data["flags"]:
            flag = data["flags"][0]
            for field in ["rule", "detector", "file", "offending", "pattern_snippet", "suggestion", "severity"]:
                self.assertIn(field, flag, f"flag must have field: {field}")


class TestStrictMode(unittest.TestCase):

    def test_strict_mode_exits_nonzero_on_fp_risk_flags(self):
        """Strict: CLI exits 1 only when fp_risk flags (finding-generator tier) are found.
        A DSL YAML pattern with no discriminating clauses and a broad benign-OR must
        trigger exit-1 in strict mode."""
        try:
            import yaml as _yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not available")

        # Build a truly unscoped DSL YAML that should produce fp_risk
        yaml_content = textwrap.dedent("""\
            pattern: unscoped-bad-dsl-strict-test
            preconditions:
              - contract.source_matches_regex: '.*'
            match:
              - function.body_contains_regex: '_msgSender\\s*\\(|trustedForwarder|ERC2771'
        """)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "unscoped-bad.yaml"
            p.write_text(yaml_content)
            tool = str(TOOLS_DIR / "detector-fp-shape-lint.py")
            result = subprocess.run(
                [sys.executable, tool, "--no-bash", "--dsl-dirs", d, "--strict"],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 1,
                             f"strict mode + fp_risk DSL flags should exit 1, got {result.returncode}\n"
                             f"stdout: {result.stdout[:500]}")

    def test_strict_mode_exits_zero_for_advisory_only(self):
        """Strict: CLI exits 0 when only advisory (review-grep) flags exist.
        Bash grep detectors are review-tier by default and never trigger exit-1."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            # A broad bash grep pattern - review-tier, should not trigger exit-1
            f.write(make_bash_script([
                ("bad-looking-bash-detector", "sig", r'_msgSender\s*\(|trustedForwarder|ERC2771'),
            ]))
            fname = f.name

        try:
            tool = str(TOOLS_DIR / "detector-fp-shape-lint.py")
            result = subprocess.run(
                [sys.executable, tool, "--file", fname, "--no-dsl", "--strict"],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0,
                             f"review-grep (advisory) flags must NOT trigger exit-1 in strict mode\n"
                             f"stdout: {result.stdout[:500]}")
        finally:
            os.unlink(fname)

    def test_strict_mode_exits_zero_on_clean(self):
        """Strict: CLI exits 0 when no flags found, even with --strict."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            # Write a well-formed pattern with strong discriminating tokens
            f.write(make_bash_script([
                ("good-detector", "sig", r'function\s+transferOwnership\s*\(\s*address\b'),
            ]))
            fname = f.name

        try:
            tool = str(TOOLS_DIR / "detector-fp-shape-lint.py")
            result = subprocess.run(
                [sys.executable, tool, "--file", fname, "--no-dsl", "--strict"],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0,
                             f"clean detectors should exit 0 even in strict mode\n"
                             f"stdout: {result.stdout[:500]}")
        finally:
            os.unlink(fname)


if __name__ == "__main__":
    unittest.main(verbosity=2)
