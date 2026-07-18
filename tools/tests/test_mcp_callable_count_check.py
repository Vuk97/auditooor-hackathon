"""Tests for tools/mcp-callable-count-check.py (Phase NEG-H, 2026-05-23).

Covers:
  - live_callable_count() returns >=80 (sanity-floor)
  - extract_claims() parses canonical claim shapes
  - extract_claims() ignores subset claims (<30)
  - extract_claims() ignores out-of-range non-callable numbers
  - check_doc() returns pass when claim matches live count
  - check_doc() returns fail-drift when claim disagrees
  - Layer-1 callable docs cannot reference names missing from TOOL_SCHEMAS
  - CLI exits non-zero on expected-count drift
  - make mcp-callable-count-check propagates failure
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "mcp-callable-count-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "mcp_callable_count_check", TOOL
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestExtractClaims(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "doc.md"

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, text: str):
        self.path.write_text(textwrap.dedent(text), encoding="utf-8")

    def test_canonical_layer_total(self):
        self._write(
            """
            **Status**: server ships **94 callables total** (12 Layer-1 + 82 Layer-2).
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0][1], 94)

    def test_double_star_then_callables_total(self):
        self._write(
            """
            server callable count: **94** total (12 Layer-1 + 82 Layer-2 callables)
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0][1], 94)

    def test_total_callables_documented(self):
        self._write(
            """
            Total callables documented: **66** (every entry in the live `TOOL_SCHEMAS` list).
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0][1], 66)

    def test_schema_count_appendix(self):
        self._write(
            """
            ## Appendix F: Generation provenance
            - Schema count: **94** (every entry in `TOOL_SCHEMAS`)
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0][1], 94)

    def test_n_callables_catch_all(self):
        self._write(
            """
            Use case: not sure which of the 94 callables fits.
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0][1], 94)

    def test_ignores_subset_claim_4_callables(self):
        # The pr-658 SKILL "4 callables" subset claim is below the 30-floor.
        self._write(
            """
            MCP recall (4 callables) -> dynamic lane derivation
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(claims, [])

    def test_ignores_unrelated_high_numbers(self):
        # "Check #94" is a pre-submit-check ID, not a callable count.
        self._write(
            """
            Hard gate: pre-submit-check.sh Check #94 (R29-COMMITMENT-VS-VALIDATION-GAP).
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(claims, [])

    def test_ignores_pr_number(self):
        self._write(
            """
            See PR #94 for the historical context.
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(claims, [])

    def test_missing_file(self):
        # File was never written by this test - path does not exist.
        self.assertFalse(self.path.exists())
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(claims, [])

    def test_multiple_lines_distinct_counts(self):
        self._write(
            """
            Total callables documented: **94**.
            Subset claim that should be ignored: 4 callables.
            Schema count: **94** (every entry in TOOL_SCHEMAS).
            """
        )
        claims = self.mod.extract_claims(self.path)
        self.assertEqual(len(claims), 2)
        self.assertEqual({c[1] for c in claims}, {94})

    def test_extract_layer1_callables(self):
        self._write(
            """
            **Overview**: complementary to LAYER_1 (`vault_resume_context`, `vault_goal_state`).
            """
        )
        refs = self.mod.extract_layer1_callables(self.path)
        self.assertEqual(
            refs,
            [(2, "vault_resume_context"), (2, "vault_goal_state")],
        )


class TestCheckDoc(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "doc.md"

    def tearDown(self):
        self.tmp.cleanup()

    def test_pass_all_claims_match(self):
        self.path.write_text(
            "Total callables documented: **94** (live TOOL_SCHEMAS).\n",
            encoding="utf-8",
        )
        verdict = self.mod.check_doc(self.path, 94, "test-doc")
        self.assertEqual(verdict["verdict"], "pass-all-claims-match")

    def test_fail_drift(self):
        self.path.write_text(
            "Total callables documented: **66** (live TOOL_SCHEMAS).\n",
            encoding="utf-8",
        )
        verdict = self.mod.check_doc(self.path, 94, "test-doc")
        self.assertEqual(verdict["verdict"], "fail-drift")
        self.assertEqual(len(verdict["mismatches"]), 1)
        self.assertEqual(verdict["mismatches"][0]["claimed"], 66)

    def test_skip_missing(self):
        # File was never written by this test - path does not exist.
        self.assertFalse(self.path.exists())
        verdict = self.mod.check_doc(self.path, 94, "test-doc")
        self.assertEqual(verdict["verdict"], "skip-missing")

    def test_skip_no_claim(self):
        self.path.write_text(
            "This doc has no callable-count claim at all.\n",
            encoding="utf-8",
        )
        verdict = self.mod.check_doc(self.path, 94, "test-doc")
        self.assertEqual(verdict["verdict"], "skip-no-claim-found")

    def test_layer1_schema_refs_pass_when_all_live(self):
        self.path.write_text(
            "**Overview**: complementary to LAYER_1 (`vault_resume_context`, `vault_goal_state`).\n",
            encoding="utf-8",
        )
        verdict = self.mod.check_layer1_schema_refs(
            self.path,
            ["vault_goal_state", "vault_resume_context"],
        )
        self.assertEqual(verdict["verdict"], "pass-all-callables-live")
        self.assertEqual(verdict["missing"], [])

    def test_layer1_schema_refs_fail_on_missing_callable(self):
        self.path.write_text(
            "**Overview**: complementary to LAYER_1 (`vault_resume_context`, `vault_parity_precedent`).\n",
            encoding="utf-8",
        )
        verdict = self.mod.check_layer1_schema_refs(
            self.path,
            ["vault_resume_context"],
        )
        self.assertEqual(verdict["verdict"], "fail-missing-callable")
        self.assertEqual(
            verdict["missing"],
            [{"line": 1, "callable": "vault_parity_precedent"}],
        )


class TestLiveCallableCount(unittest.TestCase):
    """Smoke test: live server should report >=80 callables."""

    def test_live_count_sanity_floor(self):
        mod = _load_module()
        try:
            count, names = mod.live_callable_count()
        except SystemExit as e:
            self.fail(f"live_callable_count raised SystemExit: {e}")
        self.assertGreaterEqual(count, 80)
        self.assertEqual(count, len(names))
        self.assertEqual(sorted(names), names)  # alphabetic-sorted contract


class TestCLI(unittest.TestCase):
    def test_strict_mode_passes_on_real_repo(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"strict mode should pass on real repo; stdout={proc.stdout[:500]}",
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.mcp_callable_count_check.v1")
        self.assertEqual(payload["overall"], "pass")
        self.assertTrue(payload["live_count_matches_expected"])

    def test_expected_count_mismatch_fails(self):
        baseline = subprocess.run(
            [sys.executable, str(TOOL), "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        live_count = json.loads(baseline.stdout)["live_count"]

        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--expected-count",
                str(live_count + 1),
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["overall"], "fail")
        self.assertFalse(payload["live_count_matches_expected"])

    def test_make_target_hard_fails_on_expected_count_mismatch(self):
        baseline = subprocess.run(
            [sys.executable, str(TOOL), "--json"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        live_count = json.loads(baseline.stdout)["live_count"]

        proc = subprocess.run(
            [
                "make",
                "-s",
                "mcp-callable-count-check",
                f"MCP_CALLABLE_EXPECTED_COUNT={live_count + 1}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(REPO_ROOT),
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("FAIL expected live count", proc.stdout)


if __name__ == "__main__":
    unittest.main()
