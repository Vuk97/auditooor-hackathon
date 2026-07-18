#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION declared 10 files via tools/agent-pathspec-register.py at lane start
"""Regression coverage for tools/r64-prompt-claim-verifier.py.

Covers:
- Claim extraction matrix (tool paths, MCP callables, Check #N, R-rule,
  schemas, make targets, record counts)
- Rebuttal detection (HTML comment + visible line forms)
- Verdict vocabulary (pass-no-claims / pass-all-verified / ok-rebuttal /
  fail-prompt-contains-unverified-claim)
- record-count claim parsing ('10K Cantina rationales' anchor)
- CLI: --json, --strict, stdin, --workspace, exit codes
- Synthetic-hallucinated prompt vs canonical-real prompt
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_THIS = Path(__file__).resolve().parent
_REPO = _THIS.parent.parent
_TOOL_PATH = _REPO / "tools" / "r64-prompt-claim-verifier.py"
_INV_PATH = _REPO / "tools" / "canonical-inventory.py"

# Import as a module
_spec = importlib.util.spec_from_file_location("r64_verifier", _TOOL_PATH)
r64 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r64)


class TestClaimExtraction(unittest.TestCase):
    def test_extract_tool_path(self):
        claims = r64.extract_claims("Run tools/foo.py to check things.")
        kinds = [c["kind_hint"] for c in claims]
        self.assertIn("tool-path", kinds)
        paths = [c["claim"] for c in claims if c["kind_hint"] == "tool-path"]
        self.assertIn("tools/foo.py", paths)

    def test_extract_mcp_callable(self):
        claims = r64.extract_claims("Call vault_resume_context first.")
        names = [c["claim"] for c in claims if c["kind_hint"] == "mcp-callable"]
        self.assertIn("vault_resume_context", names)

    def test_extract_check_number(self):
        claims = r64.extract_claims("Run Check #99 against the draft.")
        nums = [c["claim"] for c in claims if c["kind_hint"] == "check"]
        self.assertIn("Check #99", nums)

    def test_extract_r_rule(self):
        claims = r64.extract_claims("Apply R52 to verify rubric coverage.")
        rules = [c["claim"] for c in claims if c["kind_hint"] == "r-rule"]
        self.assertIn("R52", rules)

    def test_extract_schema(self):
        claims = r64.extract_claims("Schema is auditooor.canonical_inventory.v1.")
        schemas = [c["claim"] for c in claims if c["kind_hint"] == "schema"]
        self.assertIn("auditooor.canonical_inventory.v1", schemas)

    def test_extract_make_target(self):
        claims = r64.extract_claims("Then run make audit-fast for top-30.")
        targets = [c["claim"] for c in claims if c["kind_hint"] == "makefile"]
        self.assertIn("make audit-fast", targets)

    def test_extract_record_count_with_k_suffix(self):
        # Anchor: TOK-A "10K Cantina rationales"
        claims = r64.extract_claims("mine 10K Cantina rationales from prior_audits")
        counts = [c["claim"] for c in claims if c["kind_hint"] == "record-count"]
        # The extractor normalises to "10K Cantina"
        self.assertTrue(any("Cantina" in c.lower() or "cantina" in c.lower()
                            for c in counts))

    def test_extract_record_count_with_comma(self):
        claims = r64.extract_claims("Total: 5,000 findings across the corpus.")
        counts = [c["claim"] for c in claims if c["kind_hint"] == "record-count"]
        self.assertTrue(any("findings" in c for c in counts))

    def test_extract_dedupes_same_claim(self):
        text = "vault_resume_context, again vault_resume_context, and once more vault_resume_context"
        claims = r64.extract_claims(text)
        names = [c["claim"] for c in claims if c["kind_hint"] == "mcp-callable"]
        self.assertEqual(len(names), 1)

    def test_empty_prompt_no_claims(self):
        claims = r64.extract_claims("Hello world, nothing technical here.")
        # 'world' should not match anything; the recipes are designed to skip
        # plain prose. Allow possible false-positives but at least the count
        # should be small.
        self.assertLess(len(claims), 3)


class TestRebuttalDetection(unittest.TestCase):
    def test_html_comment_rebuttal(self):
        text = "Some prompt body <!-- r64-rebuttal: operator-approved 10K target -->"
        self.assertEqual(
            r64.detect_rebuttal(text),
            "operator-approved 10K target",
        )

    def test_visible_line_rebuttal(self):
        text = "Some prompt body\nr64-rebuttal: synthetic claim for fixture testing\nmore"
        result = r64.detect_rebuttal(text)
        self.assertIn("synthetic", result)

    def test_no_rebuttal(self):
        self.assertEqual(r64.detect_rebuttal("Plain body"), "")

    def test_empty_rebuttal_ignored(self):
        # Empty reason should be ignored even though the marker is present
        text = "<!-- r64-rebuttal:   -->"
        self.assertEqual(r64.detect_rebuttal(text), "")


class TestRecordCountParser(unittest.TestCase):
    def test_parse_10k(self):
        self.assertEqual(r64._parse_count_claim("10K cantina"), 10000)

    def test_parse_comma(self):
        self.assertEqual(r64._parse_count_claim("5,000 findings"), 5000)

    def test_parse_bare_int(self):
        self.assertEqual(r64._parse_count_claim("200 records"), 200)

    def test_parse_invalid(self):
        self.assertIsNone(r64._parse_count_claim("many records"))


class TestVerifyPrompt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import canonical-inventory for snapshot generation.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "canonical_inventory_for_test", _INV_PATH,
        )
        cls.ci = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.ci)
        cls.snap = cls.ci.build_snapshot(
            _REPO,
            audits_root=Path("/tmp/nonexistent_audits"),
        )

    def test_pass_no_claims_empty_prompt(self):
        result = r64.verify_prompt("Hello world, nothing technical here.", self.snap)
        # May extract zero or near-zero claims
        self.assertIn(result["overall_verdict"],
                      ("pass-no-claims", "pass-all-verified"))

    def test_pass_all_verified_real_claims(self):
        text = (
            "Run vault_resume_context then "
            "tools/canonical-inventory.py and check R52."
        )
        result = r64.verify_prompt(text, self.snap)
        self.assertEqual(result["overall_verdict"], "pass-all-verified")
        self.assertGreaterEqual(result["verified_count"], 3)

    def test_fail_unverified_claim(self):
        text = (
            "Call vault_completely_fabricated_xyz and run "
            "tools/does-not-exist.py."
        )
        result = r64.verify_prompt(text, self.snap)
        self.assertEqual(result["overall_verdict"],
                         "fail-prompt-contains-unverified-claim")
        self.assertGreaterEqual(result["unverified_count"], 2)

    def test_ok_rebuttal(self):
        text = (
            "Call vault_completely_fabricated_xyz and "
            "tools/does-not-exist.py.\n"
            "<!-- r64-rebuttal: synthetic-fixture-for-testing-only -->"
        )
        result = r64.verify_prompt(text, self.snap)
        self.assertEqual(result["overall_verdict"], "ok-rebuttal")

    def test_tok_a_10k_cantina_anchor(self):
        # Empirical anchor: TOK-A "10K Cantina rationales"
        text = (
            "Mine 10K Cantina rationales from the prior_audits corpus."
        )
        result = r64.verify_prompt(text, self.snap)
        # Should flag the 10K record-count claim as unverified.
        self.assertEqual(result["overall_verdict"],
                         "fail-prompt-contains-unverified-claim")
        # At least one unverified claim with kind=record-count
        unverif = [c for c in result["claims"]
                   if not c.get("verified")
                   and c.get("kind") == "record-count"]
        self.assertGreater(len(unverif), 0)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # Use real snapshot in repo cache to avoid 30s rebuild
        self.snap_path = _REPO / ".auditooor" / "canonical_inventory.json"

    def _run(self, prompt_text: str, *extra_args, expect_rc: int = 0):
        prompt_file = self.tmpdir / "prompt.md"
        prompt_file.write_text(prompt_text)
        cmd = ["python3", str(_TOOL_PATH), str(prompt_file),
               "--workspace", str(_REPO),
               "--audits-root", "/tmp/nonexistent_audits",
               *extra_args]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout, proc.stderr

    def test_cli_pass_all_verified(self):
        rc, stdout, _ = self._run(
            "Run vault_resume_context and check Check #102 and R52."
        )
        self.assertEqual(rc, 0)
        self.assertIn("pass-all-verified", stdout)

    def test_cli_fail_unverified(self):
        rc, stdout, _ = self._run(
            "Call vault_completely_fabricated_xyz."
        )
        # default mode returns rc=0 (verdict still printed)
        self.assertEqual(rc, 0)
        self.assertIn("fail-prompt-contains-unverified-claim", stdout)

    def test_cli_strict_fails_unverified(self):
        rc, stdout, _ = self._run(
            "Call vault_completely_fabricated_xyz.",
            "--strict",
        )
        self.assertEqual(rc, 1)

    def test_cli_json_output_shape(self):
        rc, stdout, _ = self._run(
            "Run vault_resume_context.",
            "--json",
        )
        self.assertEqual(rc, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["schema"],
                         "auditooor.r64_prompt_claim_verifier.v1")
        self.assertIn("claims", payload)


if __name__ == "__main__":
    unittest.main()
