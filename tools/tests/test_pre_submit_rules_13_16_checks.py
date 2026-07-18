"""test_pre_submit_rules_13_16_checks.py — gates 50-57 unit tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

# Import the module by file path since the filename has dashes.
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "rules_13_16",
    ROOT / "tools" / "pre-submit-rules-13-16-checks.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _make(content: str, workspace_token: str = "dydx") -> Path:
    """Create a temp draft inside a workspace_token-named directory so the
    engagement-inference logic resolves the right engagement."""
    d = Path(tempfile.mkdtemp(prefix=f"{workspace_token}_ws_"))
    sub = d / workspace_token / "submissions"
    sub.mkdir(parents=True, exist_ok=True)
    p = sub / "draft.md"
    p.write_text(content, encoding="utf-8")
    return p


class Check50Tests(unittest.TestCase):
    def test_spark_phrase_in_dydx_fails(self):
        text = "Severity: CRITICAL\nfix requires hardfork on this dydx finding."
        p = _make(text, workspace_token="dydx")
        ok, msg = mod.check_50_wrong_rubric_contamination(text, p)
        self.assertFalse(ok)
        self.assertIn("Rule 10", msg)

    def test_dydx_phrase_in_spark_fails(self):
        text = "This Spark finding involves the Cantina v4-chain (protocol)."
        p = _make(text, workspace_token="spark")
        ok, msg = mod.check_50_wrong_rubric_contamination(text, p)
        self.assertFalse(ok)

    def test_clean_dydx_passes(self):
        text = "Severity: HIGH\nClean dydx-only finding."
        p = _make(text, workspace_token="dydx")
        ok, _ = mod.check_50_wrong_rubric_contamination(text, p)
        self.assertTrue(ok)

    def test_rebuttal_override(self):
        text = "<!-- r10-rebuttal: legitimate -->\nfix requires hardfork is valid here."
        p = _make(text, workspace_token="dydx")
        ok, _ = mod.check_50_wrong_rubric_contamination(text, p)
        self.assertTrue(ok)


class Check51Tests(unittest.TestCase):
    def test_default_claim_without_citation_fails(self):
        text = "By default, snapshot pruning is enabled."
        p = _make(text)
        ok, msg = mod.check_51_default_vs_opt_in_citation(text, p)
        self.assertFalse(ok)
        self.assertIn("Rule 11", msg)

    def test_default_claim_with_citation_passes(self):
        text = "By default, snapshot pruning is enabled (server/util.go:430)."
        p = _make(text)
        ok, _ = mod.check_51_default_vs_opt_in_citation(text, p)
        self.assertTrue(ok)

    def test_no_default_claim_passes(self):
        text = "No claims here."
        p = _make(text)
        ok, _ = mod.check_51_default_vs_opt_in_citation(text, p)
        self.assertTrue(ok)


class Check52Tests(unittest.TestCase):
    def test_build_path_with_3_items_passes(self):
        text = "What would upgrade to Critical:\n1. Build harness X\n2. Effort 2-4 days\n3. Blocker: multi-validator regtest"
        p = _make(text)
        ok, _ = mod.check_52_build_path_itemization(text, p)
        self.assertTrue(ok)

    def test_build_path_with_2_items_fails(self):
        text = "What would upgrade to Critical:\n- Build harness X\n- Effort 2-4 days"
        p = _make(text)
        ok, msg = mod.check_52_build_path_itemization(text, p)
        self.assertFalse(ok)
        self.assertIn("Rule 12", msg)

    def test_no_build_path_section_passes(self):
        text = "Severity: HIGH\nFinding details."
        p = _make(text)
        ok, _ = mod.check_52_build_path_itemization(text, p)
        self.assertTrue(ok)


class Check53Tests(unittest.TestCase):
    def test_orphan_advisory_id_fails(self):
        text = "Random sentence mentioning CVE-2024-12345 with no context."
        p = _make(text)
        ok, msg = mod.check_53_advisory_id_oos_leak(text, p)
        self.assertFalse(ok)
        self.assertIn("Rule 13", msg)

    def test_advisory_in_originality_section_passes(self):
        text = "## Scope and Originality\nPrior CVE-2024-12345 is unrelated."
        p = _make(text)
        ok, _ = mod.check_53_advisory_id_oos_leak(text, p)
        self.assertTrue(ok)

    def test_advisory_with_oos_context_passes(self):
        text = "- oos_traps: GHSA-aaaa-bbbb-cccc is out-of-scope (different module)"
        p = _make(text)
        ok, _ = mod.check_53_advisory_id_oos_leak(text, p)
        self.assertTrue(ok)

    def test_rebuttal_override(self):
        text = "<!-- r13-rebuttal: needed -->\nCVE-2024-99999 cited elsewhere."
        p = _make(text)
        ok, _ = mod.check_53_advisory_id_oos_leak(text, p)
        self.assertTrue(ok)


class Check53AdvisoryOfAnchorTests(unittest.TestCase):
    """Rank-6(a): ``OF-`` advisory anchor no longer matches OUT-OF-BAND /
    OUT-OF-SCOPE contrast prose, but still fires on a real ``OF-\\d{3,}`` id."""

    def test_out_of_band_prose_does_not_leak(self):
        # False-positive suppressed: refutation/contrast context.
        text = "The oracle uses an out-of-band price feed which is out-of-scope here."
        p = _make(text)
        ok, _ = mod.check_53_advisory_id_oos_leak(text, p)
        self.assertTrue(ok)

    def test_real_of_advisory_id_still_fails(self):
        # Control / true-positive: an orphan OF-### advisory id still leaks.
        text = "Random sentence citing advisory OF-451 with no originality context."
        p = _make(text)
        ok, msg = mod.check_53_advisory_id_oos_leak(text, p)
        self.assertFalse(ok)
        self.assertIn("Rule 13", msg)


class Check54Tests(unittest.TestCase):
    def test_escalation_history_fails(self):
        text = "We attempted Approach A which failed, then we tried iteration 2."
        p = _make(text)
        ok, msg = mod.check_54_escalation_history_narrative(text, p)
        self.assertFalse(ok)
        self.assertIn("D13", msg)

    def test_consolidated_narrative_passes(self):
        text = "The bug causes X. The fix is Y."
        p = _make(text)
        ok, _ = mod.check_54_escalation_history_narrative(text, p)
        self.assertTrue(ok)


class Check55Tests(unittest.TestCase):
    def test_critical_without_but_for_fails(self):
        text = "Severity: CRITICAL\n\nThe bug allows X."
        p = _make(text)
        ok, msg = mod.check_55_but_for_causation(text, p)
        self.assertFalse(ok)
        self.assertIn("Rule 15", msg)

    def test_critical_with_but_for_passes(self):
        text = "Severity: CRITICAL\n\nAbsent this bug, the impact does not occur."
        p = _make(text)
        ok, _ = mod.check_55_but_for_causation(text, p)
        self.assertTrue(ok)

    def test_medium_severity_softskips(self):
        text = "Severity: MEDIUM\nNo but-for required."
        p = _make(text)
        ok, msg = mod.check_55_but_for_causation(text, p)
        self.assertTrue(ok)
        self.assertIn("soft-skip", msg)


class Check56Tests(unittest.TestCase):
    def test_parity_without_citation_fails(self):
        text = "Escalated by parity-precedent."
        p = _make(text)
        ok, msg = mod.check_56_parity_precedent_citation(text, p)
        self.assertFalse(ok)
        self.assertIn("Rule 16", msg)

    def test_parity_with_citation_passes(self):
        text = "Escalated by parity with cantina-#048 (same mechanism)."
        p = _make(text)
        ok, _ = mod.check_56_parity_precedent_citation(text, p)
        self.assertTrue(ok)

    def test_no_parity_claim_passes(self):
        text = "Severity: HIGH. Standard finding."
        p = _make(text)
        ok, _ = mod.check_56_parity_precedent_citation(text, p)
        self.assertTrue(ok)


class Check57Tests(unittest.TestCase):
    def test_three_test_paths_fails(self):
        text = (
            "PoC files:\n"
            "- `a_test.go`\n"
            "- `b_test.go`\n"
            "- `c_test.go`\n"
        )
        p = _make(text)
        ok, msg = mod.check_57_consolidation_linter(text, p)
        self.assertFalse(ok)
        self.assertIn("D20", msg)

    def test_single_test_path_passes(self):
        text = "PoC at `single_test.go` only."
        p = _make(text)
        ok, _ = mod.check_57_consolidation_linter(text, p)
        self.assertTrue(ok)

    def test_rebuttal_override(self):
        text = (
            "<!-- d20-rebuttal: multi-component PoC required -->\n"
            "- `a_test.go`\n- `b_test.go`\n- `c_test.go`\n- `d_test.go`\n"
        )
        p = _make(text)
        ok, _ = mod.check_57_consolidation_linter(text, p)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
