#!/usr/bin/env python3
"""Docs truth sweep assertions (P2-1 burn-down).

Pin curated "must-be-true" facts so future drift fails loudly.
"""

import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


class TestDocsTruthSweep(unittest.TestCase):
    """Assert that key capability claims remain accurate across anchor docs."""

    def test_tool_status_symbolic_runner_executes_live(self):
        """After I12+I13+I15, symbolic-runner executes in LIVE=1 mode;
        stale "scaffolded/dry-run" wording must not regress."""
        text = _read("docs/TOOL_STATUS.md")
        self.assertIn("symbolic-runner.sh", text)
        self.assertIn("After I12+I13+I15 fixes", text)
        self.assertIn("LIVE=1", text)
        # Ensure the old stale claim is gone
        self.assertNotIn("some angle modes are scaffolded/dry-run", text)

    def test_tool_status_detector_backend_split(self):
        """PR #460 backend split must be documented in TOOL_STATUS.md."""
        text = _read("docs/TOOL_STATUS.md")
        self.assertIn("detector-lint.py", text)
        self.assertIn("Backend-aware", text)
        self.assertIn("Check 7b", text)

    def test_source_mining_runbook_ext_rs(self):
        """Rust source-mining (--ext rs) must appear in runbook (PR #337 / I18)."""
        text = _read("docs/SOURCE_MINING_RUNBOOK.md")
        self.assertIn("--ext rs", text)
        self.assertIn("post-I18", text)

    def test_pattern_dsl_backend_field(self):
        """PATTERN_DSL.md must document the optional backend: field (PR #460)."""
        text = _read("reference/PATTERN_DSL.md")
        self.assertIn("backend:", text)
        self.assertIn("solidity", text)
        self.assertIn("documentation_only", text)
        self.assertIn("Check 7b", text)

    def test_known_limitations_p2_1_sweep_landed(self):
        """P2-1 row must reflect that the 2026-04-29 truth sweep landed."""
        text = _read("docs/KNOWN_LIMITATIONS.md")
        self.assertIn("2026-04-29 truth sweep landed", text)
        self.assertIn("PR #459 P2-1", text)

    def test_known_limitations_p1_1_backend_aware(self):
        """P1-1 row must reference backend-aware lint and Check 7b."""
        text = _read("docs/KNOWN_LIMITATIONS.md")
        self.assertIn("backend-split", text)
        self.assertIn("Check 7b", text)

    # PR #511 Slice 1: Documentation Truth and Operator Guardrails
    # ----------------------------------------------------------------
    # The four bullet claims and the "no finding proven != no bug exists"
    # operator language must remain present across the operator-facing docs.
    # If a future edit drops them, this test fails so the regression is
    # impossible to merge silently.

    def test_known_limitations_audit_deep_not_exhaustive(self):
        """KNOWN_LIMITATIONS.md must state audit-deep is not exhaustive."""
        text = _read("docs/KNOWN_LIMITATIONS.md")
        # Collapse whitespace so wrapped sentences still match.
        flat = " ".join(text.split())
        self.assertIn("`make audit-deep` does NOT synthesize all protocol invariants", flat)
        self.assertIn("`DEEP_PROFILE=all` is NOT exhaustive", flat)
        self.assertIn("intentionally excludes `coverage-gaps`", flat)
        self.assertIn("Invariant templates", flat)
        self.assertIn("candidate harness seeds, NOT proof", flat)
        self.assertIn("Rust DLT semantic graph is import-graph only", flat)

    def test_known_limitations_invariant_ledger_section(self):
        """KNOWN_LIMITATIONS.md must carry the Invariant Ledger Required section."""
        text = _read("docs/KNOWN_LIMITATIONS.md")
        self.assertIn("## Invariant Ledger Required", text)
        self.assertIn("INVARIANT_LEDGER.md", text)
        self.assertIn("make invariant-ledger-check", text)
        self.assertIn("tooling is live", text)

    def test_tool_status_execution_state_vocabulary(self):
        """TOOL_STATUS.md must distinguish planned/scaffolded/executed/proved."""
        text = _read("docs/TOOL_STATUS.md")
        self.assertIn("## Execution-State Vocabulary", text)
        for state in ("`planned`", "`scaffolded`", "`executed`", "`proved`"):
            self.assertIn(state, text)

    def test_engage_invariant_ledger_requirement(self):
        """ENGAGE.md must require an invariant ledger or explicit no-ledger warning."""
        text = _read("docs/ENGAGE.md")
        self.assertIn("Invariant ledger requirement", text)
        self.assertIn("INVARIANT_LEDGER.md", text)
        self.assertIn("source-only", text)
        self.assertIn("no-ledger", text)
        self.assertIn("make invariant-ledger-check", text)
        self.assertIn("now validates", text)

    def test_stage_reference_invariant_ledger_stage(self):
        """STAGE_REFERENCE.md must list the invariant-ledger stage as REQUIRED."""
        text = _read("docs/STAGE_REFERENCE.md")
        self.assertIn("invariant-ledger", text)
        self.assertIn("REQUIRED for High/Critical impact subsystems", text)

    def test_workflow_no_finding_proven_language(self):
        """WORKFLOW.md must carry the 'no finding proven != no bug exists' language."""
        text = _read("docs/WORKFLOW.md")
        flat = " ".join(text.split())
        # The phrase must appear prominently and explicitly. Tolerate wrapping.
        self.assertIn('"No finding proven" is NOT "no bug exists."', flat)
        self.assertIn('"no invariant-backed proof found."', flat)

    def test_workflow_source_proof_is_fail_closed(self):
        """WORKFLOW.md must not overclaim source-proof readiness."""
        text = _read("docs/WORKFLOW.md")
        flat = " ".join(text.split())
        self.assertIn("Source-proof closure is fail-closed too", flat)
        self.assertIn("exact impact contract", flat)
        self.assertIn("valid source citation", flat)
        self.assertIn("OOS=in_scope", flat)

    def test_base_preflight_docs_preserve_proof_boundary(self):
        """Base preflight docs must say PASS is readiness-only, not proof."""
        workflow = " ".join(_read("docs/WORKFLOW.md").split())
        readme = " ".join(_read("README.md").split())
        self.assertIn("A `PASS` means scan prerequisites are present; it is not exploit proof", workflow)
        self.assertIn("A preflight `PASS` means prerequisites are present; it is not exploit proof", readme)
        self.assertIn("semantic completeness", workflow)
        self.assertIn("submission readiness", readme)

    def test_high_impact_bridge_docs_preserve_blocked_non_proof_status(self):
        """High-impact execution bridge docs must keep blocked rows non-runnable."""
        readme = _read("README.md")
        tool_status = _read("docs/TOOL_STATUS.md")
        self.assertIn("execution-readiness routing, not exploit proof", readme)
        self.assertIn("blocked_missing_impact_contract", readme)
        self.assertIn("Execution state: `scaffolded`", tool_status)
        self.assertIn("bridge output is readiness evidence, not exploit proof", tool_status)

    def test_workflow_pre_submit_summary_defers_to_shell_gate(self):
        """WORKFLOW.md must keep 32-check wording anchored to the shell gate."""
        text = _read("docs/WORKFLOW.md")
        self.assertIn('source of truth: `tools/pre-submit-check.sh` "ALL 32 CHECKS"', text)
        self.assertIn("The numbered bullets below are an operator summary, not the authoritative", text)
        self.assertIn("Check #31 validates exact listed program-impact mapping", text)
        self.assertIn("Check #32 is SEVERITY-CLAIM-GUARD", text)


if __name__ == "__main__":
    unittest.main()
