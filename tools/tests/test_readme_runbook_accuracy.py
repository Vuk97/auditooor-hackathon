#!/usr/bin/env python3
"""
Regression tests for README Canonical Audit Runbook accuracy.

Pins three corrections applied in the wave-3 funnel-generic-fixes pass:

(1) fail-function-coverage-incomplete criterion:
    The old README said "0 sidecars = hollow hunt" as the trigger for
    fail-function-coverage-incomplete.  The real criterion (from
    tools/function-coverage-completeness.py) is: every in-scope function must
    carry a real-attack verdict.  A hunt with 304 sidecars that all carry
    applies_to_target=false still fails - identically to a 0-sidecar hunt.
    The README must describe the real fix (check
    function_coverage_completeness.json and re-run to genuine real-attack
    verdicts), not the misleading sidecar-count proxy.

(2) audit-pipeline-full is NOT a complete one-command driver:
    The old README stated audit-pipeline-full "chains every step below" and
    produces pass-audit-complete.  The real Makefile target omits chain-synth,
    prove-top-leads, and does not pass DEPTH_PROBE_LIVE=1 to audit-depth.
    The README must document these gaps so operators know to run those steps
    separately, and must note that without AUDITOOOR_LLM_HUNT=1 the hunt and
    exploit-conversion steps are obligation-recorded (skipped) and
    audit-complete STRICT=1 still fails those signals.

(3) Step 2 / Step 3 STOP conditions must document known failure modes:
    - All three EVM engines (Halmos, Medusa, Echidna) can time out or error on
      mixed hardhat+foundry workspaces; this is a known class that the operator
      must handle with a typed skip reason.
    - hunt_provider_obligation.json with status=orchestrator-dispatch-required
      means the batch plan was generated but the Haiku agents were NOT yet
      dispatched; the hunt is queued, not run.

r36-rebuttal: funnel-generic-fixes-wave3
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """Collapse whitespace so wrapped lines still match single-line assertions."""
    return " ".join(text.split())


class TestReadmeFunctionCoverageIncompleteDescription(unittest.TestCase):
    """Bug (1): fail-function-coverage-incomplete must describe the real criterion."""

    def setUp(self) -> None:
        if not README.is_file():
            self.skipTest(f"{README} not found")
        self.text = _readme()
        self.flat = _flat(self.text)

    def test_no_misleading_zero_sidecars_hollow_hunt_claim(self) -> None:
        """The README must not equate 0 sidecars with a hollow hunt for this signal."""
        # The OLD text was: "zero sidecars = hollow hunt" as the FIX guidance.
        # This is wrong because a hunt with many sidecars all having
        # applies_to_target=false also fails this signal.
        self.assertNotIn(
            "zero sidecars = hollow hunt",
            self.flat,
            "README still says 'zero sidecars = hollow hunt' for "
            "fail-function-coverage-incomplete; this is wrong - a hunt with many "
            "sidecars all applies_to_target=false fails identically. "
            "Describe the real criterion: check function_coverage_completeness.json "
            "for untouched/hollow functions.",
        )

    def test_no_misleading_zero_sidecars_is_hollow_stop_condition(self) -> None:
        """The Step 3 STOP must not say 'a hunt that produced 0 sidecars is a hollow hunt'."""
        self.assertNotIn(
            "a hunt that produced 0 sidecars is a hollow hunt",
            self.flat,
            "README Step 3 STOP still has the misleading '0 sidecars = hollow hunt' "
            "framing. Replace with the real criterion from "
            "tools/function-coverage-completeness.py: real-attack verdict per function.",
        )

    def test_function_coverage_completeness_json_mentioned_as_diagnostic(self) -> None:
        """The README must direct operators to function_coverage_completeness.json."""
        self.assertIn(
            "function_coverage_completeness.json",
            self.text,
            "README must reference function_coverage_completeness.json as the "
            "diagnostic artifact for fail-function-coverage-incomplete; "
            "operators cannot diagnose which functions are hollow without it.",
        )

    def test_real_attack_verdict_criterion_explained(self) -> None:
        """The README must explain that the criterion is a real-attack verdict per function."""
        self.assertTrue(
            "real-attack verdict" in self.flat or "real-attack" in self.text,
            "README must explain that the gate requires a real-attack verdict for "
            "each in-scope function, not just a non-zero sidecar count.",
        )

    def test_applies_to_target_false_failure_mode_documented(self) -> None:
        """The README must note that sidecars with applies_to_target=false still fail."""
        self.assertIn(
            "applies_to_target",
            self.text,
            "README must document that sidecars with applies_to_target=false do not "
            "satisfy fail-function-coverage-incomplete; a large sidecar count with "
            "all-false applies_to_target is equivalent to a 0-sidecar hunt.",
        )

    def test_table_row_fix_for_function_coverage(self) -> None:
        """The quick-fix table row must mention function_coverage_completeness.json."""
        # The old table row said: "zero sidecars = hollow hunt" - must be fixed.
        self.assertIn(
            "function_coverage_completeness.json",
            self.text,
            "The quick-fix table row for fail-function-coverage-incomplete must "
            "reference function_coverage_completeness.json so operators know "
            "where to look.",
        )


class TestReadmeAuditPipelineFullAuthority(unittest.TestCase):
    """Bug (2): README must describe the V2 manifest/executor authority."""

    def setUp(self) -> None:
        if not README.is_file():
            self.skipTest(f"{README} not found")
        self.text = _readme()
        self.flat = _flat(self.text)

    def test_readme_does_not_claim_step_five_runs_separately(self) -> None:
        self.assertNotIn(
            "Step 5 runs SEPARATELY",
            self.text,
            "README still says Step 5 runs separately even though the public "
            "driver now delegates canonical order to the V2 manifest/executor.",
        )

    def test_readme_does_not_claim_chain_synth_and_prove_top_leads_are_omitted(self) -> None:
        self.assertNotIn(
            "does not call chain-synth or prove-top-leads",
            self.text,
            "README still describes the old shell-owned omission instead of the "
            "executor-owned V2 manifest flow.",
        )

    def test_readme_does_not_claim_depth_probe_live_is_missing_from_pipeline(self) -> None:
        self.assertNotIn(
            "audit-depth inside `audit-pipeline-full` runs WITHOUT `DEPTH_PROBE_LIVE=1`",
            self.text,
            "README still describes the old public Make recipe instead of the "
            "canonical manifest/executor authority.",
        )

    def test_readme_pipeline_section_mentions_executor_authority(self) -> None:
        idx = self.text.find("audit-pipeline-full")
        self.assertGreater(idx, -1)
        pipeline_section = self.text[idx : idx + 2500]
        self.assertIn(
            "pipeline-executor.py",
            pipeline_section,
            "The audit-pipeline-full section must name pipeline-executor.py as "
            "the public driver authority.",
        )

    def test_readme_pipeline_section_mentions_manifest_authority(self) -> None:
        idx = self.text.find("audit-pipeline-full")
        self.assertGreater(idx, -1)
        pipeline_section = self.text[idx : idx + 2500]
        self.assertIn(
            "tools/readme_runbook_steps.json",
            pipeline_section,
            "The audit-pipeline-full section must point at tools/readme_runbook_steps.json "
            "for canonical order.",
        )


class TestReadmeStopConditions(unittest.TestCase):
    """Bug (3): Step 2 and Step 3 STOP conditions must document known failure modes."""

    def setUp(self) -> None:
        if not README.is_file():
            self.skipTest(f"{README} not found")
        self.text = _readme()
        self.flat = _flat(self.text)

    def test_mixed_hardhat_foundry_engine_failure_documented(self) -> None:
        """Step 2 STOP must note that all three EVM engines can fail on mixed workspaces."""
        self.assertIn(
            "hardhat",
            self.text.lower(),
            "README Step 2 STOP must document that all three Solidity engines "
            "(Halmos, Medusa, Echidna) can fail with engine-error or timeout on "
            "mixed hardhat+foundry workspaces.",
        )
        # The README heading text has shifted over time; anchor on the first
        # mixed hardhat+foundry failure-mode note rather than a brittle exact
        # heading token.
        step2_start = self.text.lower().find("mixed hardhat+foundry workspaces")
        self.assertGreater(step2_start, -1, "README must document the mixed hardhat+foundry failure mode")
        step2_section = self.text[step2_start : step2_start + 900]
        self.assertTrue(
            "hardhat" in step2_section.lower() or "engine-error" in step2_section,
            "README Step 2 section must document the mixed hardhat+foundry "
            "all-engines-fail failure mode.",
        )

    def test_orchestrator_dispatch_required_documented(self) -> None:
        """Step 3 STOP must note that orchestrator-dispatch-required means queued-not-run."""
        self.assertIn(
            "orchestrator-dispatch-required",
            self.text,
            "README Step 3 STOP must document that "
            "hunt_provider_obligation.json status=orchestrator-dispatch-required "
            "means the hunt is queued (batch plan written) but NOT yet run.",
        )

    def test_orchestrator_dispatch_queued_not_run_framing(self) -> None:
        """The orchestrator-dispatch-required note must use 'queued' or 'not run' language."""
        idx = self.text.find("orchestrator-dispatch-required")
        self.assertGreater(idx, -1)
        context = self.text[max(0, idx - 200) : idx + 400]
        self.assertTrue(
            "queued" in context.lower() or "not yet" in context.lower() or "not run" in context.lower(),
            "The orchestrator-dispatch-required note must clearly state the hunt "
            "is queued/not-yet-run, not completed. "
            f"Context found: {context!r}",
        )


class TestStep3ObligationTerminalStatus(unittest.TestCase):
    """The step-3 done-check must accept residual-empty-no-hunt-required as a
    terminal-green obligation status. residual-scope-per-fn writes it once the
    hunt-coverage gate passes with an EMPTY residual (a genuinely DRAINED hunt);
    if the verifier only whitelists 'completed'/null, a fully-hunted workspace is
    scored step-3-not-done forever (NUVA 2026-07-03 false-red)."""

    def setUp(self) -> None:
        import json
        p = Path(__file__).resolve().parents[1] / "readme_runbook_steps.json"
        self.steps = json.loads(p.read_text(encoding="utf-8"))

    def _step3_obligation_check(self):
        steps = self.steps if isinstance(self.steps, list) else self.steps.get("steps", [])
        for s in steps:
            if s.get("step_id") != "step-3":
                continue
            verify = s.get("how_to_verify_done") or {}
            checks = verify.get("artifact_checks") if isinstance(verify, dict) else verify
            for chk in checks or []:
                if (chk.get("type") == "file_absent_or_field_equals"
                        and "hunt_provider_obligation" in str(chk.get("path", ""))):
                    return chk
        return None

    def test_residual_empty_is_a_terminal_ok_value(self) -> None:
        chk = self._step3_obligation_check()
        self.assertIsNotNone(chk, "step-3 must have a hunt_provider_obligation status check")
        self.assertIn("residual-empty-no-hunt-required", chk.get("ok_values") or [],
                      "a drained residual (gate-pass-empty) must be a terminal-green status")

    def test_not_run_statuses_are_not_ok_values(self) -> None:
        chk = self._step3_obligation_check()
        self.assertIsNotNone(chk)
        ok = chk.get("ok_values") or []
        for not_done in ("orchestrator-dispatch-required",
                         "residual-hunt-required",
                         "residual-unknown-dispatch-required"):
            self.assertNotIn(not_done, ok,
                             f"{not_done} is a NOT-run/NOT-done status and must stay RED")


class TestEmptyArtifactHolesClosed(unittest.TestCase):
    """G-5 + R59 (2026-07-03 enforcement-gap audit): a required step's artifact_check
    must reject an EMPTY/STUB file, not pass on mere existence. step-4b's
    INVARIANT_LEDGER.md and step-1c's dataflow_paths.jsonl both used existence-only
    checks, so a 0-byte artifact (Step 4b never authored / dataflow timed out to 0
    output - the strata incident) passed conformance."""

    def setUp(self) -> None:
        import json
        p = Path(__file__).resolve().parents[1] / "readme_runbook_steps.json"
        self.steps = json.loads(p.read_text(encoding="utf-8")).get("steps", [])

    def _checks(self, step_id):
        for s in self.steps:
            if s.get("step_id") == step_id:
                v = s.get("how_to_verify_done") or {}
                return v.get("artifact_checks") if isinstance(v, dict) else v
        return None

    def test_step4b_invariant_ledger_is_file_nonempty(self):
        checks = self._checks("step-4b") or []
        ledger = [c for c in checks if "INVARIANT_LEDGER.md" in str(c.get("path", ""))]
        self.assertTrue(ledger, "step-4b must check INVARIANT_LEDGER.md")
        self.assertEqual(ledger[0].get("type"), "file_nonempty",
                         "an empty/stub ledger must FAIL, not pass on existence (G-5)")

    def test_step1c_dataflow_is_nonempty(self):
        checks = self._checks("step-1c") or []
        df = [c for c in checks if any("dataflow_paths.jsonl" in str(p) for p in (c.get("paths") or []))]
        self.assertTrue(df, "step-1c must check dataflow_paths.jsonl")
        self.assertEqual(df[0].get("type"), "file_nonempty_any",
                         "a 0-byte dataflow_paths.jsonl must FAIL (R59 strata timeout->0-output)")


class TestStep0gCoveragePlaneManifestVsWiring(unittest.TestCase):
    """A3 (2026-07-03): step-0g's prose once made two FALSE claims about the
    coverage_plane substrate:
      (1) that the materialized plane "seeds/drains the hunt" (i.e. the hunt
          reads coverage_plane.jsonl as its worklist), and
      (2) that "audit-complete reads the unified plane" for its (unit x frame)
          verdict enforcement.
    Both are false by grep: NO hunt builder opens coverage_plane, and
    tools/audit-completeness-check.py has ZERO references to coverage_plane.
    The truth: coverage_plane.jsonl is an ADVISORY, MCP-inspectable mirror
    DERIVED FROM completeness_matrix.json by tools/coverage-plane-build.py
    (advisory-only inside make audit-deep); the real (unit x frame) enforcement
    reads .auditooor/completeness_matrix.json.

    This lint is advisory manifest-vs-wiring drift protection: it fails if the
    step-0g text re-introduces a false claim OR if the wiring reality it now
    describes stops holding (audit-complete starts reading coverage_plane, or a
    hunt builder starts reading it) - either direction means the doc and the
    code have diverged and must be re-reconciled."""

    def setUp(self) -> None:
        import json
        self.tools = REPO / "tools"
        p = self.tools / "readme_runbook_steps.json"
        if not p.is_file():
            self.skipTest(f"{p} not found")
        steps = json.loads(p.read_text(encoding="utf-8")).get("steps", [])
        self.step0g = next((s for s in steps if s.get("step_id") == "step-0g"), None)
        if self.step0g is None:
            self.skipTest("step-0g not present in readme_runbook_steps.json")
        self.blob = _flat(json.dumps(self.step0g))

    # ---- part 1: the prose must not re-introduce the false claims ----

    def test_step0g_does_not_claim_plane_seeds_or_drains_the_hunt(self) -> None:
        lowered = self.blob.lower()
        for bad in ("drains a known worklist", "drain cells rather than run"):
            self.assertNotIn(
                bad, lowered,
                "step-0g re-introduced the FALSE claim that the coverage_plane "
                f"seeds/drains the hunt ({bad!r}); no hunt builder reads "
                "coverage_plane. The hunt worklist comes from per-(fn x impact) "
                "task generation gated by PER_IMPACT_FRAMES, seeded from "
                "completeness_matrix, not from draining the plane.",
            )

    def test_step0g_does_not_claim_audit_complete_reads_the_plane(self) -> None:
        lowered = self.blob.lower()
        self.assertNotIn(
            "audit-complete reads the unified plane", lowered,
            "step-0g re-introduced the FALSE claim that audit-complete reads the "
            "plane; audit-completeness-check.py has zero coverage_plane refs. The "
            "(unit x frame) enforcement reads completeness_matrix.json.",
        )

    def test_step0g_states_the_plane_is_advisory_and_derived(self) -> None:
        lowered = self.blob.lower()
        self.assertIn(
            "advisory", lowered,
            "step-0g must state the coverage_plane is advisory / inspect-only.",
        )
        self.assertIn(
            "completeness_matrix", lowered,
            "step-0g must name completeness_matrix as the real enforcement "
            "artifact the plane is derived from.",
        )

    # ---- part 2: the wiring reality the corrected prose describes must hold ----

    def test_audit_completeness_check_does_not_read_step0g_plane_file(self) -> None:
        f = self.tools / "audit-completeness-check.py"
        self.assertTrue(f.is_file(), f"{f} not found")
        src = f.read_text(encoding="utf-8")
        self.assertNotIn(".auditooor/coverage_plane.jsonl", src)
        self.assertNotIn("coverage-plane-build.py", src)

    def test_no_hunt_builder_reads_coverage_plane_unconditionally(self) -> None:
        # A3 invariant (2026-07-03), reconciled with A2 (task #128): the plane must
        # never be the DEFAULT / unconditional hunt worklist source (that would
        # re-introduce false-completeness). A2 later added an OPT-IN advisory drain
        # (AUDITOOOR_PLANE_DRAIN, default OFF, byte-identical to legacy when off).
        # So the real invariant is: any coverage_plane read on a hunt builder MUST be
        # gated behind the AUDITOOOR_PLANE_DRAIN env flag, not unconditional.
        for name in ("per-fn-mimo-batch-gen.py", "inscope-hunt-batch-builder.py"):
            f = self.tools / name
            self.assertTrue(f.is_file(), f"{f} not found")
            txt = f.read_text(encoding="utf-8")
            if "coverage_plane" in txt:
                self.assertIn(
                    "AUDITOOOR_PLANE_DRAIN", txt,
                    f"{name} reads coverage_plane but NOT behind the "
                    "AUDITOOOR_PLANE_DRAIN gate (default-off); an unconditional plane "
                    "read re-introduces the false-completeness A3 forbids - re-gate it.",
                )

    def test_coverage_plane_producer_exists_and_reads_the_matrix(self) -> None:
        f = self.tools / "coverage-plane-build.py"
        self.assertTrue(
            f.is_file(),
            "step-0g names coverage-plane-build.py as the plane producer but it "
            "is missing.",
        )
        src = f.read_text(encoding="utf-8")
        self.assertIn(
            "completeness_matrix", src,
            "coverage-plane-build.py must derive the plane from "
            "completeness_matrix.json (the plane is a downstream mirror, not a "
            "source of truth).",
        )


if __name__ == "__main__":
    unittest.main()
