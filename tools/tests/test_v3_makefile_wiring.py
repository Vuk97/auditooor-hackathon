from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"


class V3MakefileWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = MAKEFILE.read_text(encoding="utf-8")

    def _target_body(self, target: str, next_target: str) -> str:
        target_index = self.text.index(target)
        next_target_index = self.text.index(next_target, target_index)
        return self.text[target_index:next_target_index]

    def _make_dry_run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["make", "--no-print-directory", "-n", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_new_v3_targets_are_exposed(self) -> None:
        for target in (
            "queue-proof-hard-close:",
            "field-validation-report:",
            "audit-workflow-coverage-map:",
            "audit-fast:",
            "fuzz-quick:",
            "fuzz-quick-test:",
            "mining-coverage-dashboard:",
            "lesson-source-inventory:",
            "lesson-promotion-review-queue:",
            "lesson-enforcement-inventory:",
            "agent-artifact-mine-all:",
            "agent-artifact-lesson-candidates:",
            "anti-pattern-corpus-bootstrap:",
            "hackerman-sidecar-coverage-report:",
            "audit-v3-enforcement-gate:",
            "v3-source-first-audit:",
            "v3-source-first-prereq-gate:",
            "v3-source-first-prereq-gate-test:",
            "v3-source-first-prior-audit-dupe-gate:",
            "v3-source-first-row-gate:",
            "v3-source-first-row-gate-test:",
            "source-mined-impact-contracts:",
            "source-mined-impact-contracts-test:",
            "v3-roadmap-sidecars:",
            "v3-roadmap-progress-report:",
            "triager-pre-filing-simulator:",
            "triager-pre-filing-simulator-test:",
            "field-validation-platform-id-gaps:",
            "field-validation-platform-id-gaps-test:",
            "source-miner-backlog-actions:",
            "source-miner-backlog-actions-test:",
            "phase-b-e-measurement-report:",
            "phase-b-e-measurement-report-test:",
            "p4-provider-readiness-probe:",
            "p4-provider-readiness-probe-test:",
            "outcome-lesson-gate:",
            "provider-keep-verification-backfill:",
            "v3-provider-campaign-completeness-gate:",
            "hacker-question-workflow-audit:",
            "darknavy-web3-plan:",
        ):
            self.assertIn(target, self.text)

    def test_dispatch_preflight_exposes_severity_and_local_judgment_bundle(self) -> None:
        body = self._target_body("dispatch-preflight:", "dispatch-preflight-test:")
        self.assertIn("[SEVERITY=<level>]", body)
        self.assertIn("[LOCAL_JUDGMENT_BUNDLE=<path>]", body)
        self.assertIn('--severity "$(SEVERITY)"', body)
        self.assertIn(
            '--require-local-judgment-bundle "$(LOCAL_JUDGMENT_BUNDLE)"',
            body,
        )

    def test_audit_path_wires_hacker_context_and_closeout_reports(self) -> None:
        for needle in (
            'brain-prime WS="$(_WS_RESOLVED)" $(if $(filter 1,$(STRICT)),STRICT=1)',
            'hacker-brief WS="$(_WS_RESOLVED)" LANE="canonical-audit"',
            "reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/dydx_phase_ii5_predicate_coverage.json",
            "reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/hyperbridge_phase_ii5_predicate_coverage.json",
            "reports/v3_iter_2026-05-24/lane_PHASE_II5_PREDICATE_COVERAGE/hyperbridge_pre_phase_ii5_predicate_coverage.json",
            'prove-top-leads WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),10)" JSON=1',
            'queue-proof-hard-close WS="$(_WS_RESOLVED)"',
            'field-validation-report WS="$(_WS_RESOLVED)"',
            'v3-roadmap-sidecars WS="$(_WS_RESOLVED)"',
            'candidate judgment/proof lead queue advisory',
            "queue_proof_hard_close.json",
            "field_validation_report.json",
            '$(if $(filter 1,$(STRICT)),--strict)',
        ):
            self.assertIn(needle, self.text)

        audit_index = self.text.index("audit:")
        audit_deep_index = self.text.index("audit-deep:")
        audit_body = self.text[audit_index:audit_deep_index]
        self.assertLess(
            audit_body.index('exploit-queue WS="$(_WS_RESOLVED)" JSON=1'),
            audit_body.index('prove-top-leads WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),10)" JSON=1'),
        )
        self.assertLess(
            audit_body.index('prove-top-leads WS="$(_WS_RESOLVED)" TOP_N="$(if $(TOP_N),$(TOP_N),10)" JSON=1'),
            audit_body.index('queue-proof-hard-close WS="$(_WS_RESOLVED)"'),
        )

    def test_audit_fast_regenerates_live_target_and_ahdh_sidecar(self) -> None:
        body = self._target_body("audit-fast:", "audit:")

        self.assertIn("tools/live-target-intelligence-report.py", body)
        self.assertIn("tools/adversarial-hypothesis-differential-hunter.py", body)
        self.assertIn("tools/defender-narrative-simulator.py", body)
        self.assertIn("tools/post-filing-outcome-replay-pattern-distiller.py", body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', body)
        self.assertIn('--output "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md"', body)
        self.assertIn('--output-json "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json"', body)
        self.assertIn(
            '--out "$(_WS_RESOLVED)/.auditooor/adversarial_hypothesis_top5.json"',
            body,
        )
        self.assertIn('"$(_WS_RESOLVED)/.auditooor/dns_advisory.json"', body)
        self.assertIn(
            '--out-json "$(_WS_RESOLVED)/.auditooor/pforpd_replay_patterns.json"',
            body,
        )
        self.assertIn('--top-n "$(if $(TOP_N),$(TOP_N),50)"', body)
        self.assertIn(
            '--triager-precheck-budget "$(if $(TRIAGER_PRECHECK_BUDGET),$(TRIAGER_PRECHECK_BUDGET),10)"',
            body,
        )
        self.assertNotIn("--if-stale-only", body)
        for slow_target in (
            "v3-roadmap-sidecars",
            "audit-closeout",
            "audit-v3-enforcement-gate",
            "queue-proof-hard-close",
            "field-validation-report",
            "provider-fanout-discipline-check",
        ):
            self.assertNotIn(slow_target, body)

        dry_run = self._make_dry_run("audit-fast", "WS=/tmp/auditooor-abs-ws")
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertIn("python3 tools/live-target-intelligence-report.py", dry_run.stdout)
        self.assertIn(
            "python3 tools/adversarial-hypothesis-differential-hunter.py",
            dry_run.stdout,
        )
        self.assertIn("python3 tools/defender-narrative-simulator.py", dry_run.stdout)
        self.assertIn("python3 tools/post-filing-outcome-replay-pattern-distiller.py", dry_run.stdout)
        self.assertIn('--workspace "/tmp/auditooor-abs-ws"', dry_run.stdout)
        self.assertIn(
            '--output "/tmp/auditooor-abs-ws/docs/LIVE_TARGET_REPORT.md"',
            dry_run.stdout,
        )
        self.assertIn(
            '--out "/tmp/auditooor-abs-ws/.auditooor/adversarial_hypothesis_top5.json"',
            dry_run.stdout,
        )
        self.assertIn('--triager-precheck-budget "10"', dry_run.stdout)
        self.assertNotIn("v3-roadmap-sidecars", dry_run.stdout)

    def test_fuzz_quick_wires_fuzz_target_corpus_emitter(self) -> None:
        body = self._target_body("fuzz-quick:", "fuzz-quick-test:")

        self.assertIn("tools/fuzz-target-corpus.py", body)
        self.assertIn('--workspace "$(WS)"', body)
        self.assertIn('$(if $(INPUT),--input "$(INPUT)",)', body)
        self.assertIn('--limit $(if $(TARGETS),$(TARGETS),5)', body)
        self.assertIn('$(if $(OUT),--out "$(OUT)",)', body)
        self.assertIn('$(if $(JSON),--json)', body)

    def test_hunt_wires_hyperbridge_cargo_patch_as_advisory_prestep(self) -> None:
        body = self._target_body("hunt:", "critical-hunt:")

        self.assertIn("Advisory pre-step - hyperbridge workspace detected", body)
        self.assertIn("src/hyperbridge/modules/ismp/core", self.text)
        self.assertIn("src/hyperbridge/modules/ismp", self.text)
        self.assertIn("src/hyperbridge/tesseract", self.text)
        self.assertIn("src/hyperbridge/parachain", self.text)
        self.assertIn('$(MAKE) --no-print-directory hyperbridge-cargo-patch WS="$(_WS_RESOLVED)"', body)
        self.assertIn("WARN hyperbridge-cargo-patch failed rc=$$hb_rc; continuing", body)
        self.assertLess(
            body.index('$(MAKE) --no-print-directory hyperbridge-cargo-patch WS="$(_WS_RESOLVED)"'),
            body.index('$(MAKE) --no-print-directory audit-fast WS="$(_WS_RESOLVED)"'),
        )

        with tempfile.TemporaryDirectory() as workspace:
            ws = Path(workspace)
            (ws / "src/hyperbridge/modules/ismp/core").mkdir(parents=True)
            (ws / "docs").mkdir()

            dry_run = self._make_dry_run("hunt", f"WS={workspace}")

        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertIn("[make hunt] Advisory pre-step - hyperbridge workspace detected", dry_run.stdout)
        self.assertIn(
            f'hyperbridge-cargo-patch WS="{workspace}"',
            dry_run.stdout,
        )
        self.assertIn(
            f'audit-fast WS="{workspace}"',
            dry_run.stdout,
        )
        self.assertLess(
            dry_run.stdout.index(
                f'hyperbridge-cargo-patch WS="{workspace}"',
            ),
            dry_run.stdout.index(f'audit-fast WS="{workspace}"'),
        )

    def test_live_target_intel_wires_dns_and_pforpd_sidecars(self) -> None:
        body = self._target_body("live-target-intel:", "hunt-starter:")

        self.assertIn("tools/live-target-intelligence-report.py", body)
        self.assertIn("tools/semantic-predicate-gate.py", body)
        self.assertIn("tools/defender-narrative-simulator.py", body)
        self.assertIn("tools/post-filing-outcome-replay-pattern-distiller.py", body)
        self.assertIn('"$(_WS_RESOLVED)/.auditooor/dns_advisory.json"', body)
        self.assertIn(
            '--out-json "$(_WS_RESOLVED)/.auditooor/pforpd_replay_patterns.json"',
            body,
        )

    def test_live_target_intel_wires_p5_mvp3_triager_precheck_budget(self) -> None:
        body = self._target_body("live-target-intel:", "hunt-starter:")

        self.assertIn("# live-target-intel (P5 MVP3)", self.text)
        self.assertIn("[TRIAGER_PRECHECK_BUDGET=10]", body)
        self.assertIn("tools/live-target-intelligence-report.py", body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', body)
        self.assertIn('--top-n "$(if $(TOP_N),$(TOP_N),50)"', body)
        self.assertIn(
            '--triager-precheck-budget "$(if $(TRIAGER_PRECHECK_BUDGET),$(TRIAGER_PRECHECK_BUDGET),10)"',
            body,
        )

        dry_run = self._make_dry_run(
            "live-target-intel",
            "WS=/tmp/auditooor-abs-ws",
            "TRIAGER_PRECHECK_BUDGET=17",
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertIn('--triager-precheck-budget "17"', dry_run.stdout)

    def test_live_target_intel_wires_semantic_predicate_gate_after_report(self) -> None:
        body = self._target_body("live-target-intel:", "hunt-starter:")

        self.assertIn("tools/live-target-intelligence-report.py", body)
        self.assertIn("tools/semantic-predicate-gate.py", body)
        self.assertIn('--apply-to-report "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json"', body)
        self.assertIn('--report-markdown-output "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md"', body)
        self.assertLess(
            body.index("tools/live-target-intelligence-report.py"),
            body.index("tools/semantic-predicate-gate.py"),
        )

    def test_audit_fast_wires_semantic_predicate_gate_after_report(self) -> None:
        body = self._target_body("audit-fast:", "audit:")

        self.assertIn("tools/live-target-intelligence-report.py", body)
        self.assertIn("tools/semantic-predicate-gate.py", body)
        self.assertIn('--apply-to-report "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.json"', body)
        self.assertIn('--report-markdown-output "$(_WS_RESOLVED)/docs/LIVE_TARGET_REPORT.md"', body)
        self.assertLess(
            body.index("tools/live-target-intelligence-report.py"),
            body.index("tools/semantic-predicate-gate.py"),
        )

    def test_audit_runs_preflight_after_core_audit(self) -> None:
        body = self._target_body("audit:", "audit-deep:")

        self.assertIn('$(MAKE) --no-print-directory audit-preflight WS="$(_WS_RESOLVED)"', body)
        self.assertIn("CAP-GAP-97 pre-flight packs are advisory", body)
        self.assertLess(
            body.index("python3 tools/audit-progress.py"),
            body.index("audit-preflight WS=\"$(_WS_RESOLVED)\""),
        )
        preflight_pos = body.index("audit-preflight WS=\"$(_WS_RESOLVED)\"")
        self.assertGreater(body.find("python3 tools/memory-auto-link.py", preflight_pos), preflight_pos)

    def test_audit_deep_and_closeout_emit_queue_and_field_reports(self) -> None:
        audit_deep_index = self.text.index("audit-deep:")
        closeout_index = self.text.index("audit-closeout:")
        after_audit_deep = self.text[audit_deep_index:]
        after_closeout = self.text[closeout_index:]

        self.assertIn('queue-proof-hard-close WS="$$ws"', after_audit_deep)
        self.assertIn('chained-attack-plans WS="$$ws"', after_audit_deep)
        self.assertIn('prove-top-leads WS="$$ws"', after_audit_deep)
        self.assertIn('prove-top-leads WS="$$ws" TOP_N="$(if $(TOP_N),$(TOP_N),10)" STRICT=1 JSON=1', after_audit_deep)
        self.assertIn('field-validation-report WS="$$ws"', after_audit_deep)
        self.assertIn('field-validation-report WS="$$ws" STRICT=1', after_audit_deep)
        self.assertIn('v3-roadmap-sidecars WS="$$ws"', after_audit_deep)
        self.assertIn('v3-roadmap-sidecars WS="$$ws" STRICT_HACKERMAN_V3=1', after_audit_deep)
        self.assertIn('live-target-intel WS="$$ws" IF_STALE_ONLY=1 $(if $(STRICT),STRICT=1)', after_audit_deep)
        self.assertIn("[audit-deep] WARN live-target-intel failed rc=$$lt_rc; continuing (live-target context advisory)", after_audit_deep)
        self.assertIn("phase-b-e-measurement-report JSON=1", after_audit_deep)
        self.assertIn('queue-proof-hard-close WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) $(if $(STRICT),STRICT=1)', after_closeout)
        self.assertIn('field-validation-report WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) $(if $(STRICT),STRICT=1)', after_closeout)
        self.assertIn('v3-roadmap-sidecars WS="$(_WS_RESOLVED)" $(if $(JSON),JSON=1) $(if $(STRICT),STRICT_HACKERMAN_V3=1)', after_closeout)
        self.assertIn("$(if $(STRICT),--require-strict-wiring)", after_closeout)
        self.assertIn("NOTE STRICT queue-proof-hard-close non-fatal", after_audit_deep)
        self.assertIn("NOTE STRICT field-validation-report non-fatal", after_audit_deep)
        self.assertIn("NOTE STRICT v3-roadmap-sidecars non-fatal", after_audit_deep)

    def test_audit_deep_overnight_delegates_to_full_profile(self) -> None:
        overnight_body = self._target_body("audit-deep-overnight:", "audit-deep-full:")

        self.assertIn("delegating to audit-deep-full", overnight_body)
        self.assertIn("$(MAKE) --no-print-directory audit-deep-full", overnight_body)
        self.assertIn('WS="$(_WS_RESOLVED)"', overnight_body)
        self.assertIn('TOP_N="$(if $(TOP_N),$(TOP_N),25)"', overnight_body)
        self.assertIn('$(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)")', overnight_body)
        self.assertIn("$(if $(JSON),JSON=1)", overnight_body)

    def test_audit_deep_full_owns_strict_profile_and_engine_timeouts(self) -> None:
        full_body = self._target_body("audit-deep-full:", "v3-source-first-audit:")

        self.assertIn("AUDIT_DEEP_REQUIRE_MCP_PREFLIGHT=1", full_body)
        self.assertIn("REQUIRE_RECENT_RECALL=1", full_body)
        self.assertIn("AUDIT_DEEP_SKIP_AUDIT_PREREQ=1", full_body)
        self.assertIn("AUDITOOOR_AUDIT_DEEP_LIVE=1", full_body)
        self.assertIn("HALMOS_TIMEOUT=900", full_body)
        self.assertIn("MEDUSA_TIMEOUT=1800", full_body)
        self.assertIn("ECHIDNA_TIMEOUT=1800", full_body)
        self.assertIn("$(MAKE) --no-print-directory audit-deep", full_body)
        self.assertIn('WS="$(_WS_RESOLVED)"', full_body)
        self.assertIn("LIVE=1", full_body)
        self.assertIn("DEEP_PROFILE=all", full_body)
        self.assertIn('TOP_N="$(if $(TOP_N),$(TOP_N),25)"', full_body)
        self.assertIn("STRICT=1", full_body)
        self.assertIn('$(if $(PROJECT_ROOT),PROJECT_ROOT="$(PROJECT_ROOT)")', full_body)
        self.assertIn("$(if $(JSON),JSON=1)", full_body)

    def test_audit_deep_commit_mining_runs_only_for_explicit_deep_run(self) -> None:
        audit_deep_body = self._target_body("audit-deep:", "audit-deep-medium:")

        self.assertIn('AUDIT_DEEP_RUN_COMMIT_MINING=1', audit_deep_body)
        self.assertIn('[ -n "$(AUDIT_DEEP_SKIP_AUDIT_PREREQ)" ] || [ "$(AUDIT_DEEP_RUN_COMMIT_MINING)" = "1" ]', audit_deep_body)
        self.assertIn("make audit already owns the default pre-deep mining step", audit_deep_body)
        self.assertIn("audit-target-commit-mining", audit_deep_body)

    def test_audit_deep_mixed_language_runs_generic_after_solidity(self) -> None:
        audit_deep_body = self._target_body("audit-deep:", "audit-deep-medium:")

        self.assertIn("has_generic_src=0", audit_deep_body)
        self.assertIn("*.rs", audit_deep_body)
        self.assertIn("*.go", audit_deep_body)
        self.assertIn("Mixed-language workspace detected; running generic Rust/Go deep profile after Solidity engines", audit_deep_body)
        self.assertLess(
            audit_deep_body.index("audit-deep-solidity"),
            audit_deep_body.index("Mixed-language workspace detected; running generic Rust/Go deep profile after Solidity engines"),
        )
        self.assertIn('bash tools/audit-deep.sh $(if $(LIVE),--live)', audit_deep_body)

    def test_audit_deep_solidity_generates_per_function_invariants(self) -> None:
        body = self._target_body("audit-deep-solidity:", "audit-deep-per-contract:")

        self.assertIn("per-function-invariant-gen", body)
        self.assertIn("tools/per-function-invariant-gen.py --workspace \"$$ws\"", body)
        self.assertLess(
            body.index("composition-fixtures"),
            body.index("per-function-invariant-gen"),
        )
        self.assertLess(
            body.index("per-function-invariant-gen"),
            body.index("halmos-runner"),
        )

    def test_audit_deep_solidity_manifest_includes_denominator_fields(self) -> None:
        body = self._target_body("audit-deep-solidity:", "audit-deep-per-contract:")

        for key in (
            "generated_per_function_manifest",
            "generated_per_function_harness_count",
            "available_engine_harness_roots",
            "available_engine_harness_count",
            "selected_project_root",
            "selected_engine_harness_root",
            "executed_engine_harness_count",
            "executed_generated_harness_count",
            "invariant_denominator_status",
        ):
            self.assertIn(f'"{key}"', body)

    def test_audit_run_full_freshness_checks_require_full_invariant_denominator(self) -> None:
        self.assertEqual(
            self.text.count("audit-deep-manifest.py --workspace \"$(_WS_RESOLVED)\" --check-fresh"),
            3,
        )
        self.assertEqual(self.text.count("--require-full-invariant-denominator"), 3)
        self.assertIn(
            "audit-deep-manifest.py --workspace \"$(_WS_RESOLVED)\" --check-fresh --require-full-invariant-denominator",
            self.text,
        )

    def test_hunt_full_skips_commit_mining_in_deep_step(self) -> None:
        hunt_full_body = self._target_body("hunt-full:", "hunt-time-fuzz:")

        self.assertIn('$(MAKE) --no-print-directory audit WS="$(_WS_RESOLVED)"', hunt_full_body)
        self.assertIn('AUDIT_COMMIT_MINING_SKIP=1 $(MAKE) --no-print-directory audit-deep-full', hunt_full_body)
        self.assertLess(
            hunt_full_body.index('$(MAKE) --no-print-directory audit WS="$(_WS_RESOLVED)"'),
            hunt_full_body.index('AUDIT_COMMIT_MINING_SKIP=1 $(MAKE) --no-print-directory audit-deep-full'),
        )

    def test_hunt_full_fast_ranked_surface_is_advisory(self) -> None:
        hunt_full_body = self._target_body("hunt-full:", "hunt-time-fuzz:")

        deterministic = hunt_full_body.index("hunt-deterministic WS=\"$(_WS_RESOLVED)\"")
        fast_surface = hunt_full_body.index("hunt WS=\"$(_WS_RESOLVED)\"", deterministic)
        warning = hunt_full_body.index(
            "WARN fast ranked-candidate surface returned non-zero",
            fast_surface,
        )
        zk_step = hunt_full_body.index("[make hunt-full] Step 5/5", warning)

        self.assertLess(deterministic, fast_surface)
        self.assertLess(fast_surface, warning)
        self.assertLess(warning, zk_step)
        self.assertIn("hunt-deterministic is the gated completion path", hunt_full_body)

    def test_audit_deep_full_refreshes_mcp_recall_before_preflight(self) -> None:
        full_body = self._target_body("audit-deep-full:", "v3-source-first-audit:")

        self.assertIn('bash tools/auditooor-session-start.sh "$(_WS_RESOLVED)"', full_body)
        self.assertLess(
            full_body.index('bash tools/auditooor-session-start.sh "$(_WS_RESOLVED)"'),
            full_body.index("AUDIT_DEEP_REQUIRE_MCP_PREFLIGHT=1 REQUIRE_RECENT_RECALL=1"),
        )

    def test_v3_source_first_audit_wraps_overnight_and_row_gate(self) -> None:
        source_first_index = self.text.index("v3-source-first-audit:")
        prereq_gate_index = self.text.index("v3-source-first-prereq-gate:", source_first_index)
        prereq_test_index = self.text.index("v3-source-first-prereq-gate-test:", prereq_gate_index)
        prior_dupe_index = self.text.index("v3-source-first-prior-audit-dupe-gate:", prereq_test_index)
        row_gate_index = self.text.index("v3-source-first-row-gate:", prior_dupe_index)
        test_index = self.text.index("v3-source-first-row-gate-test:", row_gate_index)
        source_first_body = self.text[source_first_index:prereq_gate_index]
        prereq_gate_body = self.text[prereq_gate_index:prereq_test_index]
        prereq_test_body = self.text[prereq_test_index:prior_dupe_index]
        prior_dupe_body = self.text[prior_dupe_index:row_gate_index]
        row_gate_body = self.text[row_gate_index:test_index]
        row_gate_test_body = self.text[test_index:]

        self.assertIn("AUDIT_COMMIT_MINING_SKIP", source_first_body)
        self.assertIn("SOURCE_FIRST_ALLOW_COMMIT_MINING_SKIP", source_first_body)
        self.assertIn("v3-source-first-prereq-gate", source_first_body)
        self.assertIn("PHASE=pre", source_first_body)
        self.assertIn("audit-deep-overnight", source_first_body)
        self.assertIn("PHASE=post", source_first_body)
        self.assertIn('WS="$(_WS_RESOLVED)"', source_first_body)
        self.assertIn('TOP_N="$(if $(TOP_N),$(TOP_N),25)"', source_first_body)
        self.assertIn("v3-source-first-prior-audit-dupe-gate", source_first_body)
        self.assertIn("source_first_prior_audit_dupe_gate.json", source_first_body)
        self.assertIn("v3-source-first-row-gate", source_first_body)
        self.assertIn("STRICT=1", source_first_body)
        self.assertLess(source_first_body.index("PHASE=pre"), source_first_body.index("audit-deep-overnight"))
        self.assertLess(source_first_body.index("audit-deep-overnight"), source_first_body.index("PHASE=post"))
        self.assertLess(source_first_body.index("PHASE=post"), source_first_body.index("v3-source-first-prior-audit-dupe-gate"))
        self.assertLess(source_first_body.index("v3-source-first-prior-audit-dupe-gate"), source_first_body.index("v3-source-first-row-gate"))

        self.assertIn("tools/v3-source-first-prereq-gate.py", prereq_gate_body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', prereq_gate_body)
        self.assertIn('--phase "$(PHASE)"', prereq_gate_body)
        self.assertIn('$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/v3_source_first_prereq_gate_$(PHASE).json)', prereq_gate_body)
        self.assertIn('$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/v3_source_first_prereq_gate_$(PHASE).md)', prereq_gate_body)
        self.assertIn("$(if $(STRICT),--strict)", prereq_gate_body)
        self.assertIn("$(if $(JSON),--print-json)", prereq_gate_body)
        self.assertIn("python3 -m unittest tools.tests.test_v3_source_first_prereq_gate -v", prereq_test_body)

        self.assertIn("tools/prior-audit-dupe-gate.py", prior_dupe_body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', prior_dupe_body)
        self.assertIn('--queue "$$queue"', prior_dupe_body)
        self.assertIn('--top-n "$(if $(TOP_N),$(TOP_N),25)"', prior_dupe_body)
        self.assertIn("$(_WS_RESOLVED)/.auditooor/exploit_queue.source_mined.json", prior_dupe_body)
        self.assertIn("$(_WS_RESOLVED)/.auditooor/exploit_queue.json", prior_dupe_body)
        self.assertIn("$(_WS_RESOLVED)/.auditooor/source_first_prior_audit_dupe_gate.json", prior_dupe_body)
        self.assertIn("--json > \"$$tmp\"", prior_dupe_body)
        self.assertIn("[ $$rc -ne 1 ]", prior_dupe_body)
        self.assertIn("[ $$rc -ne 2 ]", prior_dupe_body)
        self.assertIn('mv "$$tmp" "$$out"', prior_dupe_body)

        self.assertIn("tools/v3-source-first-row-gate.py", row_gate_body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', row_gate_body)
        self.assertIn('$(if $(QUEUE),--queue "$(QUEUE)")', row_gate_body)
        self.assertIn('--prior-audit-dupe "$(if $(PRIOR_AUDIT_DUPE),$(PRIOR_AUDIT_DUPE),$(_WS_RESOLVED)/.auditooor/source_first_prior_audit_dupe_gate.json)"', row_gate_body)
        self.assertIn('$(if $(OUT_JSON),$(OUT_JSON),$(_WS_RESOLVED)/.auditooor/v3_source_first_row_gate.json)', row_gate_body)
        self.assertIn('$(if $(OUT_MD),$(OUT_MD),$(_WS_RESOLVED)/.auditooor/v3_source_first_row_gate.md)', row_gate_body)
        self.assertIn("$(if $(STRICT),--strict)", row_gate_body)
        self.assertIn("$(if $(JSON),--print-json)", row_gate_body)
        self.assertIn("python3 -m unittest tools.tests.test_v3_source_first_row_gate -v", row_gate_test_body)

    def test_v3_source_first_audit_rejects_commit_mining_skip_without_explicit_allow(self) -> None:
        source_first_body = self._target_body(
            "v3-source-first-audit:",
            "v3-source-first-prereq-gate:",
        )

        self.assertIn(
            'if [ -n "$(AUDIT_COMMIT_MINING_SKIP)" ] && [ "$(SOURCE_FIRST_ALLOW_COMMIT_MINING_SKIP)" != "1" ]; then',
            source_first_body,
        )
        self.assertIn(
            "AUDIT_COMMIT_MINING_SKIP is not allowed for source-first audit unless SOURCE_FIRST_ALLOW_COMMIT_MINING_SKIP=1",
            source_first_body,
        )
        self.assertLess(
            source_first_body.index("AUDIT_COMMIT_MINING_SKIP"),
            source_first_body.index("v3-source-first-prereq-gate"),
        )

        with tempfile.TemporaryDirectory() as workspace:
            result = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "v3-source-first-audit",
                    f"WS={workspace}",
                    "AUDIT_COMMIT_MINING_SKIP=1",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        combined_output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, combined_output)
        self.assertIn("AUDIT_COMMIT_MINING_SKIP is not allowed", combined_output)

    def test_v3_source_first_json_expands_to_print_json_for_prereq_and_row_gate(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            prereq_result = self._make_dry_run(
                "v3-source-first-prereq-gate",
                f"WS={workspace}",
                "PHASE=pre",
                "JSON=1",
            )
            row_result = self._make_dry_run(
                "v3-source-first-row-gate",
                f"WS={workspace}",
                "JSON=1",
            )
            prior_dupe_result = self._make_dry_run(
                "v3-source-first-prior-audit-dupe-gate",
                f"WS={workspace}",
                "JSON=1",
            )

        prereq_output = prereq_result.stdout + prereq_result.stderr
        row_output = row_result.stdout + row_result.stderr
        prior_dupe_output = prior_dupe_result.stdout + prior_dupe_result.stderr

        self.assertEqual(prereq_result.returncode, 0, prereq_output)
        self.assertIn("tools/v3-source-first-prereq-gate.py", prereq_output)
        self.assertIn("--print-json", prereq_output)

        self.assertEqual(row_result.returncode, 0, row_output)
        self.assertIn("tools/v3-source-first-row-gate.py", row_output)
        self.assertIn("--print-json", row_output)

        self.assertEqual(prior_dupe_result.returncode, 0, prior_dupe_output)
        self.assertIn("tools/prior-audit-dupe-gate.py", prior_dupe_output)
        self.assertIn("--json >", prior_dupe_output)
        self.assertIn("source_first_prior_audit_dupe_gate.json", prior_dupe_output)
        self.assertIn('cat "$out"', prior_dupe_output)

    def test_v3_source_first_prior_audit_dupe_gate_writes_queue_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            workspace_path = Path(workspace)
            queue = workspace_path / ".auditooor" / "exploit_queue.source_mined.json"
            queue.parent.mkdir()
            queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.exploit_queue.source_mined.v1",
                        "queue": [{"lead_id": "EQ-001", "title": "source-mined candidate"}],
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "v3-source-first-prior-audit-dupe-gate",
                    f"WS={workspace}",
                    "JSON=1",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            artifact = workspace_path / ".auditooor" / "source_first_prior_audit_dupe_gate.json"
            combined_output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, combined_output)
            self.assertTrue(artifact.is_file(), combined_output)
            data = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], "auditooor.prior_audit_dupe_gate.v1")
            self.assertEqual(data["mode"], "queue")
            self.assertEqual(data["verdict_summary"], "no-prior-audits")
            self.assertTrue(data["gate_pass"])

    def test_source_mined_impact_contracts_target_writes_and_can_patch_queue(self) -> None:
        target_index = self.text.index("source-mined-impact-contracts:")
        test_index = self.text.index("source-mined-impact-contracts-test:", target_index)
        body = self.text[target_index:test_index]
        test_body = self.text[test_index:]

        self.assertIn("tools/source-mined-impact-contracts.py", body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', body)
        self.assertIn('$(if $(QUEUE),--queue "$(QUEUE)")', body)
        self.assertIn('$(if $(OUT_JSON),--out-json "$(OUT_JSON)")', body)
        self.assertIn("$(if $(UPDATE_QUEUE),--update-queue)", body)
        self.assertIn("$(if $(JSON),--print-json)", body)
        self.assertIn("python3 -m unittest tools.tests.test_source_mined_impact_contracts -v", test_body)

    def test_new_helper_cli_make_targets_are_opt_in_and_testable(self) -> None:
        triager_body = self._target_body(
            "triager-pre-filing-simulator:",
            "triager-pre-filing-simulator-test:",
        )
        field_gaps_body = self._target_body(
            "field-validation-platform-id-gaps:",
            "field-validation-platform-id-gaps-test:",
        )
        source_actions_body = self._target_body(
            "source-miner-backlog-actions:",
            "source-miner-backlog-actions-test:",
        )
        phase_b_e_body = self._target_body(
            "phase-b-e-measurement-report:",
            "phase-b-e-measurement-report-test:",
        )
        p4_readiness_body = self._target_body(
            "p4-provider-readiness-probe:",
            "p4-provider-readiness-probe-test:",
        )

        self.assertIn("tools/triager-pre-filing-simulator.py", triager_body)
        self.assertIn("WS=<workspace> DRAFT=<draft.md>", triager_body)
        self.assertIn('--draft "$(DRAFT)"', triager_body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', triager_body)
        self.assertIn('$(if $(SEVERITY),--severity "$(SEVERITY)")', triager_body)
        self.assertIn('if [ -n "$(OUT_JSON)" ]; then', triager_body)
        self.assertIn('> "$(OUT_JSON)"', triager_body)
        self.assertIn('cat "$(OUT_JSON)"', triager_body)
        self.assertIn(
            "python3 -m unittest tools.tests.test_triager_pre_filing_simulator -v",
            self.text,
        )

        self.assertIn("tools/field-validation-platform-id-gaps.py", field_gaps_body)
        self.assertIn("WS=<workspace>", field_gaps_body)
        self.assertIn('--workspace "$(_WS_RESOLVED)"', field_gaps_body)
        self.assertIn('$(if $(SUBMISSIONS),--submissions "$(SUBMISSIONS)")', field_gaps_body)
        self.assertIn('$(if $(OUTCOMES),--outcomes "$(OUTCOMES)")', field_gaps_body)
        self.assertIn('$(if $(PENDING),--pending "$(PENDING)")', field_gaps_body)
        self.assertIn("field_validation_platform_id_gaps.json", field_gaps_body)
        self.assertIn("field_validation_platform_id_gaps.md", field_gaps_body)
        self.assertIn("$(if $(JSON),--json)", field_gaps_body)
        self.assertIn(
            "python3 -m unittest tools.tests.test_field_validation_platform_id_gaps -v",
            self.text,
        )

        self.assertIn("tools/source-miner-backlog-actions.py", source_actions_body)
        self.assertIn("--closure-summary", source_actions_body)
        self.assertIn("lane_V3_REMAINING_SOURCE_MINERS_CLOSURE/summary.json", source_actions_body)
        self.assertIn("--dashboard", source_actions_body)
        self.assertIn(".auditooor/mining_coverage_dashboard.json", source_actions_body)
        self.assertIn("--out", source_actions_body)
        self.assertIn("--markdown-out", source_actions_body)
        self.assertIn("lane_V3_SOURCE_MINER_BACKLOG_ACTIONS", source_actions_body)
        self.assertIn('$(if $(GENERATED_ON),--generated-on "$(GENERATED_ON)")', source_actions_body)
        self.assertIn("$(if $(JSON),--json)", source_actions_body)
        self.assertIn(
            "python3 -m unittest tools.tests.test_source_miner_backlog_actions -v",
            self.text,
        )

        self.assertIn("tools/phase-b-e-measurement-report.py", phase_b_e_body)
        self.assertIn('$(if $(P1_TRIAGE),--p1-triage "$(P1_TRIAGE)")', phase_b_e_body)
        self.assertIn(
            '$(if $(P3_MEASUREMENT),--p3-measurement "$(P3_MEASUREMENT)")',
            phase_b_e_body,
        )
        self.assertIn(
            '$(if $(PRQS_COMPARATOR),--prqs-comparator "$(PRQS_COMPARATOR)")',
            phase_b_e_body,
        )
        self.assertIn(
            '$(if $(PHASE_E_ROWS),--phase-e-rows "$(PHASE_E_ROWS)")',
            phase_b_e_body,
        )
        self.assertIn('$(if $(OUT_DIR),--output-dir "$(OUT_DIR)")', phase_b_e_body)
        self.assertIn("$(if $(JSON),--json)", phase_b_e_body)
        self.assertIn(
            "python3 -m unittest tools.tests.test_phase_b_e_measurement_report -v",
            self.text,
        )

        self.assertIn("tools/p4-provider-readiness-probe.py", p4_readiness_body)
        self.assertIn('--root "$(if $(ROOT),$(ROOT),$(CURDIR))"', p4_readiness_body)
        self.assertIn(
            '$(foreach preflight,$(PREFLIGHT_JSON),--preflight-json "$(preflight)")',
            p4_readiness_body,
        )
        self.assertIn('$(if $(OUT_JSON),--out "$(OUT_JSON)")', p4_readiness_body)
        self.assertIn('$(if $(OUT_MD),--markdown-out "$(OUT_MD)")', p4_readiness_body)
        self.assertIn(
            '$(if $(GENERATED_AT_UTC),--generated-at-utc "$(GENERATED_AT_UTC)")',
            p4_readiness_body,
        )
        self.assertIn("$(if $(JSON),--print-json)", p4_readiness_body)
        self.assertIn(
            "python3 -m unittest tools.tests.test_p4_provider_readiness_probe -v",
            self.text,
        )

    def test_new_helper_cli_make_targets_expand_expected_flags(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            workspace_path = Path(workspace)
            draft = workspace_path / "draft.md"
            draft.write_text("# Candidate\n", encoding="utf-8")

            triager = self._make_dry_run(
                "triager-pre-filing-simulator",
                f"WS={workspace}",
                f"DRAFT={draft}",
                "SEVERITY=High",
                f"OUT_JSON={workspace_path / 'triager.json'}",
                "JSON=1",
            )
            field_gaps = self._make_dry_run(
                "field-validation-platform-id-gaps",
                f"WS={workspace}",
                f"SUBMISSIONS={workspace_path / 'submissions.md'}",
                f"OUTCOMES={workspace_path / 'outcomes.jsonl'}",
                f"PENDING={workspace_path / 'pending.jsonl'}",
                "JSON=1",
            )
            source_actions = self._make_dry_run(
                "source-miner-backlog-actions",
                f"OUT_DIR={workspace_path / 'source-actions'}",
                f"CLOSURE_SUMMARY={workspace_path / 'closure.json'}",
                f"DASHBOARD={workspace_path / 'dashboard.json'}",
                "GENERATED_ON=2026-05-24",
                "JSON=1",
            )
            phase_b_e = self._make_dry_run(
                "phase-b-e-measurement-report",
                f"P1_TRIAGE={workspace_path / 'p1.json'}",
                f"P3_MEASUREMENT={workspace_path / 'p3.json'}",
                f"PRQS_COMPARATOR={workspace_path / 'prqs.json'}",
                f"PHASE_E_ROWS={workspace_path / 'phase_e_rows.jsonl'}",
                f"OUT_DIR={workspace_path / 'phase-b-e'}",
                "JSON=1",
            )
            p4_readiness = self._make_dry_run(
                "p4-provider-readiness-probe",
                f"ROOT={ROOT}",
                f"PREFLIGHT_JSON={workspace_path / 'llm_preflight.json'}",
                f"OUT_JSON={workspace_path / 'p4_provider_readiness.json'}",
                f"OUT_MD={workspace_path / 'p4_provider_readiness.md'}",
                "GENERATED_AT_UTC=2026-05-24T00:00:00Z",
                "JSON=1",
            )

        triager_output = triager.stdout + triager.stderr
        field_gaps_output = field_gaps.stdout + field_gaps.stderr
        source_actions_output = source_actions.stdout + source_actions.stderr
        phase_b_e_output = phase_b_e.stdout + phase_b_e.stderr
        p4_readiness_output = p4_readiness.stdout + p4_readiness.stderr

        self.assertEqual(triager.returncode, 0, triager_output)
        self.assertIn("tools/triager-pre-filing-simulator.py", triager_output)
        self.assertIn("--severity \"High\"", triager_output)
        self.assertIn("triager.json", triager_output)
        self.assertIn("cat", triager_output)

        self.assertEqual(field_gaps.returncode, 0, field_gaps_output)
        self.assertIn("tools/field-validation-platform-id-gaps.py", field_gaps_output)
        self.assertIn("--submissions", field_gaps_output)
        self.assertIn("--outcomes", field_gaps_output)
        self.assertIn("--pending", field_gaps_output)
        self.assertIn("field_validation_platform_id_gaps.json", field_gaps_output)
        self.assertIn("--json", field_gaps_output)

        self.assertEqual(source_actions.returncode, 0, source_actions_output)
        self.assertIn("tools/source-miner-backlog-actions.py", source_actions_output)
        self.assertIn("closure.json", source_actions_output)
        self.assertIn("dashboard.json", source_actions_output)
        self.assertIn("source-actions/summary.json", source_actions_output)
        self.assertIn("source-actions/results.md", source_actions_output)
        self.assertIn("--generated-on \"2026-05-24\"", source_actions_output)
        self.assertIn("--json", source_actions_output)

        self.assertEqual(phase_b_e.returncode, 0, phase_b_e_output)
        self.assertIn("tools/phase-b-e-measurement-report.py", phase_b_e_output)
        self.assertIn("--p1-triage", phase_b_e_output)
        self.assertIn("p1.json", phase_b_e_output)
        self.assertIn("--p3-measurement", phase_b_e_output)
        self.assertIn("--prqs-comparator", phase_b_e_output)
        self.assertIn("--phase-e-rows", phase_b_e_output)
        self.assertIn("phase_e_rows.jsonl", phase_b_e_output)
        self.assertIn("--output-dir", phase_b_e_output)
        self.assertIn("phase-b-e", phase_b_e_output)
        self.assertIn("--json", phase_b_e_output)

        self.assertEqual(p4_readiness.returncode, 0, p4_readiness_output)
        self.assertIn("tools/p4-provider-readiness-probe.py", p4_readiness_output)
        self.assertIn("--root", p4_readiness_output)
        self.assertIn("--preflight-json", p4_readiness_output)
        self.assertIn("llm_preflight.json", p4_readiness_output)
        self.assertIn("--out", p4_readiness_output)
        self.assertIn("p4_provider_readiness.json", p4_readiness_output)
        self.assertIn("--markdown-out", p4_readiness_output)
        self.assertIn("p4_provider_readiness.md", p4_readiness_output)
        self.assertIn("--generated-at-utc \"2026-05-24T00:00:00Z\"", p4_readiness_output)
        self.assertIn("--print-json", p4_readiness_output)

    def test_prove_top_leads_runs_prefiling_and_outcome_lesson_before_harness_work(self) -> None:
        prove_index = self.text.index("prove-top-leads:")
        loop_index = self.text.index("exploit-conversion-loop:")
        prove_body = self.text[prove_index:loop_index]

        self.assertIn("tools/outcome-lesson-gate.py", prove_body)
        self.assertIn('--candidate-json "$$queue"', prove_body)
        self.assertNotIn('--draft "$$queue"', prove_body)
        self.assertIn("prove_top_leads_outcome_lesson_gate.json", prove_body)
        self.assertIn("prefiling-stress-test", prove_body)
        self.assertIn('QUEUE="$$queue"', prove_body)
        self.assertIn("prove_top_leads_prefiling_stress_test.json", prove_body)
        self.assertIn("candidate-judgment-packet", prove_body)
        self.assertIn("prove_top_leads_candidate_judgment_packet.json", prove_body)
        self.assertIn("judgment packets are advisory", prove_body)
        self.assertIn("source-mined-impact-contracts", prove_body)
        self.assertIn("prove_top_leads_source_mined_impact_contracts.json", prove_body)
        self.assertIn("UPDATE_QUEUE=1", prove_body)
        self.assertIn("tools/agent-artifact-lesson-candidates.py", prove_body)
        self.assertIn("agent_artifact_lesson_candidates.json", prove_body)
        self.assertIn("tools/lesson-source-inventory.py", prove_body)
        self.assertIn("lesson_source_inventory.json", prove_body)
        self.assertIn("tools/lesson-enforcement-inventory.py", prove_body)
        self.assertIn("lesson_enforcement_inventory.json", prove_body)
        self.assertIn("prefiling-stress-test blocked proof work", prove_body)
        self.assertIn("$(if $(filter 1 true yes,$(STRICT)),--strict)", prove_body)
        self.assertIn('mkdir -p "$(_WS_RESOLVED)/.auditooor"', prove_body)
        self.assertIn('if [ -n "$(filter 1 true yes,$(STRICT))" ]; then', prove_body)
        self.assertIn('if [ ! -f "$$queue" ]; then queue="$(_WS_RESOLVED)/.auditooor/exploit_queue.json"; fi', prove_body)
        self.assertIn('src_inv="$(_WS_RESOLVED)/.auditooor/lesson_source_inventory.json"', prove_body)
        self.assertIn("--source-inventory \"$$src_inv\"", prove_body)
        self.assertIn("tools/prove-top-leads.py", prove_body)
        self.assertIn("prove_top_leads_queue_semantics.json", prove_body)
        self.assertIn("--harness-queue \"$(_WS_RESOLVED)/.auditooor/harness_execution_queue_from_exploit_queue.json\"", prove_body)
        self.assertIn("$${ENFORCE_AUTONOMOUS_PROOF_CONVERSION:-}", prove_body)
        self.assertIn("REQUIRE_STRICT_WIRING", prove_body)
        self.assertIn("$${strict_semantics:+--strict}", prove_body)
        self.assertIn("proof conversion semantics are advisory", prove_body)
        self.assertLess(
            prove_body.index("prefiling-stress-test"),
            prove_body.index("candidate-judgment-packet"),
        )
        self.assertLess(
            prove_body.index("source-mined-impact-contracts"),
            prove_body.index("prefiling-stress-test"),
        )
        self.assertLess(
            prove_body.index("candidate-judgment-packet"),
            prove_body.index("tools/agent-artifact-lesson-candidates.py"),
        )
        self.assertLess(
            prove_body.index("tools/agent-artifact-lesson-candidates.py"),
            prove_body.index("tools/lesson-source-inventory.py"),
        )
        self.assertLess(
            prove_body.index("tools/lesson-source-inventory.py"),
            prove_body.index("tools/lesson-enforcement-inventory.py"),
        )
        self.assertLess(
            prove_body.index("tools/lesson-enforcement-inventory.py"),
            prove_body.index("tools/outcome-lesson-gate.py"),
        )
        self.assertLess(
            prove_body.index("tools/outcome-lesson-gate.py"),
            prove_body.index("tools/harness-binding-manifest.py"),
        )
        self.assertLess(
            prove_body.index("prefiling-stress-test"),
            prove_body.index("tools/harness-binding-manifest.py"),
        )
        self.assertLess(
            prove_body.index("tools/harness-execution-queue.py"),
            prove_body.index("tools/prove-top-leads.py"),
        )
        semantics_body = prove_body[prove_body.index("tools/prove-top-leads.py") :]
        self.assertNotIn("$(STRICT)", semantics_body)

    def test_strict_closeout_and_pre_submit_wire_new_v3_gates(self) -> None:
        closeout_index = self.text.index("audit-closeout:")
        after_closeout = self.text[closeout_index:]
        pre_submit = (ROOT / "tools" / "pre-submit-check.sh").read_text(encoding="utf-8")

        self.assertIn('provider-keep-verification-backfill WS="$(_WS_RESOLVED)"', after_closeout)
        self.assertIn("provider_fanout_discipline_check.json", after_closeout)
        self.assertIn("v3-provider-campaign-completeness-gate", self.text)
        self.assertIn("--require-mcp-context", self.text)
        self.assertIn("lesson-source-inventory.py", self.text)
        self.assertIn("lesson-promotion-review-queue.py", self.text)
        self.assertIn('INPUT_JSON="$$pfd_json"', after_closeout)
        self.assertIn('BACKFILL_JSON="$$backfill_json"', after_closeout)
        self.assertIn('QUEUE="$$backfill_queue_json"', after_closeout)
        self.assertIn('hacker-question-workflow-audit WS="$(_WS_RESOLVED)" JSON=1 STRICT=1', after_closeout)
        self.assertIn('agent-artifact-mine WS="$(_WS_RESOLVED)"', after_closeout)
        self.assertIn("OUTCOME-LESSON-GATE", pre_submit)
        self.assertIn("outcome-lesson-gate.py", pre_submit)
        self.assertIn("lesson_source_inventory.json", pre_submit)
        self.assertIn("--source-inventory", pre_submit)
        self.assertIn("PREFILING-STRESS-ARTIFACT", pre_submit)
        self.assertIn("prefiling_stress_test.json", pre_submit)
        self.assertIn("CANDIDATE-JUDGMENT-PACKET", pre_submit)
        self.assertIn("candidate_judgment_packet.json", pre_submit)
        self.assertIn("strict_poc_planning_allowed", pre_submit)
        self.assertIn("--strict", pre_submit)

    def test_agent_artifact_mine_all_target_is_wired(self) -> None:
        target_index = self.text.index("agent-artifact-mine-all:")
        test_index = self.text.index("agent-artifact-mine-all-test:")
        body = self.text[target_index:test_index]

        self.assertIn('AUDITS_ROOT_PATH="$(if $(AUDITS_ROOT),$(AUDITS_ROOT),$(HOME)/audits)"', body)
        self.assertIn("tools/agent-artifact-mine-all.py", body)
        self.assertIn('--audits-root "$$AUDITS_ROOT_PATH"', body)
        self.assertIn('$(if $(WS),--workspace "$(_WS_RESOLVED)")', body)
        self.assertIn('$(if $(OUT),--out "$(OUT)")', body)
        self.assertIn("$(if $(DRY_RUN),--dry-run)", body)
        self.assertIn("$(if $(JSON),--json)", body)
        self.assertIn(
            "python3 -m unittest tools.tests.test_agent_artifact_mine_all -v",
            self.text[test_index:],
        )

    def test_worker_packet_auto_includes_hacker_question_obligations(self) -> None:
        target_index = self.text.index("v3-worker-packet:")
        next_target_index = self.text.index("v3-provider-fanout-queue:", target_index)
        body = self.text[target_index:next_target_index]

        self.assertIn("--auto-workspace-receipts", body)
        self.assertIn(".auditooor/hacker_question_obligations.jsonl", body)
        self.assertIn('--hacker-questions-file "$(_WS_RESOLVED)/.auditooor/hacker_question_obligations.jsonl"', body)

    def test_v3_roadmap_sidecars_refresh_field_validation_before_progress(self) -> None:
        sidecars_index = self.text.index("v3-roadmap-sidecars:")
        progress_index = self.text.index("v3-roadmap-progress-report:")
        sidecars_body = self.text[sidecars_index:progress_index]

        self.assertIn('field-validation-report WS="$(_WS_RESOLVED)"', sidecars_body)
        self.assertIn("tools/lesson-source-inventory.py", sidecars_body)
        self.assertIn("agent-artifact-lesson-candidates", sidecars_body)
        self.assertLess(
            sidecars_body.index("agent-artifact-lesson-candidates"),
            sidecars_body.index("tools/lesson-source-inventory.py"),
        )
        self.assertLess(
            sidecars_body.index("tools/lesson-source-inventory.py"),
            sidecars_body.index("tools/lesson-enforcement-inventory.py"),
        )
        self.assertIn("v3-provider-campaign-completeness-gate", sidecars_body)
        self.assertIn("audit-v3-enforcement-gate.py", sidecars_body)
        self.assertIn("STRICT_HACKERMAN_V3", sidecars_body)
        self.assertIn("GLOBAL_HACKERMAN_SIDECAR", sidecars_body)
        self.assertIn("skipping global hackerman-sidecar-coverage-report for workspace audit", sidecars_body)
        self.assertIn("anti-pattern-corpus-bootstrap", sidecars_body)
        self.assertIn('WORKSPACE="$(if $(WS),$(_WS_RESOLVED),.)"', sidecars_body)
        self.assertLess(
            sidecars_body.index('field-validation-report WS="$(_WS_RESOLVED)"'),
            sidecars_body.index("tools/v3-roadmap-progress-report.py"),
        )

    def test_p8_orphan_makefile_wrappers_are_wired(self) -> None:
        for target, tool in (
            ("depth-tools:", "tools/depth-tools-orchestrator.py"),
            ("agent-output-synth:", "tools/agent-output-synthesizer.py"),
            ("exploit-chain-correlator:", "tools/exploit-chain-correlator.py"),
            ("causal-chain-extract:", "tools/causal-chain-extract.py"),
            ("hackerman-function-shapes:", "tools/hackerman-backfill-solodit-function-shapes.py"),
            ("always-escalate-platform-oos-check:", "tools/always-escalate-platform-oos-check.py"),
        ):
            self.assertIn(target, self.text)
            self.assertIn(tool, self.text)

        phony_line = next(
            line
            for line in self.text.splitlines()
            if line.startswith(".PHONY:") and "orient-prefilter" in line
        )
        for target in (
            "orient-prefilter",
            "global-chain-template-library-build",
            "workflow-fullness-check",
            "depth-tools",
            "agent-output-synth",
            "exploit-chain-correlator",
            "causal-chain-extract",
            "hackerman-function-shapes",
            "always-escalate-platform-oos-check",
        ):
            self.assertIn(target, phony_line)

    def test_p8_orphan_wrappers_noop_without_inputs(self) -> None:
        for target, expected_note in (
            ("depth-tools", "WS=<workspace> not supplied; no-op."),
            ("agent-output-synth", "WS=<workspace> not supplied; no-op."),
            ("exploit-chain-correlator", "SOURCE=<path-or-url> not supplied; no-op."),
            ("always-escalate-platform-oos-check", "WS=<workspace> not supplied; no-op."),
        ):
            result = self._make_dry_run(target)
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertIn(expected_note, output)

    def test_p8_orphan_wrappers_pass_expected_cli_flags(self) -> None:
        with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as tmp:
            ws = Path(workspace)
            (ws / ".auditooor").mkdir()
            source = Path(tmp) / "postmortem.md"
            source.write_text("root cause then exploit then drain", encoding="utf-8")
            predicates = Path(tmp) / "predicates.jsonl"
            predicates.write_text('{"id":"p1","predicate":"unchecked transfer"}\n', encoding="utf-8")
            framing = Path(tmp) / "framing.txt"
            framing.write_text("theoretical vulnerability without demonstration", encoding="utf-8")

            cases = (
                (
                    ("depth-tools", f"WS={workspace}", "ALL=1", "DRY_RUN=1", "JSON=1"),
                    ("tools/depth-tools-orchestrator.py", f'--workspace "{workspace}"', "--all", "--dry-run", "--json"),
                ),
                (
                    ("agent-output-synth", f"WS={workspace}", "BRIEF_CANDIDATES=1"),
                    ("tools/agent-output-synthesizer.py", f'"{workspace}"', "agent_output_synthesis.json", "--brief-candidates"),
                ),
                (
                    ("exploit-chain-correlator", f"SOURCE={source}", "CHAIN=1", "GAP_SURFACE=1", "EXPORT_JSON=1"),
                    ("tools/exploit-chain-correlator.py", str(source), "--chain", "--gap-surface", "--export-json"),
                ),
                (
                    ("causal-chain-extract", f"INPUT={predicates}", f"OUTPUT={Path(tmp) / 'chains.jsonl'}", "LIMIT=3"),
                    ("tools/causal-chain-extract.py", f'input="{predicates}"', '--input "$input"', "--output", "--index-json", "--limit \"3\""),
                ),
                (
                    ("hackerman-function-shapes", "JSON=1"),
                    ("tools/hackerman-backfill-solodit-function-shapes.py", "--tag-dir", "--index-dir", "--dry-run", "--json-summary"),
                ),
                (
                    ("always-escalate-platform-oos-check", f"WS={workspace}", f"FRAMING_FILE={framing}", "JSON=1"),
                    ("tools/always-escalate-platform-oos-check.py", f'--workspace "{workspace}"', f'--framing-file "{framing}"', "--json"),
                ),
            )

            for args, needles in cases:
                result = self._make_dry_run(*args)
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, output)
                for needle in needles:
                    self.assertIn(needle, output)


if __name__ == "__main__":
    unittest.main()
