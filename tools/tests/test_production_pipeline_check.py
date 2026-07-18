# <!-- r36-rebuttal: lane-PR10-PRODUCTION-PIPELINE registered in .auditooor/agent_pathspec.json -->
"""Tests for tools/production-pipeline-check.py (PR10 FINAL gate orchestrator).

The orchestrator delegates every signal to L37 (audit-completeness-check), so
the all-pass fixture reuses L37's own ``_build_complete_ws`` helper to build a
workspace that satisfies EVERY stage. The tests then assert:

  - the FINAL gate FAILS-CLOSES when a required artifact is absent,
  - it PASSES when every required signal is satisfied under L37 policy,
  - the per-stage manifest is written in canonical (L37 _SIGNAL_ORDER) order,
  - the ADD-D fail-close branches (brain-prime, hacker-questions),
  - the PR10 new-stage fail-close branches (novel-vector, adversarial-panel)
    and the advisory-by-default EVM proof branch,
  - the stage ORDERING is the canonical L37 ordering,
  - STRICT threads into the engine-harness proof gate,
  - error handling for a bad workspace path.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "production-pipeline-check.py"

# Reuse the L37 test fixture builder (it builds a workspace that passes ALL
# L37 signals, incl. a real git clone for the hunt gate).
import importlib.util

_L37_TEST = Path(__file__).resolve().with_name("test_audit_completeness_check.py")
_spec = importlib.util.spec_from_file_location("_l37_test_helpers", _L37_TEST)
_l37t = importlib.util.module_from_spec(_spec)
sys.modules["_l37_test_helpers"] = _l37t
_spec.loader.exec_module(_l37t)

_build_complete_ws = _l37t._build_complete_ws
_write_json = _l37t._write_json
_convert_complete_ws_to_go = _l37t._convert_complete_ws_to_go
_write_audit_run_start = _l37t._write_audit_run_start
_write_fresh_audit_deep_manifest = _l37t._write_fresh_audit_deep_manifest
_write_typed_deep_skip = _l37t._write_typed_deep_skip


def _refresh_coverage_report(ws: Path) -> None:
    _write_json(ws / ".auditooor" / "coverage_report.json", _l37t._coverage_report(ws))


def _run(ws: Path, *extra: str, env: dict[str, str] | None = None):
    proc = subprocess.run(
        [sys.executable, str(TOOL), str(ws), "--json", *extra],
        capture_output=True, text=True,
        env=env,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {"_stdout": proc.stdout, "_stderr": proc.stderr}
    return proc.returncode, payload


# Canonical stage ordering (must match L37 _SIGNAL_ORDER). 23 stages.
_EXPECTED_ORDER = [
    "tier6-mining", "hunt-complete", "live-engines", "engine-harness",
    "audit-preflight", "exploit-queue", "chain-synth", "exploit-conversion",
    "prove-top-leads", "originality", "advisory-corpus", "learning",
    "mined-landed", "cross-ws-seed", "brain-prime", "hacker-questions",
    "fork-divergence", "novel-vector", "adversarial-panel", "evm-0day-proof",
    "coverage-map", "rubric-coverage", "hunt-trust",
]


class TestProductionPipelinePass(unittest.TestCase):
    def test_all_artifacts_present_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            self.assertEqual(payload["verdict"], "pass-production-pipeline-complete")
            self.assertIsNone(payload["blocker"])
            self.assertEqual(payload["n_failing"], 0)
            self.assertEqual(payload["n_stages"], len(_EXPECTED_ORDER))
            self.assertNotIn("left a real artifact", payload["reason"])
            hard_required = [s for s in payload["stages"] if s["hard_required"]]
            self.assertIn(
                f"all {len(hard_required)} hard-required pipeline checks",
                payload["reason"],
            )
            self.assertNotIn(
                f"all {len(payload['stages'])} hard-required pipeline checks",
                payload["reason"],
            )

    def test_manifest_written_in_canonical_order(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            rc, payload = _run(ws)
            self.assertEqual(rc, 0, payload)
            manifest_path = Path(payload["manifest_path"])
            self.assertTrue(manifest_path.is_file(), "manifest not written")
            manifest = json.loads(manifest_path.read_text())
            stages = [s["stage"] for s in manifest["stages"]]
            self.assertEqual(stages, _EXPECTED_ORDER)
            # order field is 1-based and monotonic
            orders = [s["order"] for s in manifest["stages"]]
            self.assertEqual(orders, list(range(1, len(_EXPECTED_ORDER) + 1)))

    def test_default_manifest_path(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            rc, payload = _run(ws)
            self.assertEqual(rc, 0)
            expected = (ws / ".auditooor" / "production_pipeline_manifest.json").resolve()
            self.assertEqual(Path(payload["manifest_path"]).resolve(), expected)
            self.assertTrue(expected.is_file())

    def test_manifest_write_failure_returns_error(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            manifest_dir = Path(td) / "manifest-dir"
            manifest_dir.mkdir()
            rc, payload = _run(ws, "--manifest-out", str(manifest_dir))
            self.assertEqual(rc, 2)
            self.assertEqual(payload["verdict"], "error")
            self.assertEqual(Path(payload["manifest_path"]), manifest_dir.resolve())
            self.assertIn("failed to write production pipeline manifest", payload["reason"])


class TestFailCloseOnMissingArtifact(unittest.TestCase):
    """The core PR10 discipline: missing hard-required evidence fail-closes."""

    def _build_and_remove(self, td, relpath):
        ws = _build_complete_ws(Path(td))
        target = ws / relpath
        if target.exists():
            target.unlink()
        return ws

    def test_missing_tier6_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            # remove the whole mining_rounds dir
            import shutil
            shutil.rmtree(ws / "mining_rounds")
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "fail-production-pipeline-incomplete")
            self.assertEqual(payload["blocker"]["stage"], "tier6-mining")

    def test_missing_exploit_queue_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._build_and_remove(td, ".auditooor/exploit_queue.json")
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "fail-production-pipeline-incomplete")
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("exploit-queue", failing)

    def test_missing_chain_synth_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            import shutil
            shutil.rmtree(ws / ".auditooor" / "chain_synthesis")
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("chain-synth", failing)

    def test_stale_audit_deep_manifest_blocks_production_pipeline(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            _convert_complete_ws_to_go(ws)
            _write_audit_run_start(ws)
            _write_fresh_audit_deep_manifest(ws, generated_at="2026-05-30T09:59:00Z")

            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verdict"], "fail-production-pipeline-incomplete")
            live = [s for s in payload["stages"] if s["stage"] == "live-engines"][0]
            self.assertFalse(live["ok"])
            self.assertEqual(live["verdict"], "fail-engines-not-run-for-language")
            self.assertEqual(live["status_class"], "stale-deep-manifest")
            p0 = live["p0_deep_engine_freshness"]
            self.assertEqual(p0["status"], "stale-deep-manifest")
            self.assertEqual(p0["verdict"], "fail-stale-deep-manifest")
            self.assertFalse(p0["completion_claimed"])


class TestP0DeepEngineFreshnessReport(unittest.TestCase):
    def _go_workspace(self, td):
        ws = _build_complete_ws(Path(td))
        _convert_complete_ws_to_go(ws)
        _refresh_coverage_report(ws)
        _write_audit_run_start(ws)
        return ws

    def test_fresh_audit_deep_manifest_reports_hard_required_pass(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._go_workspace(td)
            _write_fresh_audit_deep_manifest(ws)

            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            live = next(s for s in payload["stages"] if s["stage"] == "live-engines")
            self.assertEqual(live["status_class"], "hard-required-pass")
            p0 = live["p0_deep_engine_freshness"]
            self.assertEqual(p0["schema"], "auditooor.pr10_p0_deep_engine_freshness.v1")
            self.assertEqual(p0["status"], "hard-required-pass")
            self.assertEqual(p0["verdict"], "pass-fresh-deep-manifest")
            self.assertEqual(p0["completion_mode"], "fresh-manifest")
            self.assertTrue(p0["completion_claimed"])
            self.assertIn(".audit_logs/audit_deep_all_manifest.json", p0["fresh_manifest_paths"])
            self.assertEqual(live["l37_detail"]["audit_deep_freshness"]["verdict"], p0["verdict"])

    def test_typed_deep_skip_reports_skip_without_claiming_completion(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._go_workspace(td)
            for p in (ws / ".audit_logs").glob("audit_deep*"):
                p.unlink()
            _write_typed_deep_skip(ws)

            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1, payload)
            self.assertEqual(payload["blocker"]["stage"], "hunt-complete")
            live = next(s for s in payload["stages"] if s["stage"] == "live-engines")
            self.assertTrue(live["ok"])
            self.assertEqual(live["status_class"], "typed-deep-skip")
            p0 = live["p0_deep_engine_freshness"]
            self.assertEqual(p0["status"], "typed-deep-skip")
            self.assertEqual(p0["verdict"], "pass-explicit-deep-skip")
            self.assertEqual(p0["completion_mode"], "typed-skip")
            self.assertFalse(p0["completion_claimed"])
            self.assertEqual(p0["skip"]["path"], ".auditooor/stage_skips.json")

    def test_missing_deep_manifest_reports_missing_without_claiming_completion(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._go_workspace(td)
            for p in (ws / ".audit_logs").glob("audit_deep*"):
                p.unlink()

            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            live = next(s for s in payload["stages"] if s["stage"] == "live-engines")
            self.assertFalse(live["ok"])
            self.assertEqual(live["status_class"], "missing-deep-manifest")
            p0 = live["p0_deep_engine_freshness"]
            self.assertEqual(p0["status"], "missing-deep-manifest")
            self.assertEqual(p0["verdict"], "fail-no-deep-manifest")
            self.assertFalse(p0["completion_claimed"])
            self.assertEqual(p0["fresh_manifest_paths"], [])


class TestAddDFailClose(unittest.TestCase):
    """ADD-D: production-pipeline MUST fail-close without brain-prime AND a
    per-fn hacker-question artifact."""

    def test_missing_brain_prime_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            (ws / "BRAIN_PRIMING_REPORT.md").unlink()
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("brain-prime", failing)

    def test_missing_hacker_questions_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            (ws / ".auditooor" / "per_fn_hacker_questions.jsonl").unlink()
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("hacker-questions", failing)


class TestNovelVectorStage(unittest.TestCase):
    def test_missing_novel_vector_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            (ws / ".auditooor" / "novel_vector_invariants.json").unlink()
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("novel-vector", failing)

    def test_pr9_demo_summary_satisfies_novel_vector(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            # remove miner output, add pr9 demo summary instead
            (ws / ".auditooor" / "novel_vector_invariants.json").unlink()
            demo = ws / ".auditooor" / "pr9_0day_demo"
            demo.mkdir(parents=True, exist_ok=True)
            _write_json(demo / "pr9_0day_demo_summary.json", {"ok": True})
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            self.assertEqual(payload["verdict"], "pass-production-pipeline-complete")


class TestAdversarialPanelStage(unittest.TestCase):
    def test_final_leads_without_panel_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            # Introduce a FINAL_LEADS set with NO adversarial panel.
            (ws / ".auditooor" / "final_leads.json").write_text(
                '{"leads": []}', encoding="utf-8")
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            blocker_stages = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("adversarial-panel", blocker_stages)

    def test_final_leads_with_panel_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            (ws / ".auditooor" / "final_leads.json").write_text(
                '{"leads": []}', encoding="utf-8")
            _write_json(ws / ".auditooor" / "adversarial_panel.json",
                        {"panel_verdict": "pass-survived-panel"})
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)

    def test_no_final_leads_panel_na_passes(self):
        # the all-pass fixture has no FINAL_LEADS -> panel N/A -> passes
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0)
            panel = next(s for s in payload["stages"] if s["stage"] == "adversarial-panel")
            self.assertTrue(panel["ok"])


class TestEvm0dayProofStage(unittest.TestCase):
    def test_evm_medium_plus_without_proof_is_advisory_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            # the fixture is Solidity (EVM). Add a Medium+ candidate to the queue.
            _write_json(ws / ".auditooor" / "exploit_queue.json", {
                "queue": [{"id": "c1", "severity": "High"}],
            })
            _refresh_coverage_report(ws)
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            evm = next(s for s in payload["stages"] if s["stage"] == "evm-0day-proof")
            self.assertTrue(evm["ok"])
            self.assertIn("advisory by default", evm["reason"])
            self.assertFalse(evm["artifact_present"])
            self.assertTrue(evm["advisory_without_artifact"])
            self.assertEqual(evm["artifact_requirement"], "advisory-without-artifact")
            self.assertEqual(evm["verdict"], "advisory-without-artifact")
            self.assertEqual(evm["status_class"], "advisory-accounted")

    def test_evm_medium_plus_without_proof_fails_when_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            _write_json(ws / ".auditooor" / "exploit_queue.json", {
                "queue": [{"id": "c1", "severity": "High"}],
            })
            _refresh_coverage_report(ws)
            env = {**os.environ, "ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}
            rc, payload = _run(ws, "--no-manifest", env=env)
            self.assertEqual(rc, 1)
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("evm-0day-proof", failing)

    def test_evm_medium_plus_with_proof_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            _write_json(ws / ".auditooor" / "exploit_queue.json", {
                "queue": [{"id": "c1", "severity": "High"}],
            })
            _refresh_coverage_report(ws)
            _write_json(ws / ".auditooor" / "evm_0day_proof.json",
                        {"verdict": "proof-backed"})
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            evm = next(s for s in payload["stages"] if s["stage"] == "evm-0day-proof")
            self.assertTrue(evm["artifact_present"])
            self.assertEqual(evm["artifact_requirement"], "advisory-artifact-present")
            self.assertEqual(evm["policy"], "advisory")
            self.assertFalse(evm["hard_required"])
            self.assertEqual(evm["verdict"], "advisory-artifact-present")

    def test_evm_no_medium_plus_candidate_na_passes(self):
        # the all-pass fixture's queue has no Medium+ candidate -> N/A pass
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0)
            evm = next(s for s in payload["stages"] if s["stage"] == "evm-0day-proof")
            self.assertTrue(evm["ok"])


class TestProofConversionAdvisoryStages(unittest.TestCase):
    def test_exploit_conversion_missing_is_advisory_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            (ws / ".auditooor" / "current_to_exploit_conversion_gate.json").unlink()
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            stage = next(s for s in payload["stages"] if s["stage"] == "exploit-conversion")
            self.assertTrue(stage["ok"])
            self.assertFalse(stage["artifact_present"])
            self.assertTrue(stage["advisory_without_artifact"])
            self.assertEqual(stage["artifact_requirement"], "advisory-without-artifact")
            self.assertEqual(stage["policy"], "advisory")
            self.assertFalse(stage["hard_required"])
            self.assertEqual(stage["verdict"], "advisory-without-artifact")
            self.assertEqual(stage["status_class"], "advisory-accounted")
            self.assertNotEqual(stage["verdict"], "pass")

    def test_exploit_conversion_env_values_other_than_one_remain_advisory(self):
        for value in ("true", "yes", "on", "2", "garbage"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as td:
                ws = _build_complete_ws(Path(td))
                (ws / ".auditooor" / "current_to_exploit_conversion_gate.json").unlink()
                env = {**os.environ, "ENFORCE_AUTONOMOUS_PROOF_CONVERSION": value}
                rc, payload = _run(ws, "--no-manifest", env=env)
                self.assertEqual(rc, 0, payload)
                stage = next(s for s in payload["stages"] if s["stage"] == "exploit-conversion")
                self.assertTrue(stage["ok"])
                self.assertFalse(stage["hard_required"])
                self.assertEqual(stage["policy"], "advisory")
                self.assertEqual(stage["verdict"], "advisory-without-artifact")

    def test_exploit_conversion_missing_fails_when_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            (ws / ".auditooor" / "current_to_exploit_conversion_gate.json").unlink()
            env = {**os.environ, "ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}
            rc, payload = _run(ws, "--no-manifest", env=env)
            self.assertEqual(rc, 1)
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("exploit-conversion", failing)

    def test_prove_top_leads_missing_is_advisory_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            for path in (ws / ".auditooor").glob("prove_top_leads_*"):
                path.unlink()
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            stage = next(s for s in payload["stages"] if s["stage"] == "prove-top-leads")
            self.assertTrue(stage["ok"])
            self.assertFalse(stage["artifact_present"])
            self.assertTrue(stage["advisory_without_artifact"])
            self.assertEqual(stage["artifact_requirement"], "advisory-without-artifact")
            self.assertEqual(stage["policy"], "advisory")
            self.assertFalse(stage["hard_required"])
            self.assertEqual(stage["verdict"], "advisory-without-artifact")
            self.assertNotEqual(stage["verdict"], "pass")

    def test_advisory_proof_stage_with_artifact_stays_advisory(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            for name in ("exploit-conversion", "prove-top-leads"):
                stage = next(s for s in payload["stages"] if s["stage"] == name)
                self.assertTrue(stage["artifact_present"])
                self.assertFalse(stage["advisory_without_artifact"])
                self.assertEqual(stage["artifact_requirement"], "advisory-artifact-present")
                self.assertEqual(stage["policy"], "advisory")
                self.assertFalse(stage["hard_required"])
                self.assertEqual(stage["verdict"], "advisory-artifact-present")

    def test_missing_advisory_proof_stage_prints_advisory_not_plain_pass(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            (ws / ".auditooor" / "current_to_exploit_conversion_gate.json").unlink()
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws), "--no-manifest"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("[ADVISORY] exploit-conversion", proc.stdout)
            self.assertNotIn("[PASS] exploit-conversion", proc.stdout)

    def test_prove_top_leads_missing_fails_when_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            for path in (ws / ".auditooor").glob("prove_top_leads_*"):
                path.unlink()
            env = {**os.environ, "ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}
            rc, payload = _run(ws, "--no-manifest", env=env)
            self.assertEqual(rc, 1)
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("prove-top-leads", failing)

    def test_prove_top_leads_weak_reports_fallback_fails_when_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            aud = ws / ".auditooor"
            reports = ws / "reports"
            (aud / "prove_top_leads_candidate_judgment_packet.json").unlink()
            _write_json(aud / "prove_top_leads_outcome_lesson_gate.json", {"ok": True})
            _write_json(reports / "prove_top_leads_source_mine.json", {"ok": True})
            _write_json(reports / "prove_top_leads_prefiling_stress_test.json", {"ok": True})
            env = {**os.environ, "ENFORCE_AUTONOMOUS_PROOF_CONVERSION": "1"}
            rc, payload = _run(ws, "--no-manifest", env=env)
            self.assertEqual(rc, 1)
            stage = next(s for s in payload["stages"] if s["stage"] == "prove-top-leads")
            self.assertFalse(stage["ok"])
            self.assertIn("bare prove_top_leads", stage["reason"])


class TestForkDivergenceHuntStageEvidence(unittest.TestCase):
    """PR8 ADD-C: a fork target that ran the fork-divergence HUNT stage
    (proof_obligation_queue.json with fork_divergence_last_run) is credited."""

    def test_fork_target_with_hunt_queue_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            # make it a fork target
            (ws / "Cargo.toml").write_text(
                '[dependencies]\nfoo = { git = "https://x/y", rev = "abcdef1234" }\n',
                encoding="utf-8")
            # the fork-divergence HUNT stage queue marker satisfies signal (k)
            _write_json(ws / ".auditooor" / "proof_obligation_queue.json", {
                "queue": [], "fork_divergence_last_run": "2026-05-30T00:00:00Z",
            })
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 0, payload)
            fork = next(s for s in payload["stages"] if s["stage"] == "fork-divergence")
            self.assertTrue(fork["ok"])

    def test_fork_target_without_any_artifact_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            (ws / "Cargo.toml").write_text(
                '[dependencies]\nfoo = { git = "https://x/y", rev = "abcdef1234" }\n',
                encoding="utf-8")
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            failing = [s["stage"] for s in payload["stages"] if not s["ok"]]
            self.assertIn("fork-divergence", failing)


class TestOrderingAndStrict(unittest.TestCase):
    def test_stage_ordering_is_canonical(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            rc, payload = _run(ws, "--no-manifest")
            stages = [s["stage"] for s in payload["stages"]]
            self.assertEqual(stages, _EXPECTED_ORDER)
            # the PR10 proof stages fire before the three cross-cutting
            # coverage and hunt-trust signals.
            self.assertEqual(
                stages[17:20],
                ["novel-vector", "adversarial-panel", "evm-0day-proof"],
            )
            self.assertEqual(stages[-3:], ["coverage-map", "rubric-coverage", "hunt-trust"])
            # ADD-D fail-close stages sit at 15/16
            self.assertEqual(stages[14], "brain-prime")
            self.assertEqual(stages[15], "hacker-questions")

    def test_strict_flag_records_strict(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            rc, payload = _run(ws, "--strict", "--no-manifest")
            self.assertTrue(payload["strict"])

    def test_strict_env_threads(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            env = {**os.environ, "STRICT": "1"}
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws), "--json", "--no-manifest"],
                capture_output=True, text=True, env=env,
            )
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["strict"])


class TestErrorHandling(unittest.TestCase):
    def test_missing_workspace_errors(self):
        rc, payload = _run(Path("/nonexistent/ws/path/xyz"), "--no-manifest")
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    def test_blocker_is_first_failing_in_order(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _build_complete_ws(Path(td))
            import shutil
            # remove an EARLY independent stage (chain-synth, #7) AND a LATE
            # stage (novel-vector, #18). Neither cascades into the hunt gate.
            shutil.rmtree(ws / ".auditooor" / "chain_synthesis")
            (ws / ".auditooor" / "novel_vector_invariants.json").unlink()
            rc, payload = _run(ws, "--no-manifest")
            self.assertEqual(rc, 1)
            # blocker must be the FIRST failing stage in ordering = chain-synth
            self.assertEqual(payload["blocker"]["stage"], "chain-synth")
            self.assertEqual(payload["n_failing"], 2)


if __name__ == "__main__":
    unittest.main()
