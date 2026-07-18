#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""Unit tests for tools/hunt-orchestrate.py (deterministic L36 step engine)."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered
_TOOL = Path(__file__).resolve().parent.parent / "hunt-orchestrate.py"
_spec = importlib.util.spec_from_file_location("hunt_orchestrate", _TOOL)
mod = importlib.util.module_from_spec(_spec)
# Register in sys.modules BEFORE exec so dataclass field() introspection
# (Python 3.14) can resolve the module dict.
sys.modules["hunt_orchestrate"] = mod
_spec.loader.exec_module(mod)


class TestHuntOrchestratePlan(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir()
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_dedup_load_is_step_zero(self):
        steps = mod.build_plan(self.ws, self.repo, use_mcp=True)
        self.assertEqual(steps[0].order, 0)
        self.assertEqual(steps[0].step_id, mod.STEP_DEDUP_LOAD)
        self.assertTrue(steps[0].mandatory)

    def test_completeness_gate_is_last_step(self):
        steps = mod.build_plan(self.ws, self.repo, use_mcp=True)
        self.assertEqual(steps[-1].step_id, mod.STEP_COMPLETENESS)
        self.assertTrue(steps[-1].mandatory)

    def test_step_order_is_strictly_increasing(self):
        steps = mod.build_plan(self.ws, self.repo, use_mcp=True)
        orders = [s.order for s in steps]
        self.assertEqual(orders, sorted(orders))
        self.assertEqual(orders, list(range(len(orders))))

    def test_full_canonical_pipeline_present_in_order(self):
        steps = mod.build_plan(self.ws, self.repo, use_mcp=True)
        ids = [s.step_id for s in steps]
        # The canonical 0..8 pipeline, in order.
        expected = [
            "dedup-load", "ensure-full-clone", "make-audit", "make-audit-deep",
            "tier6-bidirectional-mining", "emit-cluster-briefs",
            "sidecar-corpus-learn-etl", "capability-coverage-matrix",
            "completeness-gate",
        ]
        self.assertEqual(ids, expected)

    def test_skip_audit_stages_reuses_prior_full_audit_work(self):
        steps = mod.build_plan(self.ws, self.repo, use_mcp=True, skip_audit_stages=True)
        ids = [s.step_id for s in steps]
        self.assertNotIn("make-audit", ids)
        self.assertNotIn("make-audit-deep", ids)
        self.assertEqual(ids[0], mod.STEP_DEDUP_LOAD)
        self.assertEqual(ids[-1], mod.STEP_COMPLETENESS)
        self.assertEqual([s.order for s in steps], list(range(len(steps))))

    def test_audit_stages_are_mandatory(self):
        steps = {s.step_id: s for s in mod.build_plan(self.ws, self.repo, use_mcp=True)}
        self.assertTrue(steps["make-audit"].mandatory)
        self.assertTrue(steps["make-audit-deep"].mandatory)

    def test_mining_and_briefs_are_best_effort(self):
        steps = {s.step_id: s for s in mod.build_plan(self.ws, self.repo, use_mcp=True)}
        self.assertTrue(steps["tier6-bidirectional-mining"].best_effort)
        self.assertTrue(steps["emit-cluster-briefs"].best_effort)
        self.assertTrue(steps["sidecar-corpus-learn-etl"].best_effort)

    def test_no_mcp_propagated_to_dedup_command(self):
        steps = mod.build_plan(self.ws, self.repo, use_mcp=False)
        dedup_cmd = steps[0].commands[0]
        self.assertIn("--no-mcp", dedup_cmd)
        steps_mcp = mod.build_plan(self.ws, self.repo, use_mcp=True)
        self.assertNotIn("--no-mcp", steps_mcp[0].commands[0])

    def test_plan_cli_emits_dedup_first_invariant(self):
        rc = mod.main(["--workspace", str(self.ws), "--plan"])
        self.assertEqual(rc, 0)


class TestHuntOrchestrateExecute(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir()
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _make_step(self, step_id, order, cmd, mandatory=True, best_effort=False):
        return mod.Step(
            step_id=step_id, order=order, label=step_id, commands=[cmd],
            mandatory=mandatory, best_effort=best_effort,
        )

    def test_mandatory_failure_short_circuits_and_skips_rest(self):
        # Step 1 mandatory FAILS (python exit 1) => step 2 skipped, exit 1.
        fail_cmd = ["python3", "-c", "import sys; sys.exit(1)"]
        ok_cmd = ["python3", "-c", "pass"]
        steps = [
            self._make_step("s0", 0, ok_cmd, mandatory=True),
            self._make_step("s1", 1, fail_cmd, mandatory=True),
            self._make_step("s2", 2, ok_cmd, mandatory=True),
        ]
        results, verdict, rc = mod.execute_plan(steps, self.repo, dry_run=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "fail-step-s1")
        # s2 must be reported as skipped (rc == -1).
        s2 = next(r for r in results if r.step_id == "s2")
        self.assertEqual(s2.rc, -1)
        self.assertIn("skipped", s2.skipped_reason)

    def test_best_effort_failure_continues(self):
        fail_cmd = ["python3", "-c", "import sys; sys.exit(3)"]
        ok_cmd = ["python3", "-c", "pass"]
        steps = [
            self._make_step("s0", 0, ok_cmd, mandatory=True),
            self._make_step("s1", 1, fail_cmd, mandatory=False, best_effort=True),
            self._make_step("s2", 2, ok_cmd, mandatory=True),
        ]
        results, verdict, rc = mod.execute_plan(steps, self.repo, dry_run=False)
        self.assertEqual(rc, 0)
        self.assertEqual(verdict, "pass-hunt-orchestrated")
        s2 = next(r for r in results if r.step_id == "s2")
        self.assertEqual(s2.rc, 0)

    def test_missing_mandatory_tool_hard_fails(self):
        # A mandatory step whose .py tool does not exist must fail (rc 127).
        missing = ["python3", str(self.repo / "tools" / "does-not-exist.py"), "x"]
        ok_cmd = ["python3", "-c", "pass"]
        steps = [
            self._make_step("s0", 0, ok_cmd, mandatory=True),
            self._make_step("missing", 1, missing, mandatory=True, best_effort=False),
        ]
        results, verdict, rc = mod.execute_plan(steps, self.repo, dry_run=False)
        self.assertEqual(rc, 1)
        self.assertEqual(verdict, "fail-step-missing")

    def test_missing_best_effort_tool_skipped_not_fatal(self):
        missing = ["python3", str(self.repo / "tools" / "absent.py"), "x"]
        steps = [self._make_step("be", 0, missing, mandatory=False, best_effort=True)]
        results, verdict, rc = mod.execute_plan(steps, self.repo, dry_run=False)
        self.assertEqual(rc, 0)
        self.assertEqual(verdict, "pass-hunt-orchestrated")

    def test_dry_run_executes_nothing_passes(self):
        steps = mod.build_plan(self.ws, self.repo, use_mcp=False)
        results, verdict, rc = mod.execute_plan(steps, self.repo, dry_run=True)
        self.assertEqual(rc, 0)
        self.assertTrue(all(r.skipped_reason == "dry-run" for r in results))


class TestForkDivergenceAutoWire(unittest.TestCase):
    """Fork-divergence auto-wire: fork targets inject the fork-divergence step
    and auto-resolve the upstream for Tier-6 mining; non-fork targets do not."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        self.real_repo = Path(__file__).resolve().parent.parent.parent

    def tearDown(self):
        self._tmp.cleanup()

    def _fork_ws(self):
        ws = Path(self._tmp.name) / "forkws"
        ws.mkdir()
        (ws / "Cargo.toml").write_text(
            '[dependencies]\nfoo = { git = "https://github.com/acme/upstream-repo", '
            'rev = "abc1234" }\n', encoding="utf-8")
        return ws

    def _plain_ws(self):
        ws = Path(self._tmp.name) / "plainws"
        ws.mkdir()
        return ws

    def test_non_fork_plan_is_legacy_nine_steps(self):
        steps = mod.build_plan(self._plain_ws(), self.real_repo, use_mcp=True)
        ids = [s.step_id for s in steps]
        self.assertEqual(ids, [
            "dedup-load", "ensure-full-clone", "make-audit", "make-audit-deep",
            "tier6-bidirectional-mining", "emit-cluster-briefs",
            "sidecar-corpus-learn-etl", "capability-coverage-matrix",
            "completeness-gate",
        ])
        self.assertNotIn(mod.STEP_FORK_DIVERGENCE, ids)

    def test_fork_plan_injects_fork_divergence_step(self):
        steps = mod.build_plan(self._fork_ws(), self.real_repo, use_mcp=True)
        ids = [s.step_id for s in steps]
        self.assertIn(mod.STEP_FORK_DIVERGENCE, ids)
        self.assertEqual(
            ids.index(mod.STEP_FORK_DIVERGENCE),
            ids.index("tier6-bidirectional-mining") + 1,
        )
        self.assertLess(ids.index(mod.STEP_FORK_DIVERGENCE), ids.index("emit-cluster-briefs"))

    def test_fork_plan_orders_strictly_increasing_and_complete(self):
        steps = mod.build_plan(self._fork_ws(), self.real_repo, use_mcp=True)
        orders = [s.order for s in steps]
        self.assertEqual(orders, list(range(len(steps))))
        self.assertEqual(steps[0].step_id, mod.STEP_DEDUP_LOAD)
        self.assertEqual(steps[-1].step_id, mod.STEP_COMPLETENESS)

    def test_fork_step_emits_canonical_artifact_path(self):
        ws = self._fork_ws()
        steps = mod.build_plan(ws, self.real_repo, use_mcp=True)
        fork_step = next(s for s in steps if s.step_id == mod.STEP_FORK_DIVERGENCE)
        cmd = fork_step.commands[0]
        self.assertIn("--out", cmd)
        out_path = cmd[cmd.index("--out") + 1]
        self.assertTrue(out_path.endswith(".auditooor/fork_divergence_probe.json"))
        self.assertIn("fork-divergence-prober.py", "".join(cmd))

    def test_fork_step_uses_nested_src_probe_workspace_when_present(self):
        ws = self._plain_ws()
        (ws / "src").mkdir(parents=True)
        subprocess.run(["git", "init"], cwd=ws / "src", check=True, capture_output=True)
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "differential_seed_queue.json").write_text(
            json.dumps({
                "schema": "auditooor.cross_workspace_differential_seed.v1",
                "target_families": ["morpho-blue"],
                "selected_siblings": [
                    {"workspace": "morpho", "families": ["morpho-blue"]},
                ],
                "hypotheses": [
                    {"hypothesis_id": "DIFF-1", "verdict": "unproven"},
                ],
            }),
            encoding="utf-8",
        )
        steps = mod.build_plan(ws, self.real_repo, use_mcp=True)
        fork_step = next(s for s in steps if s.step_id == mod.STEP_FORK_DIVERGENCE)
        cmd = fork_step.commands[0]
        probe_path = cmd[cmd.index("--workspace") + 1]
        self.assertEqual(
            Path(probe_path).resolve(strict=False),
            (ws / "src").resolve(strict=False),
        )

    def test_same_family_plan_runs_differential_seed_and_probe(self):
        ws = Path(self._tmp.name) / "morpho-midnight"
        sibling = Path(self._tmp.name) / "morpho"
        ws.mkdir()
        sibling.mkdir()
        (ws / ".auditooor").mkdir()
        (sibling / ".auditooor").mkdir()
        (ws / ".auditooor" / "engagement_family.txt").write_text("morpho-blue\n", encoding="utf-8")
        (sibling / ".auditooor" / "engagement_family.txt").write_text("morpho-blue\n", encoding="utf-8")
        (ws / "src").mkdir(parents=True)
        subprocess.run(["git", "init"], cwd=ws / "src", check=True, capture_output=True)

        steps = mod.build_plan(ws, self.real_repo, use_mcp=True)
        ids = [s.step_id for s in steps]
        self.assertIn(mod.STEP_DIFFERENTIAL_SEED, ids)
        self.assertIn(mod.STEP_FORK_DIVERGENCE, ids)
        self.assertLess(ids.index(mod.STEP_DIFFERENTIAL_SEED), ids.index(mod.STEP_FORK_DIVERGENCE))
        seed_step = next(s for s in steps if s.step_id == mod.STEP_DIFFERENTIAL_SEED)
        seed_cmd = seed_step.commands[0]
        self.assertIn("cross-workspace-differential-seed.py", "".join(seed_cmd))
        self.assertIn("--merge-proof-queue", seed_cmd)
        fork_step = next(s for s in steps if s.step_id == mod.STEP_FORK_DIVERGENCE)
        fork_cmd = fork_step.commands[0]
        probe_path = fork_cmd[fork_cmd.index("--workspace") + 1]
        self.assertEqual(probe_path, str(ws / "src"))

    def test_fork_step_is_best_effort(self):
        steps = mod.build_plan(self._fork_ws(), self.real_repo, use_mcp=True)
        fork_step = next(s for s in steps if s.step_id == mod.STEP_FORK_DIVERGENCE)
        self.assertTrue(fork_step.best_effort)
        self.assertFalse(fork_step.mandatory)

    def test_tier6_auto_wires_resolved_upstream(self):
        steps = mod.build_plan(self._fork_ws(), self.real_repo, use_mcp=True)
        tier6 = next(s for s in steps if s.step_id == "tier6-bidirectional-mining")
        cmd = tier6.commands[0]
        self.assertIn("--upstream", cmd)
        self.assertEqual(cmd[cmd.index("--upstream") + 1], "acme/upstream-repo")
        self.assertIn("--lang", cmd)
        self.assertEqual(cmd[cmd.index("--lang") + 1], "rust")

    def test_non_fork_tier6_has_no_upstream(self):
        steps = mod.build_plan(self._plain_ws(), self.real_repo, use_mcp=True)
        tier6 = next(s for s in steps if s.step_id == "tier6-bidirectional-mining")
        self.assertNotIn("--upstream", tier6.commands[0])
        self.assertIn("audit-target-commit-mining.py", "".join(tier6.commands[0]))
        self.assertIn("--workspace", tier6.commands[0])
        self.assertIn("--window", tier6.commands[0])

    def test_non_fork_tier6_does_not_call_git_miner_without_upstream(self):
        steps = mod.build_plan(self._plain_ws(), self.real_repo, use_mcp=True)
        tier6 = next(s for s in steps if s.step_id == "tier6-bidirectional-mining")
        cmd = " ".join(tier6.commands[0])
        self.assertNotIn("git-commits-mining.py", cmd)

    def test_artifact_detected_by_master_gate(self):
        ws = self._fork_ws()
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "fork_divergence_probe.json").write_text(
            json.dumps({"schema": "auditooor.fork_divergence_prober.v1", "pins": []}),
            encoding="utf-8")
        acc_tool = self.real_repo / "tools" / "audit-completeness-check.py"
        spec = importlib.util.spec_from_file_location("acc_gate", acc_tool)
        acc = importlib.util.module_from_spec(spec)
        sys.modules["acc_gate"] = acc
        spec.loader.exec_module(acc)
        self.assertTrue(acc._detect_fork(ws)[0])
        r = acc.check_fork_divergence(ws)
        self.assertTrue(r.ok)


if __name__ == "__main__":
    unittest.main()
