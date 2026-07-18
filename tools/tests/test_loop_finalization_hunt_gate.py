#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""Tests for the L36 hunt-completeness BLOCKING gate in loop-finalization-check."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "loop-finalization-check.py"
_spec = importlib.util.spec_from_file_location("loop_finalization_check", _TOOL)
mod = importlib.util.module_from_spec(_spec)
sys.modules["loop_finalization_check"] = mod
_spec.loader.exec_module(mod)


class TestHuntCompletenessGate(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _eval(self, manifest):
        malformed, policy = [], []
        return mod._check_hunt_completeness_when_done(
            manifest, malformed=malformed, policy_failures=policy, manifest_path=None
        ), policy, malformed

    def test_not_relevant_when_hunt_not_declared_done(self):
        res, policy, _ = self._eval({"changed_artifacts": ["x.md"]})
        self.assertFalse(res["relevant"])
        self.assertEqual(res["mode"], "not_required")
        self.assertEqual(policy, [])

    def test_hunt_done_flag_requires_workspace_path(self):
        res, policy, _ = self._eval({"hunt_done": True})
        self.assertFalse(res["ok"])
        self.assertTrue(any("workspace_path" in p for p in policy))

    def test_hunt_done_status_string_detected(self):
        for field in ("hunt_status", "loop_status", "status", "slice_status"):
            for val in ("exhausted", "done", "hunt-complete", "complete"):
                self.assertTrue(mod._hunt_done_declared({field: val}), f"{field}={val}")

    def test_hunt_done_blocked_when_completeness_fails(self):
        # ws has no skip-set, no audit-deep etc => completeness fails => BLOCK.
        manifest = {"hunt_done": True, "workspace_path": str(self.ws)}
        res, policy, _ = self._eval(manifest)
        self.assertFalse(res["ok"])
        self.assertEqual(res["mode"], "hunt_incomplete")
        self.assertTrue(any("BLOCKED by hunt-completeness" in p for p in policy))

    def test_hunt_done_passes_only_when_completeness_passes(self):
        # Build a fully-complete workspace so hunt-completeness-check returns
        # pass-hunt-complete, then assert the gate is OK.
        self._make_complete_workspace()
        manifest = {"hunt_status": "exhausted", "workspace_path": str(self.ws)}
        res, policy, malformed = self._eval(manifest)
        self.assertTrue(res["ok"], f"policy={policy} malformed={malformed} res={res}")
        self.assertEqual(res["verdict"], "pass-hunt-complete")

    def test_gate_wired_into_evaluate_manifest(self):
        # A hunt-done manifest must surface a hunt_completeness check key and
        # fail the manifest (policy_fail) when the ws is incomplete.
        manifest = {
            "hunt_done": True,
            "workspace_path": str(self.ws),
            "changed_artifacts": ["note.md"],
            "handoff_or_ledger_updated": "yes",
            "agent_outputs_collected": "yes",
        }
        result = mod.evaluate_manifest(manifest, allow_no_artifact=True)
        self.assertIn("hunt_completeness", result["checks"])
        self.assertFalse(result["passed"])
        self.assertTrue(any("hunt-completeness" in p for p in result["policy_failures"]))

    # ------------------------------------------------------------------
    def _make_complete_workspace(self):
        ws = self.ws
        a = ws / ".auditooor"
        # (f) dedup-first: skip-set present.
        (a / "hunt_skip_set.json").write_text(json.dumps({
            "schema": "auditooor.l36_hunt_skip_set.v1",
            "source_counts": {"total_after_dedup": 1},
            "entries": [{"slug": "x"}],
        }))
        # (a) full clone: a real git repo with >1 commit + mining_rounds.
        import subprocess
        repo = ws  # ws itself is the repo
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
        (repo / "f1").write_text("1")
        subprocess.run(["git", "-C", str(repo), "add", "f1"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "c1"], check=True)
        (repo / "f2").write_text("2")
        subprocess.run(["git", "-C", str(repo), "add", "f2"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "c2"], check=True)
        mr = ws / "mining_rounds" / "round1"
        mr.mkdir(parents=True)
        (mr / "manifest.json").write_text("{}")
        # (b) audit-deep manifest.
        logs = ws / ".audit_logs"
        logs.mkdir()
        (logs / "audit_deep_report.md").write_text("deep")
        # (c)/(d) coverage matrix with no DARK rows covering the one cluster.
        (ws / "SCOPE.md").write_text("- alpha-cluster\n")
        (ws / "HUNT_CAPABILITY_COVERAGE_MATRIX.md").write_text(
            "| Cluster | Status |\n| --- | --- |\n| alpha-cluster | COVERED |\n"
        )
        # (d) cluster-coverage: a sidecar stem matching the cluster.
        sc = ws / "hunt_findings_sidecars"
        sc.mkdir()
        (sc / "alpha-cluster.json").write_text("{}")
        # (e) artifact-mining: learn report.
        reports = ws / "reports"
        reports.mkdir()
        (reports / "agent_learning_report.json").write_text("{}")


if __name__ == "__main__":
    unittest.main()
