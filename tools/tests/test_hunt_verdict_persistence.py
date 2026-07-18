#!/usr/bin/env python3
"""Guard tests for the hunt-verdict persistence ENFORCEMENT: the obligation hook
(records when a Workflow hunt launches) + the chokepoint gate (blocks done while
an obligation is unresolved). These guarantee a hunt's verdicts can never silently
evaporate before a done / audit-complete claim."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "tools" / "hooks" / "auditooor-workflow-verdict-obligation.sh"
GATE = ROOT / "tools" / "hunt-verdict-persistence-gate.py"
SINK = ROOT / "tools" / "verdict-sink.py"


class TestObligationHook(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ledger = self.tmp / "obligations.jsonl"
        self.env = {**os.environ, "AUDITOOOR_VERDICT_OBLIGATION_LEDGER": str(self.ledger)}

    def _fire(self, payload: dict):
        subprocess.run(["bash", str(HOOK)], input=json.dumps(payload),
                       text=True, env=self.env, capture_output=True)

    def test_records_audit_workflow(self):
        self._fire({"tool_name": "Workflow",
                    "tool_input": {"script": 'agent("hunt /Users/wolf/audits/beanstalk/src")'},
                    "tool_response": "launched. Run ID: wf_abc-001"})
        lines = self.ledger.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        rec = json.loads(lines[0])
        self.assertEqual(rec["run_id"], "wf_abc-001")
        self.assertEqual(rec["workspaces"], ["/Users/wolf/audits/beanstalk"])

    def test_skips_non_audit_workflow(self):
        self._fire({"tool_name": "Workflow",
                    "tool_input": {"script": 'agent("refactor /tmp/foo")'},
                    "tool_response": "Run ID: wf_xyz-002"})
        self.assertFalse(self.ledger.exists() and self.ledger.read_text().strip())

    def test_skips_non_workflow_tool(self):
        self._fire({"tool_name": "Bash", "tool_input": {"command": "ls /Users/wolf/audits/beanstalk"},
                    "tool_response": "ok"})
        self.assertFalse(self.ledger.exists() and self.ledger.read_text().strip())

    def test_dedup_same_run(self):
        p = {"tool_name": "Workflow",
             "tool_input": {"script": 'x /Users/wolf/audits/monero-oxide/y'},
             "tool_response": "Run ID: wf_dup-003"}
        self._fire(p)
        self._fire(p)
        self.assertEqual(len(self.ledger.read_text().splitlines()), 1)

    # ------------------------------------------------------------------
    # Task-dispatch tests: Task tool_name must ALSO create obligations
    # ------------------------------------------------------------------

    def test_records_task_dispatch_with_task_id(self):
        """Task-dispatched hunt using 'Task ID:' in response creates an obligation."""
        self._fire({"tool_name": "Task",
                    "tool_input": {"prompt": "hunt /Users/wolf/audits/beanstalk/src"},
                    "tool_response": "Hunt started. Task ID: task-abc-007"})
        self.assertTrue(self.ledger.exists() and self.ledger.read_text().strip(),
                        "Task-dispatch should have created an obligation record")
        rec = json.loads(self.ledger.read_text().splitlines()[0])
        self.assertEqual(rec["run_id"], "task-abc-007")
        self.assertEqual(rec["workspaces"], ["/Users/wolf/audits/beanstalk"])
        self.assertEqual(rec["tool"], "Task")

    def test_records_task_dispatch_with_wf_run_id(self):
        """Task dispatch that emits a wf_-prefixed run ID also creates an obligation."""
        self._fire({"tool_name": "Task",
                    "tool_input": {"prompt": "run hunt on /Users/wolf/audits/monero-oxide"},
                    "tool_response": "started wf_task-deadbeef"})
        rec = json.loads(self.ledger.read_text().splitlines()[0])
        self.assertEqual(rec["run_id"], "wf_task-deadbeef")
        self.assertEqual(rec["tool"], "Task")

    def test_task_dispatch_skips_non_audit_path(self):
        """Task dispatch with no audits/ path must NOT create an obligation."""
        self._fire({"tool_name": "Task",
                    "tool_input": {"prompt": "refactor /tmp/scratch"},
                    "tool_response": "Task ID: task-no-ws-999"})
        self.assertFalse(self.ledger.exists() and self.ledger.read_text().strip(),
                         "Task dispatch with no audit workspace should be skipped")

    def test_skips_non_workflow_non_task_tool(self):
        """Other tool names (e.g. Bash) must still be ignored."""
        self._fire({"tool_name": "Bash",
                    "tool_input": {"command": "ls /Users/wolf/audits/beanstalk"},
                    "tool_response": "Task ID: task-bash-should-skip"})
        self.assertFalse(self.ledger.exists() and self.ledger.read_text().strip(),
                         "Bash tool must not create an obligation even with Task ID in response")

    def test_concurrent_distinct_launches_all_persist(self):
        # Two+ Workflow launches in one message fire PostToolUse hooks
        # concurrently; the flock'd read-dedup-append must not drop any.
        import subprocess as sp
        HELPER = ROOT / "tools" / "hooks" / "_workflow_verdict_obligation.py"
        procs = []
        for i in range(8):
            payload = json.dumps({"tool_name": "Workflow",
                                  "tool_input": {"script": "/Users/wolf/audits/beanstalk/x"},
                                  "tool_response": f"Run ID: wf_conc-{i}-abcdef"})
            procs.append(sp.Popen(["python3", str(HELPER), str(self.ledger)],
                                  stdin=sp.PIPE, text=True))
            procs[-1].stdin.write(payload)
            procs[-1].stdin.close()
        for p in procs:
            p.wait()
        run_ids = {json.loads(l)["run_id"] for l in self.ledger.read_text().splitlines() if l.strip()}
        self.assertEqual(len(run_ids), 8, f"lost a concurrent write; got {sorted(run_ids)}")


class TestPersistenceGate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ledger = self.tmp / "obligations.jsonl"
        self.sinklog = self.tmp / "sink_log.jsonl"
        self.env = {**os.environ,
                    "AUDITOOOR_VERDICT_OBLIGATION_LEDGER": str(self.ledger),
                    "AUDITOOOR_VERDICT_SINK_LOG": str(self.sinklog)}

    def _gate(self, ws: str):
        # --no-corpus-closure: these tests exercise only the obligation/sink-log
        # (persistence) dimension; the corpus-feedback-closure dimension is covered
        # separately in TestCorpusFeedbackClosure.
        return subprocess.run(["python3", str(GATE), "--workspace", ws, "--no-corpus-closure", "--json"],
                              text=True, env=self.env, capture_output=True)

    def _obligation(self, run_id, ws):
        with self.ledger.open("a") as fh:
            fh.write(json.dumps({"run_id": run_id, "workspaces": [ws], "status": "open"}) + "\n")

    def _resolve(self, run_id):
        with self.sinklog.open("a") as fh:
            fh.write(json.dumps({"run_id": run_id, "sidecars_written": 3}) + "\n")

    def test_pass_when_no_obligations(self):
        r = self._gate("/Users/wolf/audits/beanstalk")
        self.assertEqual(r.returncode, 0)

    def test_fail_on_open_obligation(self):
        self._obligation("wf_open-1", "/Users/wolf/audits/beanstalk")
        r = self._gate("/Users/wolf/audits/beanstalk")
        self.assertEqual(r.returncode, 1)
        self.assertIn("fail-unsunk", r.stdout)

    def test_unrelated_workspace_not_blocked(self):
        self._obligation("wf_open-2", "/Users/wolf/audits/beanstalk")
        r = self._gate("/Users/wolf/audits/monero-oxide")
        self.assertEqual(r.returncode, 0)

    def test_resolved_obligation_passes(self):
        self._obligation("wf_res-3", "/Users/wolf/audits/beanstalk")
        self._resolve("wf_res-3")
        r = self._gate("/Users/wolf/audits/beanstalk")
        self.assertEqual(r.returncode, 0)

    def test_global_obligation_blocks_any_workspace(self):
        # an obligation with NO recorded workspaces is conservatively global
        with self.ledger.open("a") as fh:
            fh.write(json.dumps({"run_id": "wf_glob-4", "workspaces": [], "status": "open"}) + "\n")
        r = self._gate("/Users/wolf/audits/anything")
        self.assertEqual(r.returncode, 1)


class TestCorpusFeedbackClosure(unittest.TestCase):
    """The learning-loop closure: a CONFIRMED or kill hunt-sidecar that never
    reached the corpus (ETL never ran / failed) must FAIL the gate, so a sunk
    verdict can never reach the gates but skip the corpus and get re-dispatched."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # Empty obligation/sink ledgers -> the persistence dimension is a clean PASS,
        # isolating the corpus-closure dimension under test.
        self.ledger = self.tmp / "obligations.jsonl"
        self.sinklog = self.tmp / "sink_log.jsonl"
        # Redirect the corpus stores the ETL would write to temp paths.
        self.kde = self.tmp / "reports" / "known_dead_ends.jsonl"
        self.inv_root = self.tmp / "derived" / "invariant_library_extended"
        self.det_root = self.tmp / "derived" / "detector_synthesis_v2"
        self.ws = self.tmp / "audits" / "testchain"
        self.scdir = self.ws / ".auditooor" / "hunt_findings_sidecars"
        self.scdir.mkdir(parents=True, exist_ok=True)
        self.env = {**os.environ,
                    "AUDITOOOR_VERDICT_OBLIGATION_LEDGER": str(self.ledger),
                    "AUDITOOOR_VERDICT_SINK_LOG": str(self.sinklog),
                    "AUDITOOOR_KDE_PATH": str(self.kde),
                    "AUDITOOOR_INV_BATCH_ROOT": str(self.inv_root),
                    "AUDITOOOR_DET_BATCH_ROOT": str(self.det_root)}

    def _sidecar(self, name: str, obj: dict):
        (self.scdir / name).write_text(json.dumps(obj), encoding="utf-8")

    def _gate(self):
        return subprocess.run(["python3", str(GATE), "--workspace", str(self.ws), "--json"],
                              text=True, env=self.env, capture_output=True)

    def test_confirmed_and_kill_sidecars_without_corpus_record_fail(self):
        # one CONFIRMED (HIGH) + one kill (collapse) sidecar in verdict-sink shape,
        # NO corpus record exists -> gate FAILS closed.
        self._sidecar("conf.json", {
            "task_id": "verdictsink_testchain_hunt_aaa1", "slug": "verdictsink_testchain_hunt_aaa1",
            "proposed_severity": "HIGH", "verdict": "needs-poc",
            "result": {"applies_to_target": "yes", "severity": "High", "final_verdict": "needs-poc"}})
        self._sidecar("kill.json", {
            "task_id": "verdictsink_testchain_adjudication_bbb2", "slug": "verdictsink_testchain_adjudication_bbb2",
            "proposed_severity": "", "verdict": "KILLED collapse collapse",
            "result": {"applies_to_target": "no", "final_verdict": "collapse"}})
        r = self._gate()
        self.assertEqual(r.returncode, 1, r.stdout)
        out = json.loads(r.stdout)
        self.assertEqual(out["verdict"], "fail-uncorpused-verdicts")
        classes = sorted(g["class"] for g in out["corpus_closure_gaps"])
        self.assertEqual(classes, ["confirmed", "kill"])

    def test_passes_once_etl_routes_to_corpus(self):
        # After the real ETL runs over the same sidecars, the slugs land in the
        # corpus (KDE for the kill, derived INV/detector for the confirmed) and the
        # gate PASSES. End-to-end: verdict-sink-shape sidecar -> ETL -> corpus -> gate.
        # CONFIRMED needs >=3 ETL mandatory fields (title, severity, audit_pin, evidence).
        self._sidecar("conf.json", {
            "task_id": "verdictsink_testchain_hunt_ccc3", "slug": "verdictsink_testchain_hunt_ccc3",
            "title": "theft via skipped guard", "proposed_severity": "HIGH",
            "audit_pin": "deadbeef", "summary": "victim funds drained",
            "affected_component": "src/Vault.sol:10", "attack_class": "theft",
            "verdict": "needs-poc",
            "result": {"applies_to_target": "yes", "severity": "High"}})
        self._sidecar("kill.json", {
            "task_id": "verdictsink_testchain_adjudication_ddd4", "slug": "verdictsink_testchain_adjudication_ddd4",
            "title": "view getter, no value sink", "proposed_severity": "",
            "why_dropped": "pure view, designed-as-intended", "verdict": "KILLED collapse",
            "result": {"applies_to_target": "no", "final_verdict": "collapse"}})
        etl = ROOT / "tools" / "hackerman-etl-from-finding-sidecars.py"
        rc = subprocess.run(["python3", str(etl), "--workspace", str(self.ws), "--json"],
                            text=True, env=self.env, capture_output=True)
        self.assertEqual(rc.returncode, 0, rc.stderr)
        etl_summ = json.loads(rc.stdout)
        # confirmed -> INV + detector seed; kill (collapse) -> known-dead-end
        self.assertGreaterEqual(etl_summ["invariant_records"], 1, etl_summ)
        self.assertGreaterEqual(etl_summ["new_kde_records"], 1, etl_summ)
        # both corpus stores now carry the slugs -> the closure gate passes
        self.assertTrue(self.kde.exists())
        r = self._gate()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(json.loads(r.stdout)["verdict"], "pass")

    def test_no_sidecars_passes(self):
        # empty hunt_findings_sidecars/ -> nothing to close -> pass
        r = self._gate()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_no_corpus_closure_flag_skips_check(self):
        self._sidecar("kill.json", {
            "task_id": "verdictsink_testchain_x_eee5", "slug": "verdictsink_testchain_x_eee5",
            "verdict": "KILLED collapse", "result": {"applies_to_target": "no"}})
        r = subprocess.run(["python3", str(GATE), "--workspace", str(self.ws),
                            "--no-corpus-closure", "--json"],
                           text=True, env=self.env, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
