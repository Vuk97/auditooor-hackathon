import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


PATH = Path(__file__).resolve().parent.parent / "hunt-provider-sidecar-reconcile.py"
SPEC = importlib.util.spec_from_file_location("reconcile", PATH)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)


class ReconcileTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.ws = self.root / "sample"
        self.plan = self.root / "derived" / "haiku_harness_sample_scoped_n2" / "_haiku_plan"
        self.sidecars = self.ws / ".auditooor" / "hunt_findings_sidecars"
        self.plan.mkdir(parents=True)
        self.sidecars.mkdir(parents=True)
        for index, task_id in enumerate(("task_a", "task_b")):
            (self.plan / f"agent_batch_{index:04d}.md").write_text(
                f"### Task 1: {task_id}\n", encoding="utf-8"
            )

    def _write(self, task_id, provider="sonnet-via-agent", result=None):
        data = {
            "task_id": task_id,
            "workspace": "sample",
            "workspace_path": str(self.ws),
            "provider": provider,
            "status": "ok",
            "result": json.dumps(result or {"applies_to_target": "no"}),
        }
        (self.sidecars / f"{task_id}.json").write_text(json.dumps(data), encoding="utf-8")

    def test_all_tasks_reconcile(self):
        self._write("task_a")
        self._write("task_b")
        receipt = MOD.reconcile(self.ws, self.plan, self.sidecars, "sonnet-via-agent")
        self.assertEqual(receipt["terminal_counts"], {"ok": 2, "failed": 0})

    def test_missing_or_wrong_identity_fails(self):
        self._write("task_a", provider="local-cli")
        receipt = MOD.reconcile(self.ws, self.plan, self.sidecars, "sonnet-via-agent")
        self.assertEqual(receipt["terminal_counts"], {"ok": 0, "failed": 2})
        self.assertTrue(any("task_b" in item for item in receipt["reconciliation"]["errors"]))


if __name__ == "__main__":
    unittest.main()
