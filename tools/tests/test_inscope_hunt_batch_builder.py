# <!-- r36-rebuttal: lane FIX-INSCOPE-HUNT-WORKLIST registered via agent-pathspec-register.py -->
"""Guard: inscope-hunt-batch-builder emits an IN-SCOPE-AUTHORITATIVE per-fn hunt
task-batch from inscope_units.jsonl - OOS units (kona/op-batcher/docs/test/...) are
dropped, in-scope units kept, anchors carry the real file + fn, and the prompt
instructs the agent to read+cite real source (R76)."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_hunt_batch_builder", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["inscope_hunt_batch_builder"] = m
    spec.loader.exec_module(m)
    return m


class InscopeHuntBatchBuilderTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True)
        rows = [
            {"file": "src/packages/contracts-bedrock/src/L1/OptimismPortal2.sol", "function": "finalizeWithdrawalTransaction", "lang": "solidity", "prior_covered": True},
            {"file": "src/op-node/rollup/derive/pipeline.go", "function": "", "lang": "go", "prior_covered": False},
            {"file": "src/rust/op-reth/crates/node/src/lib.rs", "function": "", "lang": "rust", "prior_covered": True},
            # OOS units that MUST be dropped:
            {"file": "src/rust/kona/crates/proof/src/core.rs", "function": "", "lang": "rust"},
            {"file": "src/op-batcher/rpc/api.go", "function": "NewAdminAPI", "lang": "go"},
            {"file": "src/docs/public-docs/public/tutorials/InteropToken.sol", "function": "crosschainMint", "lang": "solidity"},
            {"file": "src/packages/contracts-bedrock/test/L1/Foo.t.sol", "function": "testBar", "lang": "solidity"},
            {"file": "src/cannon/mipsevm/exec/memory.go", "function": "TrackMemAccess", "lang": "go"},
        ]
        (self.tmp / ".auditooor" / "inscope_units.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    def _build(self, **kw):
        tasks, err = self.m.build_tasks(self.tmp, kw.get("lang"), kw.get("only_uncovered", False), kw.get("limit"))
        self.assertIsNone(err, err)
        return tasks

    def test_oos_units_dropped_in_scope_kept(self):
        tasks = self._build()
        files = [t["function_anchor"]["file"] for t in tasks]
        # in-scope kept (3)
        self.assertEqual(len(tasks), 3, f"expected 3 in-scope, got {files}")
        joined = " ".join(files)
        self.assertIn("OptimismPortal2.sol", joined)
        self.assertIn("op-node/rollup", joined)
        self.assertIn("op-reth/crates", joined)
        # OOS dropped
        for oos in ("kona", "op-batcher", "tutorials", "/test/", "cannon"):
            self.assertNotIn(oos, joined, f"OOS leaked: {oos}")

    def test_task_shape_and_r76_prompt(self):
        t = next(t for t in self._build() if "OptimismPortal2" in t["function_anchor"]["file"])
        self.assertEqual(t["task_type"], "per_fn_workspace_hunt_v2")
        self.assertEqual(t["function_anchor"]["fn"], "finalizeWithdrawalTransaction")
        self.assertTrue(t["function_anchor"]["file"].endswith("OptimismPortal2.sol"))
        self.assertIn("READ THE REAL SOURCE", t["prompt"])
        self.assertIn("R76", t["prompt"])
        # Program/impacts are workspace-derived, NOT hardcoded OP Stack (generic fix).
        self.assertNotIn("op stack", t["prompt"].lower())
        self.assertNotIn("op-dispute-mon", t["prompt"].lower())
        self.assertIn("severity.md", t["prompt"].lower())  # impacts anchored to ws rubric

    def test_impact_anchor_uses_workspace_severity_rows(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / "SEVERITY.md").write_text(
                "# SEVERITY\n## Critical\n- Direct theft of any user funds\n"
                "- Unauthorized minting of interchain assets\n")
            anchor = mod._impact_anchor(str(ws))
            self.assertIn("Direct theft of any user funds", anchor)
            self.assertIn("Unauthorized minting of interchain assets", anchor)
            self.assertNotIn("op-dispute-mon", anchor.lower())

    def test_lang_filter(self):
        tasks = self._build(lang="solidity")
        self.assertEqual(len(tasks), 1)  # only the in-scope sol unit (tutorial+test are OOS)
        self.assertIn("OptimismPortal2", tasks[0]["function_anchor"]["file"])

    def test_only_uncovered(self):
        tasks = self._build(only_uncovered=True)
        files = " ".join(t["function_anchor"]["file"] for t in tasks)
        self.assertIn("op-node/rollup", files)          # prior_covered False -> kept
        self.assertNotIn("OptimismPortal2", files)       # prior_covered True -> dropped
        self.assertNotIn("op-reth/crates", files)        # prior_covered True -> dropped


if __name__ == "__main__":
    unittest.main(verbosity=2)
