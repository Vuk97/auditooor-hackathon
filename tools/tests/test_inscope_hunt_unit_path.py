# <!-- r36-rebuttal: lane df-wire registered via agent-pathspec-register.py -->
"""Guard: inscope-hunt-batch-builder --unit path (df-wire).

- Default --unit function is byte-identical to the legacy default (no --unit flag).
- --unit path with NO dataflow_paths.jsonl degrades to per-function (never fewer units).
- --unit path with a slice emits one per_path task per UNGUARDED multi-hop/storage path,
  skips guarded + degraded + single-intra paths, and falls back to per-function for the rest.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_hunt_batch_builder_pathtest", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def _path(path_id, src_file, src_fn, src_line, snk_file, snk_fn, snk_line,
          call_depth=1, unguarded=True, degraded=False, storage=False, confidence="semantic-ssa"):
    via = "storage" if storage else "internal_call"
    hops = [] if call_depth == 0 and not storage else [{
        "from_var": "x", "to_var": "y", "fn": src_fn, "via": via,
        "file": src_file, "line": src_line, "ir": "", "guarded": False,
    }]
    return {
        "schema": "dataflow_path.v1", "path_id": path_id, "language": "solidity",
        "direction": "forward", "engine": "evm-ssa",
        "source": {"kind": "param", "fn": src_fn, "var": "x", "file": src_file, "line": src_line},
        "sink": {"kind": "call", "callee": snk_fn, "arg_pos": 0, "fn": snk_fn, "file": snk_file, "line": snk_line},
        "hops": hops, "call_depth": call_depth, "unguarded": unguarded,
        "guard_nodes": [], "source_unit_ids": [], "sink_unit_ids": [],
        "confidence": confidence, "degraded": degraded,
    }


class UnitPathTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir(parents=True)
        (self.ws / "a.sol").write_text(
            "contract A {\n  function entry(uint a) public { _move(a); }\n"
            "  function _move(uint v) internal { token.transfer(msg.sender, v); }\n}\n",
            encoding="utf-8")
        cov = {"functions": [
            {"name": "entry", "file": "a.sol", "line": 2, "lang": "sol", "classification": "untouched"},
            {"name": "_move", "file": "a.sol", "line": 3, "lang": "sol", "classification": "untouched"},
        ]}
        (self.ws / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps(cov), encoding="utf-8")

    def _write_paths(self, paths):
        (self.ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
            "".join(json.dumps(p) + "\n" for p in paths), encoding="utf-8")

    def test_path_mode_emits_per_path_task(self):
        self._write_paths([_path("p1", "a.sol", "entry", 2, "a.sol", "transfer", 3, call_depth=1)])
        tasks, err = self.m.build_path_tasks(self.ws, None, False, None)
        self.assertIsNone(err, err)
        path_tasks = [t for t in tasks if t["task_type"] == self.m.PATH_TASK_TYPE]
        self.assertEqual(len(path_tasks), 1)
        t = path_tasks[0]
        self.assertEqual(t["path_id"], "p1")
        self.assertIn("DATA-FLOW PATH", t["prompt"])
        self.assertIn("a.sol:2", t["prompt"])  # source line
        self.assertIn("a.sol:3", t["prompt"])  # sink line

    def test_guarded_and_degraded_and_intra_skipped(self):
        self._write_paths([
            _path("guarded", "a.sol", "entry", 2, "a.sol", "transfer", 3, unguarded=False),
            _path("degraded", "a.sol", "entry", 2, "a.sol", "transfer", 3, degraded=True),
            _path("intra", "a.sol", "entry", 2, "a.sol", "transfer", 2, call_depth=0),
        ])
        tasks, err = self.m.build_path_tasks(self.ws, None, False, None)
        self.assertIsNone(err, err)
        path_tasks = [t for t in tasks if t["task_type"] == self.m.PATH_TASK_TYPE]
        self.assertEqual(len(path_tasks), 0, "guarded/degraded/intra paths must not become path tasks")

    def test_storage_mediated_path_emitted_even_zero_call_depth(self):
        self._write_paths([
            _path("stor", "a.sol", "entry", 2, "a.sol", "transfer", 3, call_depth=0, storage=True),
        ])
        tasks, err = self.m.build_path_tasks(self.ws, None, False, None)
        path_tasks = [t for t in tasks if t["task_type"] == self.m.PATH_TASK_TYPE]
        self.assertEqual(len(path_tasks), 1)

    def test_fallback_to_per_function_for_uncovered_units(self):
        # only `entry` participates in a path; `_move` should still get a per-function task.
        self._write_paths([_path("p1", "a.sol", "entry", 2, "a.sol", "transfer", 3, call_depth=1)])
        tasks, err = self.m.build_path_tasks(self.ws, None, False, None)
        self.assertIsNone(err, err)
        fn_tasks = [t for t in tasks if t["task_type"] != self.m.PATH_TASK_TYPE]
        names = {(t["function_anchor"]["fn"]) for t in fn_tasks}
        self.assertIn("_move", names, "per-function fallback must cover units not in any path")

    def test_absent_slice_degrades_to_per_function(self):
        # No dataflow_paths.jsonl -> behave exactly as per-function.
        tasks_path, err = self.m.build_path_tasks(self.ws, None, False, None)
        self.assertIsNone(err, err)
        tasks_fn, _ = self.m.build_tasks_per_function(self.ws, None, False, None, False, embed_source=True)
        self.assertEqual(
            sorted(t["function_anchor"]["fn"] for t in tasks_path),
            sorted(t["function_anchor"]["fn"] for t in tasks_fn),
        )
        self.assertTrue(all(t["task_type"] != self.m.PATH_TASK_TYPE for t in tasks_path))

    def test_default_unit_function_byte_identical(self):
        # CLI default --unit function must equal the legacy path with NO --unit flag.
        out_legacy = self.ws / "legacy.jsonl"
        out_default = self.ws / "default.jsonl"
        rc1 = self.m.main(["--workspace", str(self.ws), "--per-function", "--out", str(out_legacy)])
        rc2 = self.m.main(["--workspace", str(self.ws), "--per-function", "--unit", "function",
                           "--out", str(out_default)])
        self.assertEqual(rc1, 0)
        self.assertEqual(rc2, 0)
        self.assertEqual(out_legacy.read_text(encoding="utf-8"),
                         out_default.read_text(encoding="utf-8"),
                         "default --unit function must be byte-identical to no --unit flag")


if __name__ == "__main__":
    unittest.main()
