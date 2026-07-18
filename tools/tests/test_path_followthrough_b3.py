# <!-- r36-rebuttal: lane RW-RWBUILD-B3 registered via agent-pathspec-register.py -->
"""B3 dataflow path follow-through regression:
1. function-coverage-completeness._compute_path_coverage EXTEND: uncovered_unguarded_gaps
   rows carry additive machine-parseable endpoint fields (source_file/line/fn +
   sink_file/line/callee + unguarded) WITHOUT changing the pre-existing prose keys.
2. inscope-hunt-batch-builder emits one per_path_dataflow_hunt task per uncovered
   unguarded gap whose endpoints are NOT already followed through (joined to
   hunt_findings_sidecars/ by file:line) when AUDITOOOR_PATH_FOLLOWTHROUGH=1;
   env-off default dispatch is byte-identical (no path tasks)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_INSCOPE = _TOOLS / "inscope-hunt-batch-builder.py"
_FCC = _TOOLS / "function-coverage-completeness.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


class _FakeFn:
    def __init__(self, file, name, classification):
        self.file = file
        self.name = name
        self.classification = classification


class FccExtendB3Test(unittest.TestCase):
    def setUp(self):
        self.m = _load(_FCC, "function_coverage_completeness_b3ext")
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True)
        # one unguarded path whose endpoints are NOT real-attack covered -> a gap.
        row = {
            "path_id": "dfp-0001", "unguarded": True, "call_depth": 1,
            "confidence": "semantic-ssa",
            "source": {"file": "src/Vault.sol", "line": 10, "fn": "deposit", "var": "amt", "kind": "arg"},
            "sink": {"file": "src/Vault.sol", "line": 20, "fn": "withdraw", "callee": "transfer", "arg_pos": 0},
        }
        (self.tmp / ".auditooor" / "dataflow_paths.jsonl").write_text(
            json.dumps(row) + "\n", encoding="utf-8")

    def test_gap_carries_machine_parseable_endpoints(self):
        fns = [_FakeFn("src/Other.sol", "foo", "untouched")]  # neither endpoint covered
        pc = self.m._compute_path_coverage(self.tmp, fns)
        self.assertIsNotNone(pc)
        gaps = pc["uncovered_unguarded_gaps"]
        self.assertEqual(len(gaps), 1)
        g = gaps[0]
        # pre-existing prose keys still present (byte-shape backward compat)
        for k in ("path_id", "source", "sink", "call_depth", "confidence",
                  "source_covered", "sink_covered"):
            self.assertIn(k, g)
        # additive machine-parseable endpoints
        self.assertEqual(g["source_file"], "src/Vault.sol")
        self.assertEqual(g["source_line"], 10)
        self.assertEqual(g["source_fn"], "deposit")
        self.assertEqual(g["sink_file"], "src/Vault.sol")
        self.assertEqual(g["sink_line"], 20)
        self.assertEqual(g["sink_callee"], "transfer")
        self.assertTrue(g["unguarded"])
        # prose form unchanged
        self.assertEqual(g["source"], "src/Vault.sol:10 (deposit)")


class InscopeB3FollowThroughTest(unittest.TestCase):
    def setUp(self):
        self.m = _load(_INSCOPE, "inscope_hunt_batch_builder_b3")
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True)
        (self.tmp / "src").mkdir(parents=True)
        (self.tmp / "src" / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Vault {\n"
            "  function deposit() external {}\n"
            "  function withdraw() external {}\n"
            "}\n", encoding="utf-8")
        # inscope manifest so the env-off legacy path has a non-empty output.
        (self.tmp / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/Vault.sol", "function": "deposit", "lang": "solidity",
                        "file_line": "src/Vault.sol:3", "prior_covered": False}) + "\n",
            encoding="utf-8")
        # persisted path_coverage with two uncovered unguarded gaps.
        fcc = {
            "path_coverage": {
                "advisory": True,
                "uncovered_unguarded_gaps": [
                    {"path_id": "g1", "unguarded": True, "call_depth": 2,
                     "confidence": "semantic-ssa",
                     "source": "src/Vault.sol:10 (deposit)",
                     "sink": "src/Vault.sol:20 (transfer)",
                     "source_file": "src/Vault.sol", "source_line": 10, "source_fn": "deposit",
                     "sink_file": "src/Vault.sol", "sink_line": 20, "sink_callee": "transfer"},
                    {"path_id": "g2", "unguarded": True, "call_depth": 0,
                     "confidence": "heuristic",
                     "source": "src/Vault.sol:30 (redeem)",
                     "sink": "src/Vault.sol:40 (send)",
                     "source_file": "src/Vault.sol", "source_line": 30, "source_fn": "redeem",
                     "sink_file": "src/Vault.sol", "sink_line": 40, "sink_callee": "send"},
                ],
            },
        }
        (self.tmp / ".auditooor" / "function_coverage_completeness.json").write_text(
            json.dumps(fcc), encoding="utf-8")
        os.environ.pop("AUDITOOOR_PATH_FOLLOWTHROUGH", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_PATH_FOLLOWTHROUGH", None)

    def _run(self, out: Path, argv_extra=None):
        argv = ["--workspace", str(self.tmp), "--out", str(out)] + (argv_extra or [])
        rc = self.m.main(argv)
        self.assertEqual(rc, 0)
        return out.read_bytes(), [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

    def test_env_on_emits_per_path_tasks(self):
        os.environ["AUDITOOOR_PATH_FOLLOWTHROUGH"] = "1"
        _, rows = self._run(self.tmp / "on.jsonl")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["task_type"] == "per_path_dataflow_hunt" for r in rows))
        self.assertTrue(all(r.get("source_of_truth") == "path_coverage" for r in rows))
        # deeper-call-depth gap ranks first
        self.assertEqual(rows[0]["path_id"], "g1")

    def test_sidecar_join_excludes_followed_gaps(self):
        # add a hunt sidecar anchored at g1's source (Vault.sol:10) -> g1 excluded.
        sc_dir = self.tmp / ".auditooor" / "hunt_findings_sidecars"
        sc_dir.mkdir(parents=True)
        (sc_dir / "s.json").write_text(json.dumps({
            "function_anchor": {"file": "src/Vault.sol", "line": 10},
            "result": {"verdict": "KILL"},
        }), encoding="utf-8")
        os.environ["AUDITOOOR_PATH_FOLLOWTHROUGH"] = "1"
        _, rows = self._run(self.tmp / "on.jsonl")
        ids = {r["path_id"] for r in rows}
        self.assertNotIn("g1", ids)   # already followed through
        self.assertIn("g2", ids)

    def test_env_off_byte_identical_default(self):
        b1, rows = self._run(self.tmp / "off.jsonl")
        self.assertTrue(all(r.get("task_type") != "per_path_dataflow_hunt" for r in rows))
        b2, _ = self._run(self.tmp / "off2.jsonl")
        self.assertEqual(b1, b2)


if __name__ == "__main__":
    unittest.main()
