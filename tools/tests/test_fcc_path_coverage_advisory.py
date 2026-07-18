"""Guard: function-coverage-completeness additive ADVISORY path_coverage block
(df-wire). When .auditooor/dataflow_paths.jsonl is ABSENT the report shape + all
existing counts/classification are byte-identical (no path_coverage key). When the
slice exists, an advisory path_coverage block is ADDED that NEVER changes the
real_attack/hollow/untouched counts or the verdict, and a DefUsePath is path-covered
iff both its source and sink functions are real-attack covered.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "function-coverage-completeness.py"
_spec = importlib.util.spec_from_file_location("function_coverage_completeness", _MOD)
fcc = importlib.util.module_from_spec(_spec)
sys.modules["function_coverage_completeness"] = fcc
_spec.loader.exec_module(fcc)

SRC = (
    "pub struct S { x: u64 }\n"
    "impl S {\n"
    "  pub fn tally(&self) -> u64 { self.x }\n"
    "  pub fn risky(&self, a: u64) -> u64 {\n"
    "    if a > 0 { self.x } else { 0 }\n"
    "  }\n"
    "}\n"
)


def _mkws(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="fcc_pc_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def _sidecar(fn, line):
    return json.dumps({
        "function": fn, "file": "src/lib.rs", "line": line,
        "file_line": f"src/lib.rs:{line}", "source_refs": [f"src/lib.rs:{line}"],
        "verdict": "NEGATIVE", "in_scope": True,
        "code_excerpt": "self.x", "reason": "source-verified clean: pure accessor",
    })


def _path(path_id, src_fn, snk_fn, degraded=False):
    return json.dumps({
        "schema": "dataflow_path.v1", "path_id": path_id, "language": "rust",
        "direction": "forward", "engine": "rust-ssa",
        "source": {"kind": "param", "fn": src_fn, "var": "a", "file": "src/lib.rs", "line": 3},
        "sink": {"kind": "call", "callee": snk_fn, "arg_pos": 0, "fn": snk_fn, "file": "src/lib.rs", "line": 4},
        "hops": [{"from_var": "a", "to_var": "b", "fn": src_fn, "via": "internal_call",
                  "file": "src/lib.rs", "line": 3, "ir": "", "guarded": False}],
        "call_depth": 1, "unguarded": True, "guard_nodes": [],
        "source_unit_ids": [], "sink_unit_ids": [], "confidence": "semantic-ssa",
        "degraded": degraded,
    })


class FccPathCoverageAdvisoryTest(unittest.TestCase):
    def _base_files(self):
        # tally credited real-attack via a clean trivial verdict; risky stays hollow.
        return {
            "src/lib.rs": SRC,
            ".auditooor/hunt_findings_sidecars/tally.json": _sidecar("tally", 3),
        }

    def test_absent_slice_no_path_coverage_key(self):
        ws = _mkws(self._base_files())
        r = fcc.evaluate(ws)
        self.assertNotIn("path_coverage", r,
                         "no dataflow slice -> report must not carry path_coverage")

    def test_counts_identical_with_and_without_slice(self):
        # Run once without the slice, once with - counts/verdict/classification must match.
        files = self._base_files()
        ws_a = _mkws(files)
        r_a = fcc.evaluate(ws_a)

        ws_b = _mkws(files)
        (ws_b / ".auditooor" / "dataflow_paths.jsonl").write_text(
            _path("p1", "risky", "tally") + "\n", encoding="utf-8")
        r_b = fcc.evaluate(ws_b)

        self.assertEqual(r_a["counts"], r_b["counts"],
                         "path_coverage block must not change classification counts")
        self.assertEqual(r_a["verdict"], r_b["verdict"],
                         "path_coverage block must not change the verdict")
        cls_a = {f["name"]: f["classification"] for f in r_a["functions"]}
        cls_b = {f["name"]: f["classification"] for f in r_b["functions"]}
        self.assertEqual(cls_a, cls_b)
        self.assertIn("path_coverage", r_b)
        self.assertTrue(r_b["path_coverage"]["advisory"])

    def test_path_covered_iff_both_endpoints_real_attack(self):
        # path src=risky (hollow), sink=tally (real-attack) -> NOT path-covered (gap).
        files = self._base_files()
        ws = _mkws(files)
        (ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
            _path("gap", "risky", "tally") + "\n", encoding="utf-8")
        r = fcc.evaluate(ws)
        pc = r["path_coverage"]
        self.assertEqual(pc["total_paths"], 1)
        self.assertEqual(pc["path_covered"], 0)
        self.assertEqual(pc["path_uncovered"], 1)
        self.assertEqual(len(pc["uncovered_unguarded_gaps"]), 1)
        gap = pc["uncovered_unguarded_gaps"][0]
        self.assertTrue(gap["sink_covered"])      # tally is real-attack
        self.assertFalse(gap["source_covered"])   # risky is hollow

    def test_degraded_path_skipped_in_coverage(self):
        files = self._base_files()
        ws = _mkws(files)
        (ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
            _path("dead", "risky", "tally", degraded=True) + "\n", encoding="utf-8")
        r = fcc.evaluate(ws)
        pc = r["path_coverage"]
        self.assertEqual(pc["total_paths"], 0)
        self.assertEqual(pc["degraded_records_skipped"], 1)


if __name__ == "__main__":
    unittest.main()
