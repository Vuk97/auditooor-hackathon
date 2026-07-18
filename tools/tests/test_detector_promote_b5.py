# <!-- r36-rebuttal: lane RW-RWBUILD-B5 registered via agent-pathspec-register.py -->
"""B5 detector->hunt promoter regression: inscope-hunt-batch-builder.py converts each
RESOLVED detector_action_graph row (detector_hit with a concrete file:line) into one
detector_promoted_hunt task when AUDITOOOR_DETECTOR_PROMOTE_HUNT=1; env-off default
dispatch is byte-identical (no promoted tasks)."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "inscope-hunt-batch-builder.py"


def _load():
    spec = importlib.util.spec_from_file_location("inscope_hunt_batch_builder_b5", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["inscope_hunt_batch_builder_b5"] = m
    spec.loader.exec_module(m)
    return m


class DetectorPromoteB5Test(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / ".auditooor").mkdir(parents=True)
        (self.tmp / "src").mkdir(parents=True)
        (self.tmp / "src" / "Vault.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Vault { function f() external {} }\n",
            encoding="utf-8")
        (self.tmp / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/Vault.sol", "function": "f", "lang": "solidity",
                        "file_line": "src/Vault.sol:1", "prior_covered": False}) + "\n",
            encoding="utf-8")
        # legacy detector_action_graph.json with a RESOLVED hit.
        (self.tmp / ".auditooor" / "detector_action_graph.json").write_text(json.dumps({
            "advisory_only": True,
            "detector_hit": {"detector_slug": "uups-authorize-upgrade-missing-gate",
                             "file_path": "src/Vault.sol:1", "severity": "HIGH",
                             "snippet": "authorizeUpgrade lacks onlyOwner"},
            "proof_obligations": [{"id": "P-001", "title": "Confirm the detector hit on real source"}],
        }), encoding="utf-8")
        os.environ.pop("AUDITOOOR_DETECTOR_PROMOTE_HUNT", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_DETECTOR_PROMOTE_HUNT", None)

    def _run(self, out: Path):
        rc = self.m.main(["--workspace", str(self.tmp), "--out", str(out)])
        self.assertEqual(rc, 0)
        return out.read_bytes(), [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

    def test_env_on_promotes_resolved_graph(self):
        os.environ["AUDITOOOR_DETECTOR_PROMOTE_HUNT"] = "1"
        _, rows = self._run(self.tmp / "on.jsonl")
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["task_type"], "detector_promoted_hunt")
        self.assertEqual(r["source_of_truth"], "detector_action_graph")
        self.assertEqual(r["detector_slug"], "uups-authorize-upgrade-missing-gate")
        self.assertEqual(r["function_anchor"]["start_line"], 1)
        # the proof obligation title enriches the prompt
        self.assertIn("Confirm the detector hit on real source", r["prompt"])

    def test_unresolved_graph_not_promoted(self):
        # a graph with NO concrete file:line must NOT produce a task -> falls through.
        (self.tmp / ".auditooor" / "detector_action_graph.json").write_text(json.dumps({
            "advisory_only": True,
            "detector_hit": {"detector_slug": "vague", "file_path": "", "severity": "LOW"},
        }), encoding="utf-8")
        os.environ["AUDITOOOR_DETECTOR_PROMOTE_HUNT"] = "1"
        _, rows = self._run(self.tmp / "on.jsonl")
        # falls through to legacy dispatch (the 1 inscope unit), no promoted task
        self.assertTrue(all(r.get("task_type") != "detector_promoted_hunt" for r in rows))
        self.assertTrue(len(rows) >= 1)

    def test_dedup_across_legacy_and_perhit_graphs(self):
        # a per-hit graph directory with the SAME resolved hit must dedup on file:line+slug.
        gd = self.tmp / ".auditooor" / "detector_action_graphs"
        gd.mkdir(parents=True)
        (gd / "hit_000_x.json").write_text(json.dumps({
            "detector_hit": {"detector_slug": "uups-authorize-upgrade-missing-gate",
                             "file_path": "src/Vault.sol:1", "severity": "HIGH"},
        }), encoding="utf-8")
        os.environ["AUDITOOOR_DETECTOR_PROMOTE_HUNT"] = "1"
        _, rows = self._run(self.tmp / "on.jsonl")
        self.assertEqual(len(rows), 1)  # deduped, not 2

    def test_env_off_byte_identical(self):
        b1, rows = self._run(self.tmp / "off.jsonl")
        self.assertTrue(all(r.get("task_type") != "detector_promoted_hunt" for r in rows))
        b2, _ = self._run(self.tmp / "off2.jsonl")
        self.assertEqual(b1, b2)


if __name__ == "__main__":
    unittest.main()
