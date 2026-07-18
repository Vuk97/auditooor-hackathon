"""Loop-fix 2026-06-23 (etherfi step-5 full per-fn hunt): workflow-drill-sidecar-emit
named each sidecar `<sanitized task_id>.json` and OVERWROTE silently on a name clash.
Parallel hunt agents routinely pass DUPLICATE task_ids (each independently auto-numbers
perfn_mimo_etherfi_00161.. from the same base), so a 36-task / 3-batch wave collapsed to
12 surviving files -> ~24 per-function coverage verdicts silently lost.

Fix: emit_one never overwrites a sidecar whose content DIFFERS. An idempotent re-emit of
the SAME content maps back to the same file (no dup spam); a genuinely distinct verdict
that lands on a taken name is disambiguated with a short content hash (no lost coverage).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("wdse", str(_TOOLS / "workflow-drill-sidecar-emit.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wdse"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestSidecarEmitCollisionSafe(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.out = Path(tempfile.mkdtemp())

    def _rec(self, task_id, file_line, fn="f"):
        return {"workspace": "etherfi", "task_id": task_id, "verdict": "KILL",
                "file_line": file_line, "code_excerpt": f"function {fn}() {{}}",
                "reasoning": f"ruled out {fn}", "applies_to_target": "no"}

    def test_duplicate_task_id_distinct_content_does_not_overwrite(self):
        # Two agents pass the SAME task_id but rule out DIFFERENT functions.
        p1, _ = self.m.emit_one(self._rec("perfn_mimo_etherfi_00161", "A.sol:10", "a"), self.out)
        p2, _ = self.m.emit_one(self._rec("perfn_mimo_etherfi_00161", "B.sol:20", "b"), self.out)
        self.assertNotEqual(p1, p2, "distinct-content collision must NOT overwrite")
        self.assertEqual(len(list(self.out.glob("*.json"))), 2, "both verdicts must survive")

    def test_idempotent_same_content_reuses_same_file(self):
        # An idempotent re-emit of identical content must not spam duplicates.
        r = self._rec("perfn_mimo_etherfi_00161", "A.sol:10", "a")
        p1, _ = self.m.emit_one(r, self.out)
        p2, _ = self.m.emit_one(r, self.out)
        self.assertEqual(p1, p2, "identical re-emit should map back to the same file")
        self.assertEqual(len(list(self.out.glob("*.json"))), 1)

    def test_three_way_collision_keeps_all(self):
        for i, fl in enumerate(["A.sol:1", "B.sol:2", "C.sol:3"]):
            self.m.emit_one(self._rec("perfn_mimo_etherfi_00161", fl, f"f{i}"), self.out)
        files = list(self.out.glob("*.json"))
        self.assertEqual(len(files), 3, "all 3 distinct verdicts must survive a 3-way clash")
        seen = {json.loads(json.loads(p.read_text())["result"])["file_line"] for p in files}
        self.assertEqual(seen, {"A.sol:1", "B.sol:2", "C.sol:3"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
