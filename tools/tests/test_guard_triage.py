#!/usr/bin/env python3
"""Tests for guard-triage: ranks fns by guard-risk from the guard artifacts;
ignores non-.sol tooling-noise pairs; degrades cleanly when inputs absent."""
import importlib.util, json, tempfile, unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "guard_triage", str(Path(__file__).resolve().parent.parent / "guard-triage.py"))
gt = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(gt)


def _mk(tmp, asym=None, nspace=None):
    ws = Path(tmp); (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    if asym is not None:
        (ws / ".auditooor" / "sibling_guard_asymmetries.jsonl").write_text(
            "\n".join(json.dumps(r) for r in asym))
    if nspace is not None:
        (ws / ".auditooor" / "negative_space_worklist.jsonl").write_text(
            "\n".join(json.dumps(r) for r in nspace))
    return ws


class T(unittest.TestCase):
    def setUp(self): import tempfile; self.tmp = tempfile.mkdtemp()

    def test_missing_guard_fn_scored_and_ranked(self):
        ws = _mk(self.tmp, asym=[{
            "path_a": {"file": "src/A.sol", "name": "deposit", "line": 10},
            "path_b": {"file": "src/A.sol", "name": "withdraw", "line": 20},
            "guard_on_b_missing_on_a": ["nonReentrant"]}])
        rep = gt.triage(ws)
        self.assertEqual(rep["real_sibling_pairs"], 1)
        top = rep["risk_units"][0]
        self.assertIn("deposit", top["unit"]); self.assertEqual(top["score"], 2)

    def test_non_sol_pair_ignored(self):
        ws = _mk(self.tmp, asym=[{
            "path_a": {"file": "abi.json", "name": "x"},
            "path_b": {"file": "README.md", "name": "y"},
            "guard_on_b_missing_on_a": ["onlyOwner"]}])
        self.assertEqual(gt.triage(ws)["real_sibling_pairs"], 0)

    def test_negspace_hi_kind_scored(self):
        ws = _mk(self.tmp, nspace=[
            {"file_line": "src/A.sol:5", "kinds": ["access-control"], "invariant_hint": ""},
            {"file_line": "src/A.sol:9", "kinds": ["formatting"], "invariant_hint": "cosmetic"}])
        rep = gt.triage(ws)
        units = {r["unit"] for r in rep["risk_units"]}
        self.assertIn("src/A.sol:5", units)       # access-control scored
        self.assertNotIn("src/A.sol:9", units)    # cosmetic ignored

    def test_absent_inputs_clean(self):
        ws = Path(self.tmp)
        rep = gt.triage(ws)
        self.assertFalse(rep["inputs_present"]); self.assertEqual(rep["guard_risk_units"], 0)


if __name__ == "__main__":
    unittest.main()
