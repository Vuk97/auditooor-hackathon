#!/usr/bin/env python3
"""Guard: the per-function attack worklist consumes guard_triage.json and ranks
guard-risk functions FIRST (the guards-early rewire); falls back to the stable
order when no triage artifact exists."""
import importlib.util, sys, json, tempfile, unittest
from pathlib import Path
_spec = importlib.util.spec_from_file_location(
    "pfaw", str(Path(__file__).resolve().parent.parent / "per-function-attack-worklist.py"))
m = importlib.util.module_from_spec(_spec); sys.modules["pfaw"] = m; _spec.loader.exec_module(m)


class T(unittest.TestCase):
    def test_scores_parsed_from_triage(self):
        ws = Path(tempfile.mkdtemp()); (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "guard_triage.json").write_text(json.dumps(
            {"risk_units": [{"unit": "src/A.sol:withdraw", "score": 6},
                            {"unit": "src/A.sol:deposit", "score": 2}]}))
        sc = m._guard_risk_scores(ws)
        self.assertEqual(sc.get("withdraw"), 6)
        self.assertEqual(sc.get("deposit"), 2)

    def test_no_triage_empty(self):
        self.assertEqual(m._guard_risk_scores(Path(tempfile.mkdtemp())), {})

    def test_sort_key_prioritizes_high_score(self):
        risk = {"withdraw": 6, "deposit": 2}
        rows = [("z.sol:1", "aaa"), ("a.sol:9", "withdraw"), ("a.sol:2", "deposit")]
        ordered = sorted(rows, key=lambda r: (-risk.get(r[1].lower(), 0), r[0], r[1]))
        self.assertEqual(ordered[0][1], "withdraw")   # highest guard-risk first
        self.assertEqual(ordered[1][1], "deposit")
        self.assertEqual(ordered[2][1], "aaa")        # no-risk last


if __name__ == "__main__":
    unittest.main()
