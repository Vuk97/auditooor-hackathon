"""Regression: assumption-enumeration-falsification consumes the guard-closure verdict.

Root-caused 2026-07-14 (guard-feed audit): the reasoner read dataflow_paths.jsonl
but folded only guard_nodes[].expr, ignoring the authoritative per-path
closure_guarded / unguarded verdicts -> it emitted ~60 nuva assumption-negation
obligations as `falsifiable` while every reachable path to their sink was already
closure-guarded (the precision leak). load_dataflow must now fold the closure
verdict, and a unit whose every reachable path is closure-guarded (>=1 guarded,
0 genuinely-unguarded) must be guard-dominated. Conservative: any unguarded path
keeps the unit falsifiable, so a real attack surface is never suppressed.
"""
import importlib.util
import json
import pathlib
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "assumption-enumeration-falsification.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("aef_guard_test", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestAssumptionFalsificationGuardClosure(unittest.TestCase):
    def setUp(self):
        self.m = _load_mod()
        self.tmp = tempfile.mkdtemp(prefix="aefguard_")
        self.ws = pathlib.Path(self.tmp)
        (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_df(self, rows):
        p = self.ws / ".auditooor" / "dataflow_paths.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in rows))

    def _fold(self):
        agg = self.m.load_dataflow(self.ws)
        return agg

    def test_all_paths_closure_guarded_is_dominated(self):
        # one unit, two paths, BOTH closure-guarded, none unguarded -> dominated
        self._write_df([
            {"source": {"file": "x.go", "fn": "F", "line": 10}, "sink": {"kind": "transfer"},
             "closure_guarded": True, "closure_note": "onlyRole guard"},
            {"source": {"file": "x.go", "fn": "F", "line": 10}, "sink": {"kind": "send"},
             "closure_guarded": True},
        ])
        agg = self._fold()
        rec = next(v for v in agg.values() if v["file"] == "x.go")
        self.assertEqual(rec["closure_guarded_n"], 2)
        self.assertEqual(rec["unguarded_n"], 0)
        dominated = rec["closure_guarded_n"] > 0 and rec["unguarded_n"] == 0
        self.assertTrue(dominated, "all-paths-closure-guarded unit must be guard-dominated")
        self.assertEqual(rec["closure_note"], "onlyRole guard")

    def test_any_unguarded_path_is_not_dominated(self):
        # one guarded path + one genuinely-unguarded path -> NOT dominated (attack surface kept)
        self._write_df([
            {"source": {"file": "y.go", "fn": "G", "line": 5}, "sink": {"kind": "transfer"},
             "closure_guarded": True},
            {"source": {"file": "y.go", "fn": "G", "line": 5}, "sink": {"kind": "transfer"},
             "unguarded": True},
        ])
        rec = next(v for v in self._fold().values() if v["file"] == "y.go")
        self.assertEqual(rec["unguarded_n"], 1)
        dominated = rec["closure_guarded_n"] > 0 and rec["unguarded_n"] == 0
        self.assertFalse(dominated, "a unit with an unguarded path must stay falsifiable")

    def test_closure_corrected_unguarded_does_not_count_as_unguarded(self):
        # unguarded flag but closure-correction found a guard -> treated as guarded, dominated
        self._write_df([
            {"source": {"file": "z.go", "fn": "H", "line": 1}, "sink": {"kind": "mint"},
             "closure_guarded": True},
            {"source": {"file": "z.go", "fn": "H", "line": 1}, "sink": {"kind": "mint"},
             "unguarded": True, "unguarded_closure_corrected": True},
        ])
        rec = next(v for v in self._fold().values() if v["file"] == "z.go")
        self.assertEqual(rec["unguarded_n"], 0,
                         "unguarded_closure_corrected=True must NOT count as a genuine unguarded path")
        self.assertTrue(rec["closure_guarded_n"] > 0 and rec["unguarded_n"] == 0)


if __name__ == "__main__":
    unittest.main()
