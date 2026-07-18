"""Regression: impact-first-backward-search (novelty-layer engine #3, was missing).

A mega-impact sink reached on an UNGUARDED path with an UNGUARDED backward
entrypoint (backward_entrypoints_total > guarded) is an impact-first candidate;
a guarded backward entrypoint or a guarded path is NOT; a substrate lacking the
backward_entrypoints field reports substrate_missing_backptr (honest, not a
silent vacuous 0).
"""
import importlib.util, json, pathlib, tempfile, unittest
_TOOL = pathlib.Path(__file__).resolve().parent.parent / "impact-first-backward-search.py"

def _load():
    spec = importlib.util.spec_from_file_location("ifbs", _TOOL)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

class TestImpactFirstBackwardSearch(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.tmp = tempfile.mkdtemp(prefix="ifbs_")
        self.ws = pathlib.Path(self.tmp); (self.ws / ".auditooor").mkdir(parents=True)
    def tearDown(self):
        import shutil; shutil.rmtree(self.tmp, ignore_errors=True)
    def _df(self, rows):
        (self.ws / ".auditooor" / "dataflow_paths.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows))

    def test_unguarded_impact_with_unguarded_entrypoint_is_candidate(self):
        self._df([{"sink": {"kind": "mint", "file": "T.sol", "line": 9},
                   "unguarded": True, "backward_entrypoints_total": 2,
                   "backward_entrypoints_guarded": 0}])
        rep = self.m.analyse(self.ws)
        self.assertEqual(rep["obligation_count"], 1)
        self.assertEqual(rep["obligations"][0]["impact_tier"], "critical")

    def test_guarded_backward_entrypoint_is_not_candidate(self):
        self._df([{"sink": {"kind": "transfer", "file": "T.sol", "line": 9},
                   "unguarded": True, "backward_entrypoints_total": 2,
                   "backward_entrypoints_guarded": 2}])
        self.assertEqual(self.m.analyse(self.ws)["obligation_count"], 0)

    def test_guarded_path_is_not_candidate(self):
        self._df([{"sink": {"kind": "burn", "file": "T.sol", "line": 9},
                   "unguarded": False, "backward_entrypoints_total": 2,
                   "backward_entrypoints_guarded": 0}])
        self.assertEqual(self.m.analyse(self.ws)["obligation_count"], 0)

    def test_non_impact_sink_ignored(self):
        self._df([{"sink": {"kind": "state_var_read", "file": "T.sol", "line": 9},
                   "unguarded": True, "backward_entrypoints_total": 2,
                   "backward_entrypoints_guarded": 0}])
        self.assertEqual(self.m.analyse(self.ws)["obligation_count"], 0)

    def test_substrate_missing_backptr_is_honest(self):
        # impact sink, unguarded, but NO backward_entrypoints field (Go substrate)
        self._df([{"sink": {"kind": "mint", "file": "k.go", "line": 9}, "unguarded": True}])
        rep = self.m.analyse(self.ws)
        self.assertEqual(rep["obligation_count"], 0)
        self.assertEqual(rep["status"], "substrate_missing_backptr")

    def test_direction_ambiguous_flag(self):
        # transfer-class sink -> direction_ambiguous True (from-party unknown);
        # mint (protocol-authority op) -> NOT ambiguous.
        self._df([{"sink": {"kind": "safetransferfrom", "file": "T.sol", "line": 9},
                   "unguarded": True, "backward_entrypoints_total": 2,
                   "backward_entrypoints_guarded": 0},
                  {"sink": {"kind": "mint", "file": "T.sol", "line": 20},
                   "unguarded": True, "backward_entrypoints_total": 2,
                   "backward_entrypoints_guarded": 0}])
        obs = {o["impact_sink"]["kind"]: o for o in self.m.analyse(self.ws)["obligations"]}
        self.assertTrue(obs["safetransferfrom"]["direction_ambiguous"])
        self.assertIn("FROM == msg.sender", obs["safetransferfrom"]["search_question"])
        self.assertFalse(obs["mint"]["direction_ambiguous"])

if __name__ == "__main__":
    unittest.main()
