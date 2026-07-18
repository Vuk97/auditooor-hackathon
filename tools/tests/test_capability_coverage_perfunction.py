"""Regression: the capability-coverage matrix credits per-function-manifest
coverage. A cluster whose crate appears in >=1 processed function's source path
is COVERED (the per-function hunt ran a task per function); a cluster with 0
processed functions stays DARK (honest, no fabricated coverage).
"""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "capability-coverage-matrix-build.py"


def _load():
    spec = importlib.util.spec_from_file_location("ccmb", _T)
    m = importlib.util.module_from_spec(spec)
    sys.modules["ccmb"] = m
    spec.loader.exec_module(m)
    return m


CCMB = _load()


class TestPerFunctionCoverage(unittest.TestCase):
    def test_perfunction_tokens_cover_clusters(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "SCOPE.md").write_text(
                "## In-scope crates\n- thing/ed25519 - x\n- thing/ringct/clsag - y\n"
                "- thing/borromean - z\n", encoding="utf-8")
            man = ws / ".auditooor" / "per_function_invariants"
            man.mkdir(parents=True)
            (man / "manifest.json").write_text(json.dumps({"functions": [
                {"source": "src/thing/ed25519/src/scalar.rs:10"},
                {"source": "src/thing/ringct/clsag/src/lib.rs:20"},
            ]}), encoding="utf-8")
            toks = CCMB._per_function_coverage_tokens(ws)
            self.assertIn("ed25519", toks)
            self.assertIn("clsag", toks)
            # borromean has NO processed function -> not a token -> stays DARK
            self.assertNotIn("borromean", toks)
            _txt, rows = CCMB.build_matrix(ws)
            by = {r["cluster"]: r["status"] for r in rows}
            self.assertTrue(any("ed25519" in c and s == "COVERED" for c, s in by.items()))
            self.assertTrue(any("borromean" in c and s == "DARK" for c, s in by.items()))


if __name__ == "__main__":
    unittest.main()
