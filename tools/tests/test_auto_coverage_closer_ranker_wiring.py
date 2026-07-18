"""Guard: S3-wire-ranker - the per-fn question ranker is wired into the worklist
finalize step, and the Makefile fire prefers the ranked sibling.

Before S3 the ranker (per-fn-question-ranker.py, top-N + scanner-corroboration +
KDE/OOS) was fully built but had ZERO chain wiring - the hunt fired the raw worklist.
Now _reweight_dedup_sort_worklist emits a NON-DESTRUCTIVE ranked sibling and the
mimo-harness-hunt recipe prefers <worklist>.ranked.jsonl for the fire while leaving the
canonical worklist intact for coverage accounting.

Asserts the wiring is present (key + tool path + Makefile prefer-clause). Does not
depend on ranker internals succeeding on a fixture (non-flaky).
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ACC = ROOT / "tools" / "auto-coverage-closer.py"
MAKEFILE = ROOT / "Makefile"


def _load():
    spec = importlib.util.spec_from_file_location("auto_coverage_closer", ACC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRankerWiring(unittest.TestCase):
    def test_ranker_tool_const_points_at_real_tool(self):
        mod = _load()
        self.assertTrue(hasattr(mod, "RANKER_TOOL"), "S3 RANKER_TOOL const must exist")
        self.assertTrue(mod.RANKER_TOOL.is_file(),
                        f"RANKER_TOOL must point at a real tool: {mod.RANKER_TOOL}")

    def test_finalize_emits_ranked_sidecar_key(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            wl = ws / mod.PER_FN_HACKER_QUESTIONS_REL
            wl.parent.mkdir(parents=True, exist_ok=True)
            rows = [
                {"unit_id": f"src/V.sol:f{i}", "question": f"can f{i} be reentered?",
                 "file": "src/V.sol", "function": f"f{i}"}
                for i in range(3)
            ]
            wl.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            res = mod._reweight_dedup_sort_worklist(ws)
            # the ranker pass is wired: the result reports a ranked_sidecar status,
            # and the canonical worklist is NOT destroyed (still present for accounting).
            self.assertIn("ranked_sidecar", res, "S3: finalize must report ranked_sidecar")
            self.assertTrue(wl.is_file(), "canonical worklist must remain (non-destructive)")

    def test_makefile_fire_prefers_ranked_sibling(self):
        text = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn(".ranked.jsonl", text,
                      "S3: mimo-harness-hunt must prefer the ranked sibling for the fire")


if __name__ == "__main__":
    unittest.main()
