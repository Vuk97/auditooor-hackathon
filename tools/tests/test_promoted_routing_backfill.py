"""Guard: wave-2 D1 - promoted hacker-Q firing set is routable (was 0% -> drops all)."""
import importlib.util, json, tempfile, unittest
from pathlib import Path
TOOL = Path(__file__).resolve().parents[1] / "backfill-promoted-hackerq-routing.py"
def _load():
    spec = importlib.util.spec_from_file_location("bp", TOOL)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
class TestPromotedBackfill(unittest.TestCase):
    def test_statement_blob_yields_routing(self):
        m = _load()
        row = {"statement": json.dumps({"sub_question_variants":
               ["Can withdraw be reentered to drain before the balance is zeroed?"]}),
               "category": "deepseek-mined", "target_lang": "any"}
        out = m.backfill_row(row)
        self.assertTrue(out.get("target_function_patterns"),
                        "D1: a withdraw/drain question must gain routing patterns")
    def test_live_promoted_set_majority_routable(self):
        m = _load()
        p = Path(m.PROMOTED)
        rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        routable = sum(1 for r in rows if r.get("target_function_patterns"))
        self.assertGreater(routable, len(rows) // 2,
                           f"D1: majority of promoted set must be routable, got {routable}/{len(rows)}")
if __name__ == "__main__":
    unittest.main()
