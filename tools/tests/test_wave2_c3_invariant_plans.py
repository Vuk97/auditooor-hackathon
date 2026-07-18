"""Guard: wave-2 C3 - invariant->runnable-plan seeder is wired + the plan file is fresh."""
import json, re, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
MK = ROOT / "Makefile"
PLANS = ROOT / "audit/corpus_tags/derived/invariant_runnable_plans.jsonl"
class TestInvariantPlans(unittest.TestCase):
    def test_make_target_wired(self):
        m = re.search(r"^corpus-invariant-plans:.*?(?=^\S)", MK.read_text(), re.S | re.M)
        self.assertTrue(m, "C3: corpus-invariant-plans target missing")
        self.assertIn("invariant-library-harness-seed.py", m.group(0))
    def test_plans_not_stale(self):
        n = sum(1 for l in PLANS.read_text().splitlines() if l.strip())
        self.assertGreater(n, 10000, f"C3: plan file must be fresh (got {n}, stale was 1394)")
if __name__ == "__main__":
    unittest.main()
