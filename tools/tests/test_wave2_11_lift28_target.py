"""Guard: wave-2 #11 - LIFT-28 corpus enrichment has a make target (was zero callers)."""
import re, unittest
from pathlib import Path
MK = Path(__file__).resolve().parents[2] / "Makefile"
class TestLift28Target(unittest.TestCase):
    def test_corpus_lift28_enrich_target_exists(self):
        text = MK.read_text(encoding="utf-8")
        m = re.search(r"^corpus-lift28-enrich:.*?(?=^\S)", text, re.S | re.M)
        self.assertTrue(m, "wave2 #11: corpus-lift28-enrich target missing")
        self.assertIn("lift28-enrich-corpora.py", m.group(0))
if __name__ == "__main__":
    unittest.main()
