"""Guard: wave-2 #12 - audit-closeout banks cross-workspace depth gaps via the S9 ETL."""
import re, unittest
from pathlib import Path
MK = Path(__file__).resolve().parents[2] / "Makefile"
class TestDepthEtlCloseout(unittest.TestCase):
    def test_closeout_runs_depth_ledgers_etl(self):
        text = MK.read_text(encoding="utf-8")
        m = re.search(r"^audit-closeout:.*?(?=^\S)", text, re.S | re.M)
        self.assertTrue(m, "audit-closeout recipe not found")
        self.assertIn("hackerman-etl-from-depth-ledgers.py", m.group(0),
                      "wave2 #12: audit-closeout must run the depth-ledgers ETL")
if __name__ == "__main__":
    unittest.main()
