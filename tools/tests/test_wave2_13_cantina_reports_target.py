"""Guard: wave-2 #13 - cantina-reports ETL has a make target (was zero callers)."""
import re, unittest
from pathlib import Path
MK = Path(__file__).resolve().parents[2] / "Makefile"
class TestCantinaReportsTarget(unittest.TestCase):
    def test_target_exists(self):
        m = re.search(r"^corpus-etl-cantina-reports:.*?(?=^\S)", MK.read_text(encoding="utf-8"), re.S | re.M)
        self.assertTrue(m, "wave2 #13: corpus-etl-cantina-reports target missing")
        self.assertIn("hackerman-etl-from-cantina-reports.py", m.group(0))
if __name__ == "__main__":
    unittest.main()
