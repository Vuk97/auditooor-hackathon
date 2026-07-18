"""Guard: wave-2 #14 - etl_miner_registry build + check make targets exist."""
import re, unittest
from pathlib import Path
MK = Path(__file__).resolve().parents[2] / "Makefile"
class TestRegistryTargets(unittest.TestCase):
    def test_build_and_check_targets(self):
        t = MK.read_text(encoding="utf-8")
        for tgt in ("corpus-etl-miner-registry:", "corpus-etl-miner-registry-check:"):
            self.assertRegex(t, r"(?m)^" + re.escape(tgt), f"wave2 #14: {tgt} missing")
        m = re.search(r"^corpus-etl-miner-registry-check:.*?(?=^\S)", t, re.S | re.M)
        self.assertIn("--check", m.group(0))
if __name__ == "__main__":
    unittest.main()
