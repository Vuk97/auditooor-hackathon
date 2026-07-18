"""Guard: wave-2 #7 - chimera-invariant-registrar is wired into audit-deep.sh (LIVE-gated)."""
import re, unittest
from pathlib import Path
SH = Path(__file__).resolve().parents[1] / "audit-deep.sh"
class TestChimeraRegistrarWiring(unittest.TestCase):
    def setUp(self): self.t = SH.read_text(encoding="utf-8")
    def test_registrar_invoked(self):
        self.assertIn("chimera-invariant-registrar.py", self.t,
                      "#7: audit-deep must invoke the chimera-invariant-registrar")
    def test_live_gated(self):
        # the registrar invocation must be guarded by LIVE=1
        i = self.t.find("CHIMERA_REGISTRAR_TOOL")
        block = self.t[i:i+600]
        self.assertIn('"$LIVE" = "1"', block, "#7: registrar must be LIVE-gated")
        self.assertIn("chimera_harnesses", block)
if __name__ == "__main__":
    unittest.main()
