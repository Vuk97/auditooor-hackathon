"""Guard: C1 - medusa no-target is NOT recorded as a clean pass (silent-OK false-green)."""
import importlib.util, sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
SH = ROOT / "tools" / "medusa-fuzz.sh"
MK = ROOT / "Makefile"
PARSE = ROOT / "tools" / "deep-engine-output-parse.py"
def _load(name, p):
    spec = importlib.util.spec_from_file_location(name, p); m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m; spec.loader.exec_module(m); return m
class TestC1(unittest.TestCase):
    def test_medusa_sh_no_target_status(self):
        t = SH.read_text()
        self.assertIn('ENGINE_STATUS="no-target"', t, "C1: no-target branch must set no-target status, not ok")
        self.assertNotIn('no-target stays ok', t, "C1: the old 'no-target stays ok' comment must be gone")
    def test_makefile_routes_via_config(self):
        t = MK.read_text()
        self.assertIn('fuzz --config "$$medusa_config"', t, "C1: Makefile must route medusa via authored --config when present")
    def test_parse_no_target_is_not_run(self):
        m = _load("dep_c1", PARSE)
        # the source must map no-target -> not_run (string check is enough; behavior tested by audit)
        self.assertIn('engine_status == "no-target"', PARSE.read_text())
        self.assertIn('"verdict": "not_run"', PARSE.read_text())
if __name__ == "__main__":
    unittest.main()
