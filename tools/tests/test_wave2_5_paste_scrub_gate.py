"""Guard: wave-2 #5 - final-paste hygiene flags un-scrubbed internal labels (run cantina-paste-scrub)."""
import importlib.util, sys, tempfile, unittest
from pathlib import Path
SRC = Path(__file__).resolve().parents[1] / "audit-closeout-check.py"
def _load():
    spec = importlib.util.spec_from_file_location("acc", SRC)
    m = importlib.util.module_from_spec(spec); sys.modules["acc"]=m; spec.loader.exec_module(m); return m
class TestPasteScrubGate(unittest.TestCase):
    def test_internal_label_flagged(self):
        m = _load()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "finding.md"
            p.write_text("# Finding\n\nSee RG-KILL-42 and agent_outputs/triage.md for context.\n", encoding="utf-8")
            v = m._final_paste_hygiene_violations(p)
            kinds = {x["kind"] for x in v}
            self.assertIn("internal_label_unscrubbed", kinds, f"#5: un-scrubbed label not flagged: {v}")
    def test_clean_paste_no_internal_label(self):
        m = _load()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "clean.md"
            p.write_text("# Finding\n\nA clean scrubbed finding body with no internal labels.\n", encoding="utf-8")
            v = m._final_paste_hygiene_violations(p)
            self.assertNotIn("internal_label_unscrubbed", {x["kind"] for x in v})
if __name__ == "__main__":
    unittest.main()
