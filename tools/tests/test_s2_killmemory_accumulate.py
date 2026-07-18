"""Guard: S2 fix - terminal kill-memory sidecar ACCUMULATES across rebuilds.

Regression-fleet found the sidecar self-erased to total_rows=0 after one rebuild (it banked
only the current run's rows_clean), so a suppressed killed twin resurrected on rebuild #3.
This asserts a once-banked terminal key survives a later rebuild whose rows_clean no longer
contains it (terminal verdicts are monotonic).
"""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
TOOL = Path(__file__).resolve().parents[1] / "exploit-queue.py"
def _load():
    spec = importlib.util.spec_from_file_location("exploit_queue", TOOL)
    m = importlib.util.module_from_spec(spec); sys.modules["exploit_queue"] = m
    spec.loader.exec_module(m); return m
class TestKillMemoryAccumulate(unittest.TestCase):
    def test_terminal_key_survives_empty_rebuild(self):
        m = _load()
        src = next(iter(m._EXTERNAL_ACTIONABLE_SOURCE_EXACT))
        row = {"source": src, "unit_id": "U1", "lead_id": "L1", "quality_gate_status": "killed"}
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td); (ws / ".auditooor").mkdir()
            # rebuild 1: the killed external row is present
            p1 = m._build_terminal_sidecar_payload(ws, [row], "t1")
            self.assertEqual(p1["total_rows"], 1, f"round1 should bank the kill: {p1}")
            (ws / m._TERMINAL_ROW_SIDECAR).write_text(json.dumps(p1), encoding="utf-8")
            # rebuild 2: the twin is suppressed out of rows_clean (empty) - bank must PERSIST
            p2 = m._build_terminal_sidecar_payload(ws, [], "t2")
            self.assertEqual(p2["total_rows"], 1, f"S2: bank must accumulate, not self-erase: {p2}")
            (ws / m._TERMINAL_ROW_SIDECAR).write_text(json.dumps(p2), encoding="utf-8")
            # rebuild 3: still suppressed - still banked (the resurrection the fix prevents)
            p3 = m._build_terminal_sidecar_payload(ws, [], "t3")
            self.assertEqual(p3["total_rows"], 1, f"S2: kill must stay suppressed on rebuild 3: {p3}")
            self.assertEqual(p3["rows"][0]["terminal_key"], p1["rows"][0]["terminal_key"])
if __name__ == "__main__":
    unittest.main()
