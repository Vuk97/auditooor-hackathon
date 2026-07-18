"""Test the mechanical asymmetry filter + packet extractor."""
import importlib.util, json, tempfile, unittest
from pathlib import Path
_T = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ace", _T / "asymmetry-context-extract.py")
ACE = importlib.util.module_from_spec(spec); spec.loader.exec_module(ACE)


def _ws(t):
    ws = Path(t); (ws/".auditooor").mkdir(parents=True); (ws/"modules/a").mkdir(parents=True); (ws/"modules/b").mkdir(parents=True)
    (ws/"modules/a/x.rs").write_text("fn deposit(){\n require(ok);\n}\n")
    (ws/"modules/b/y.rs").write_text("fn withdraw(){\n // no guard\n}\n")
    (ws/"tests").mkdir()
    (ws/"tests/t.rs").write_text("fn deposit(){}\n")
    return ws


class T(unittest.TestCase):
    def _rows(self, ws, rows):
        (ws/".auditooor"/"sibling_guard_asymmetries.jsonl").write_text("\n".join(json.dumps(r) for r in rows)+"\n")
        return ACE.extract(ws, ws, 20, False)

    def test_variant_arm_kept(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._rows(ws, [{"pair":"verify~variant","pair_kind":"variant-arm",
                "path_a":{"file":"modules/a/x.rs","line":1},"path_b":{"file":"modules/b/y.rs","line":1},
                "guard_on_a_missing_on_b":["require_ok"],"guard_on_b_missing_on_a":[],"shared_invariant_hint":"both must guard"}])
            self.assertEqual(out["packets_written"], 1)

    def test_cross_module_naming_dropped(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._rows(ws, [{"pair":"deposit|withdraw","pair_kind":"naming-convention",
                "path_a":{"file":"modules/a/x.rs","line":1},"path_b":{"file":"modules/b/y.rs","line":1},
                "guard_on_a_missing_on_b":["require_ok"],"guard_on_b_missing_on_a":[]}])
            self.assertEqual(out["dropped"]["cross_module_naming"], 1)
            self.assertEqual(out["packets_written"], 0)

    def test_test_file_dropped(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._rows(ws, [{"pair":"x","pair_kind":"variant-arm",
                "path_a":{"file":"tests/t.rs","line":1},"path_b":{"file":"modules/b/y.rs","line":1},
                "guard_on_a_missing_on_b":["g"],"guard_on_b_missing_on_a":[]}])
            self.assertEqual(out["dropped"]["test_file"], 1)

    def test_no_asymmetry_dropped(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            out = self._rows(ws, [{"pair":"x","pair_kind":"variant-arm",
                "path_a":{"file":"modules/a/x.rs","line":1},"path_b":{"file":"modules/b/y.rs","line":1},
                "guard_on_a_missing_on_b":[],"guard_on_b_missing_on_a":[]}])
            self.assertEqual(out["dropped"]["no_asymmetry"], 1)

    def test_packet_has_both_sides(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _ws(t)
            self._rows(ws, [{"pair":"v","pair_kind":"variant-arm",
                "path_a":{"file":"modules/a/x.rs","line":2},"path_b":{"file":"modules/b/y.rs","line":2},
                "guard_on_a_missing_on_b":["require"],"guard_on_b_missing_on_a":[],"shared_invariant_hint":"sym"}])
            p = json.loads((ws/".auditooor"/"asymmetry_probe_packets.jsonl").read_text().splitlines()[0])
            self.assertIn("asym_id", p)
            self.assertIn("candidate_gap_id", p)
            self.assertIn("side_a", p); self.assertIn("side_b", p); self.assertIn("require", p["side_a"]["context"])


if __name__ == "__main__":
    unittest.main()
