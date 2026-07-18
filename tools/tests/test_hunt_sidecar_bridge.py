"""Regression for tools/hunt-sidecar-bridge.py - materializes a workspace's
hunt sidecars (matched by recorded workspace_path/workspace) into
<ws>/.auditooor/hunt_findings_sidecars/. Verifies: only sidecars belonging to
the target workspace are copied (never another workspace's, never by filename);
0 matches copies nothing (honest). Generic-fix anchor: the per-function hunt
writes sidecars to the repo derived dir, but hunt-completeness reads <ws>/.
"""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-sidecar-bridge.py"


def _load():
    spec = importlib.util.spec_from_file_location("hsb", _T)
    m = importlib.util.module_from_spec(spec)
    sys.modules["hsb"] = m
    spec.loader.exec_module(m)
    return m


HSB = _load()


def _sidecar(d, name, ws_path, ws_name):
    (d / name).write_text(json.dumps({
        "task_id": name, "workspace": ws_name, "workspace_path": ws_path,
        "status": "ok", "result": json.dumps({"applies_to_target": "no"}),
    }), encoding="utf-8")


class TestSidecarBridge(unittest.TestCase):
    def test_only_target_workspace_copied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "wsA"; ws.mkdir()
            other = root / "wsB"; other.mkdir()
            derived = root / "derived" / "haiku_harness_wsA_n10"
            derived.mkdir(parents=True)
            _sidecar(derived, "mimo_harness_wsA_0.json", str(ws), "wsA")
            _sidecar(derived, "mimo_harness_wsA_1.json", str(ws), "wsA")
            _sidecar(derived, "mimo_harness_wsB_0.json", str(other), "wsB")  # foreign
            res = HSB.bridge(ws, root / "derived")
            self.assertEqual(res["matched"], 2)
            out = ws / ".auditooor" / "hunt_findings_sidecars"
            self.assertEqual(len(list(out.glob("*.json"))), 2)
            # foreign sidecar NOT copied
            for f in out.glob("*.json"):
                self.assertNotIn("wsB", f.name)

    def test_zero_match_copies_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "wsA"; ws.mkdir()
            derived = root / "derived" / "haiku_harness_wsB_n10"
            derived.mkdir(parents=True)
            _sidecar(derived, "mimo_harness_wsB_0.json", str(root / "wsB"), "wsB")
            res = HSB.bridge(ws, root / "derived")
            self.assertEqual(res["matched"], 0)  # honest: none belong to wsA

    def test_skips_plan_and_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "wsA"; ws.mkdir()
            derived = root / "derived" / "haiku_harness_wsA_n10" / "_haiku_plan"
            derived.mkdir(parents=True)
            # a json under _haiku_plan must be skipped even if ws matches
            _sidecar(derived, "hunt_plan.json", str(ws), "wsA")
            res = HSB.bridge(ws, root / "derived")
            self.assertEqual(res["matched"], 0)


if __name__ == "__main__":
    unittest.main()
