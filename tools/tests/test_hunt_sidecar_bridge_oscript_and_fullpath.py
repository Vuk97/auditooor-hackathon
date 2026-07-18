"""Regression for tools/hunt-sidecar-bridge.py (obyte Oscript capability, 2026-07-09):

1. LANGUAGE REGISTRATION: .oscript / .aa are recognized SOURCE extensions, so the
   R76 source-existence gate collects + verifies a sidecar that cites an .oscript/.aa
   file (previously such a cite was a non-source suffix -> unverifiable/unenforced).
2. FULL-PATH ``workspace`` identity: a sidecar whose ``workspace`` field holds the
   ABSOLUTE workspace path (what tools/workflow-drill-sidecar-emit.py writes when the
   caller passes an absolute path - the Obyte hunt did) must be recognized as belonging
   to the workspace. Previously the belongs-check compared ``workspace`` to ws.name
   (short name) only, silently dropping every such sidecar (obyte: 23 of 24 missed).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "hunt-sidecar-bridge.py"


def _load():
    spec = importlib.util.spec_from_file_location("hsb_osc", _T)
    m = importlib.util.module_from_spec(spec)
    sys.modules["hsb_osc"] = m
    spec.loader.exec_module(m)
    return m


HSB = _load()


class TestBridgeOscriptAndFullPath(unittest.TestCase):
    def test_oscript_ext_registered(self):
        self.assertIn(".oscript", HSB._SOURCE_EXTENSIONS)
        self.assertIn(".aa", HSB._SOURCE_EXTENSIONS)
        # existing extractable exts are still present (no regression).
        for e in (".sol", ".go", ".rs"):
            self.assertIn(e, HSB._SOURCE_EXTENSIONS)

    def test_oscript_source_file_collected(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "agent.oscript").write_text("['autonomous agent', {}]",
                                                      encoding="utf-8")
            (ws / "src" / "x.aa").write_text("{}", encoding="utf-8")
            by_name = HSB._collect_source_files(ws)
            self.assertIn("agent.oscript", by_name)
            self.assertIn("x.aa", by_name)

    def test_fullpath_workspace_field_belongs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = (root / "obyte").resolve()
            ws.mkdir()
            derived = root / "derived" / "mimo_harness_obyte_workflow"
            derived.mkdir(parents=True)
            # sidecar with the FULL PATH in ``workspace`` and NO ``workspace_path``
            # (the emit shape that previously got dropped).
            (derived / "aa-negative.json").write_text(json.dumps({
                "task_id": "aa-negative",
                "workspace": str(ws),          # absolute path, not short name
                "status": "ok",
                "function_anchor": {"file": "src/agent.aa", "function": "distribute"},
                "result": {"applies_to_target": "no",
                           "file_line": "src/agent.aa:27"},
            }), encoding="utf-8")
            res = HSB.bridge(ws, root / "derived", enforce_r76=False)
            self.assertEqual(res["matched"], 1,
                             "full-path workspace sidecar must be matched")
            self.assertTrue(
                (ws / ".auditooor" / "hunt_findings_sidecars" / "aa-negative.json").is_file())

    def test_foreign_fullpath_workspace_not_matched(self):
        # a full-path workspace that resolves ELSEWHERE must NOT match (no false-copy).
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = (root / "obyte").resolve(); ws.mkdir()
            other = (root / "other").resolve(); other.mkdir()
            derived = root / "derived" / "mimo_harness_x"
            derived.mkdir(parents=True)
            (derived / "foreign.json").write_text(json.dumps({
                "task_id": "foreign", "workspace": str(other), "status": "ok",
                "result": {"applies_to_target": "no"},
            }), encoding="utf-8")
            res = HSB.bridge(ws, root / "derived", enforce_r76=False)
            self.assertEqual(res["matched"], 0)


if __name__ == "__main__":
    unittest.main()
