"""Guard test - hunt-sidecar-bridge bridges the mega/workflow-drill per-fn hunt
sidecars and synthesizes their function_anchor so function-coverage credits them.

Root cause this guards (2026-06-13): the mega per-fn hunt
(tools/workflow-drill-sidecar-emit.py) writes sidecars named <task_id>.json
INSIDE mimo_harness_<ws>_workflow/, tagged with the short engagement-alias
workspace name (e.g. "monero" for the monero-oxide dir), result as a JSON
string, and NO outer function_anchor. The bridge previously (a) only scanned
specific filename-prefix globs (missed <task_id>.json), (b) rejected the alias
workspace name, and (c) left function_anchor empty - so ~4,100 real per-fn
verdicts never credited into function-coverage (untouched stayed ~300/2005).

This test pins the three fixes together: harness-dir scan, alias belongs-match,
and function_anchor synthesis from the inner file_line via the fn index.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
BRIDGE = REPO / "tools" / "hunt-sidecar-bridge.py"


def _load() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("hunt_sidecar_bridge", BRIDGE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class BridgeMegaAnchorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.m = _load()
        self.tmp = Path(tempfile.mkdtemp())
        # workspace dir named with the FULL name; the sidecar uses the alias.
        self.ws = self.tmp / "monero-oxide"
        (self.ws / "src").mkdir(parents=True)
        # derived root with a mega-style sidecar (task_id filename, alias ws,
        # result-as-string, no function_anchor)
        self.derived = self.tmp / "derived"
        hdir = self.derived / "mimo_harness_monero_workflow"
        hdir.mkdir(parents=True)
        inner = {"applies_to_target": "no", "confidence": "high",
                 "file_line": "src/x/commitment.rs:L57", "verdict": "KILL",
                 "code_excerpt": "fn commit", "reasoning": "guarded"}
        sidecar = {"status": "ok", "task_id": "monero-mega-b0-commitment-commit",
                   "workspace": "monero", "source": "workflow-drill",
                   "emitted_at_utc": "2026-06-13T00:00:00Z",
                   "result": json.dumps(inner)}
        (hdir / "monero-mega-b0-commitment-commit.json").write_text(json.dumps(sidecar))

    def test_bridges_and_synthesizes_anchor(self) -> None:
        # fn index resolves (commitment.rs, 57) -> "commit" (what fcc would emit)
        fake_index = {("commitment.rs", 57): "commit"}
        with mock.patch.object(self.m, "_fn_index_for_ws", return_value=fake_index):
            res = self.m.bridge(self.ws, self.derived, enforce_r76=False)
        self.assertGreaterEqual(res["matched"], 1, "alias-named mega sidecar must match")
        self.assertGreaterEqual(res["anchors_synthesized"], 1, "anchor must be synthesized")
        # the written sidecar must carry a usable function_anchor
        out = list((self.ws / ".auditooor" / "hunt_findings_sidecars").glob("*.json"))
        self.assertEqual(len(out), 1)
        d = json.loads(out[0].read_text())
        fa = d.get("function_anchor")
        self.assertIsInstance(fa, dict)
        self.assertEqual(fa.get("function"), "commit")
        self.assertEqual(fa.get("line"), 57)
        self.assertTrue(fa.get("file", "").endswith("commitment.rs"))

    def test_no_index_synthesizes_file_line_anchor(self) -> None:
        # PERF path (default): with NO fn index (the slow fcc enumeration is
        # skipped), the bridge STILL synthesizes a {file,line} anchor from the
        # inner file_line. fcc resolves the function name by exact decl-line, so
        # the name is intentionally absent here - never fabricated.
        with mock.patch.object(self.m, "_fn_index_for_ws", return_value={}):
            res = self.m.bridge(self.ws, self.derived, enforce_r76=False)
        self.assertGreaterEqual(res["matched"], 1)
        self.assertGreaterEqual(res["anchors_synthesized"], 1,
                                "index-free {file,line} anchor must be synthesized")
        out = list((self.ws / ".auditooor" / "hunt_findings_sidecars").glob("*.json"))
        self.assertEqual(len(out), 1)
        fa = json.loads(out[0].read_text()).get("function_anchor")
        self.assertIsInstance(fa, dict)
        self.assertEqual(fa.get("line"), 57)
        self.assertTrue(fa.get("file", "").endswith("commitment.rs"))
        # honest: no function name fabricated when the index cannot supply one
        self.assertIsNone(fa.get("function"))

    def test_unrelated_workspace_not_matched(self) -> None:
        # a sidecar aliased "monero" must NOT bridge into an unrelated "aztec" ws
        ws2 = self.tmp / "aztec"
        (ws2 / "src").mkdir(parents=True)
        with mock.patch.object(self.m, "_fn_index_for_ws", return_value={}):
            res = self.m.bridge(ws2, self.derived, enforce_r76=False)
        self.assertEqual(res["matched"], 0, "alias prefix must not cross to unrelated ws")


if __name__ == "__main__":
    unittest.main()
