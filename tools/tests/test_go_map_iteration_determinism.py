"""Tests for the G1 consensus map-iteration non-determinism detector.

Detector: go.consensus.map_iteration_nondeterministic_state_write in
tools/go-detector-runner.py. Non-vacuous: mutating the sort-detection OR
the sink-detection breaks at least one assertion here.
"""
from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE.parent
REPO = TOOLS_DIR.parent
RUNNER_PATH = TOOLS_DIR / "go-detector-runner.py"
FIXTURES = REPO / "tests" / "fixtures" / "go" / "consensus_map_determinism"
PID = "go.consensus.map_iteration_nondeterministic_state_write"


def _load_runner():
    spec = importlib.util.spec_from_file_location("go_detector_runner", RUNNER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["go_detector_runner"] = mod
    spec.loader.exec_module(mod)
    return mod


class MapIterationDeterminismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def _scan_src(self, src: str) -> dict:
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "x.go").write_text(src, encoding="utf-8")
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS)
            )
        return summary["patterns"][PID]

    def _scan_file(self, name: str) -> dict:
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(FIXTURES / name, Path(ws) / name)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS)
            )
        return summary["patterns"][PID]

    # ------------------------------------------------------------------
    # fixture pair
    # ------------------------------------------------------------------
    def test_mustflag_fixture_fires_once(self):
        res = self._scan_file("mustflag_map_range_write.go")
        self.assertEqual(res["hit_count"], 1, res)
        hit = res["hits"][0]
        self.assertEqual(hit["extra"]["map_var"], "rewards")
        self.assertIn("store.Set", hit["extra"]["sink"])

    def test_benign_sorted_fixture_clean(self):
        res = self._scan_file("benign_sorted_keys_write.go")
        self.assertEqual(res["hit_count"], 0, res)

    # ------------------------------------------------------------------
    # sink-detection is load-bearing: a map range with NO consensus sink
    # must stay clean. If the sink requirement is dropped, this flips.
    # ------------------------------------------------------------------
    def test_map_range_without_sink_clean(self):
        src = (
            "package p\n"
            "func F(m map[string]uint64) uint64 {\n"
            "\tvar total uint64\n"
            "\tfor _, amt := range m {\n"
            "\t\ttotal += amt\n"
            "\t}\n"
            "\treturn total\n"
            "}\n"
        )
        self.assertEqual(self._scan_src(src)["hit_count"], 0)

    # ------------------------------------------------------------------
    # sort-detection is load-bearing: a map range WITH a consensus sink but
    # a sort call in the func must stay clean. If sort-detection is dropped,
    # this flips to a hit.
    # ------------------------------------------------------------------
    def test_map_range_with_sink_but_sorted_clean(self):
        src = (
            "package p\n"
            "import \"sort\"\n"
            "func F(store KVStore, m map[string]uint64) {\n"
            "\tkeys := sortedKeys(m)\n"
            "\tsort.Strings(keys)\n"
            "\tfor addr, amt := range m {\n"
            "\t\tstore.Set([]byte(addr), enc(amt))\n"
            "\t}\n"
            "}\n"
        )
        self.assertEqual(self._scan_src(src)["hit_count"], 0)

    def test_map_range_with_sink_no_sort_fires(self):
        src = (
            "package p\n"
            "func F(store KVStore, m map[string]uint64) {\n"
            "\tfor addr, amt := range m {\n"
            "\t\tstore.Set([]byte(addr), enc(amt))\n"
            "\t}\n"
            "}\n"
        )
        self.assertEqual(self._scan_src(src)["hit_count"], 1)


if __name__ == "__main__":
    unittest.main()
