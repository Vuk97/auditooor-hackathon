#!/usr/bin/env python3
"""Guard: invariant-fuzz-completeness must not silently trust a STALE
value_moving_functions.json. Root cause (nuva 2026-07-13): a Jul-11 artifact still
flagged read-only query_server.go / events.go / types-genesis.go as value-moving
because audit-deep had not re-run since the Jul-12 producer FP-fix, so 3 of 5
asset-gaps were classifier false-positives the current producer already drops.
`_vmf_stale` returns True when the artifact predates its producer, and the WARN gap
reason must announce staleness so a stale-driven gap is never silently trusted.
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "ifc", str(_TOOLS / "invariant-fuzz-completeness.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["ifc"] = m
    spec.loader.exec_module(m)
    return m


class TestVmfStalenessSignal(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws_with_vmf(self, artifact_mtime):
        t = tempfile.mkdtemp()
        ws = Path(t)
        aud = ws / ".auditooor"
        aud.mkdir(parents=True)
        vmf = aud / "value_moving_functions.json"
        vmf.write_text(json.dumps({"functions": []}), encoding="utf-8")
        os.utime(vmf, (artifact_mtime, artifact_mtime))
        return ws

    def test_stale_when_artifact_older_than_producer(self):
        producer = _TOOLS / "value-moving-functions.py"
        self.assertTrue(producer.is_file())
        ws = self._ws_with_vmf(producer.stat().st_mtime - 3600)  # 1h older
        self.assertTrue(self.m._vmf_stale(ws))

    def test_fresh_when_artifact_newer_than_producer(self):
        producer = _TOOLS / "value-moving-functions.py"
        ws = self._ws_with_vmf(producer.stat().st_mtime + 3600)  # 1h newer
        self.assertFalse(self.m._vmf_stale(ws))

    def test_absent_artifact_is_not_stale(self):
        t = tempfile.mkdtemp()
        (Path(t) / ".auditooor").mkdir(parents=True)
        self.assertFalse(self.m._vmf_stale(Path(t)))


if __name__ == "__main__":
    unittest.main()
