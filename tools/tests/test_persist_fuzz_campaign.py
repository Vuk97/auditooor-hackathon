#!/usr/bin/env python3
"""Regression: persist-fuzz-campaign parses a real medusa log's call count and
writes it into the harness mvc_sidecar (feeder-health fix), and REFUSES to persist
a count with no backing log line (never-fabricate)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("pfc", _H.parent / "persist-fuzz-campaign.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)

_LOG = ("fuzz: elapsed: 3s, calls: 35492 (11830/sec), branches: 3191, corpus: 31\n"
        "fuzz: elapsed: 3m03s, calls: 1215685 (7787/sec), branches: 9110, corpus: 52\n"
        "Test summary: 2 test(s) passed, 1 test(s) failed\n")


class T(unittest.TestCase):
    def _ws(self):
        ws = Path(tempfile.mkdtemp())
        hd = ws / "chimera_harnesses" / "FooConservation"
        hd.mkdir(parents=True)
        (hd / "FooConservation.sol").write_text("contract FooConservation {}\n")
        return ws, hd

    def test_parse_calls_takes_max(self):
        self.assertEqual(m.parse_calls(_LOG), 1_215_685)

    def test_persist_writes_count_and_log(self):
        ws, hd = self._ws()
        cfg = hd / "medusa.json"
        cfg.write_text('{"fuzzing":{"callSequenceLength":50}}')
        r = m.persist(ws, hd, _LOG, cfg, corpus_dir="chimera_harnesses/FooConservation/corpus")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["calls_executed"], 1_215_685)
        # sidecar has the count
        sc = json.loads(Path(r["sidecar"]).read_text())
        self.assertEqual(sc["medusa_campaign"]["calls_executed"], 1_215_685)
        self.assertEqual(sc["medusa_campaign"]["call_sequence_length"], 50)
        # log retained where gates look
        self.assertTrue(Path(r["log"]).is_file())
        self.assertIn("medusa_FooConservation.log", r["log"])

    def test_refuses_fabricated_count(self):
        ws, hd = self._ws()
        r = m.persist(ws, hd, "no call count here at all\n", None)
        self.assertFalse(r["ok"])
        self.assertEqual(r["calls_executed"], 0)

    def test_updates_existing_sidecar_preserving_fields(self):
        ws, hd = self._ws()
        sc_dir = ws / ".auditooor" / "mvc_sidecar"
        sc_dir.mkdir(parents=True)
        (sc_dir / "mvc-FooConservation.json").write_text(json.dumps(
            {"schema": "x", "harness_path": "chimera_harnesses/FooConservation/FooConservation.sol",
             "mutation_verified": True, "verdict": "non-vacuous"}))
        r = m.persist(ws, hd, _LOG, None)
        self.assertTrue(r["ok"])
        sc = json.loads(Path(r["sidecar"]).read_text())
        self.assertTrue(sc["mutation_verified"])   # preserved
        self.assertEqual(sc["verdict"], "non-vacuous")  # preserved
        self.assertEqual(sc["medusa_campaign"]["calls_executed"], 1_215_685)  # added


if __name__ == "__main__":
    unittest.main()
