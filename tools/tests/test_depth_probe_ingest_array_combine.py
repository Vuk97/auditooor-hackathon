#!/usr/bin/env python3
"""Guard test for depth-probe-ingest _combine_probes_dir array/JSONL handling.

Regression: depth-probe agent batches write their verdicts as a JSON ARRAY (the
canonical agent-batch prompt says "Write a JSON array"), but the combiner only
handled JSONL (one dict per line). Result on optimism: multi-line arrays were
silently DROPPED and single-line arrays were emitted as bare `list` rows that
crashed _cert_row with "'list' object has no attribute 'get'". Only 403 of 995
probe rows survived. The combiner must parse both shapes and flatten arrays to
dict rows.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "depth-probe-ingest.py"
_spec = importlib.util.spec_from_file_location("dpi", _TOOL)
dpi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dpi)


def _rec(i, gap=False):
    return {"guard_id": f"NS-{i}", "file_line": f"src/x.rs:{i}",
            "code_excerpt": "x", "gap_found": gap,
            "why_no_gap_or_exploit": "checked", "probe_source": "test"}


class CombineProbesDirTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def _combine(self):
        out = self.d / "combined.jsonl"
        n = dpi._combine_probes_dir(self.d, out)
        rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
        return n, rows

    def test_multiline_json_array_flattened(self):
        # The dominant agent-batch shape: a pretty-printed multi-line JSON array.
        (self.d / "batch_000.jsonl").write_text(
            json.dumps([_rec(0), _rec(1), _rec(2)], indent=2), encoding="utf-8")
        n, rows = self._combine()
        self.assertEqual(n, 3, "multi-line JSON array was dropped")
        self.assertTrue(all(isinstance(r, dict) for r in rows))

    def test_single_line_array_not_emitted_as_list(self):
        (self.d / "batch_001.jsonl").write_text(
            json.dumps([_rec(3), _rec(4)]), encoding="utf-8")
        n, rows = self._combine()
        self.assertEqual(n, 2)
        self.assertTrue(all(isinstance(r, dict) for r in rows),
                        "single-line array leaked a bare list row")

    def test_plain_jsonl_still_works(self):
        (self.d / "batch_002.jsonl").write_text(
            json.dumps(_rec(5)) + "\n" + json.dumps(_rec(6)) + "\n", encoding="utf-8")
        n, rows = self._combine()
        self.assertEqual(n, 2)

    def test_mixed_dir_all_recovered(self):
        (self.d / "batch_a.jsonl").write_text(json.dumps([_rec(7), _rec(8)], indent=1))
        (self.d / "batch_b.jsonl").write_text(json.dumps(_rec(9)))
        (self.d / "batch_c.jsonl").write_text(json.dumps(_rec(10)) + "\n" + json.dumps(_rec(11)))
        n, rows = self._combine()
        self.assertEqual(n, 5, "rows lost across mixed array/JSONL batch files")
        self.assertTrue(all(isinstance(r, dict) for r in rows))


if __name__ == "__main__":
    unittest.main()
