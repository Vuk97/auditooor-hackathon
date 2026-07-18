"""Regression: slice-oob-bounds-taint bounds its scan so a single pathological file
(regex catastrophic-backtrack / O(n^2) blowup) or a huge Cosmos monorepo can never
hang the step-2d-slice-oob step (2026-07-14).

Before: run() scanned the whole ws unbounded; on axelar-core (~2000 .go) one file's
scan_go_source hung >250s and the step never completed. Now: prefers ws/src, a per-file
SIGALRM timeout abandons a hung file, a total wall-clock budget stops the loop, and an
oversized-file line cap - all surfaced in the accounting (scan_capped / oversized_skipped
/ per_file_timed_out) so a bounded run is never silently mistaken for a clean 0-survivor
scan.
"""
import importlib.util
import pathlib
import sys
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "slice-oob-bounds-taint.py"
_spec = importlib.util.spec_from_file_location("_slice_oob", _TOOL)
_m = importlib.util.module_from_spec(_spec)
sys.modules["_slice_oob"] = _m
_spec.loader.exec_module(_m)


class SliceOobBoundedScan(unittest.TestCase):
    def _ws(self, files):
        ws = pathlib.Path(tempfile.mkdtemp())
        src = ws / "src"
        src.mkdir(parents=True, exist_ok=True)
        for name, body in files.items():
            (src / name).write_text(body)
        return ws

    def test_accounting_surfaces_bound_counters(self):
        ws = self._ws({"a.go": "package a\nfunc F() {}\n"})
        acct = _m.run(ws, None, emit=True)
        for k in ("scan_capped", "oversized_skipped", "per_file_timed_out",
                  "files_total", "files_scanned"):
            self.assertIn(k, acct, f"accounting must surface {k} (no silent truncation)")
        self.assertFalse(acct["scan_capped"])
        self.assertEqual(acct["per_file_timed_out"], 0)

    def test_oversized_file_skipped_and_logged(self):
        big = "package a\n" + ("// x\n" * 20)  # 21 lines
        ws = self._ws({"big.go": big, "ok.go": "package a\nfunc F() {}\n"})
        acct = _m.run(ws, None, emit=False, max_file_lines=10)
        self.assertEqual(acct["oversized_skipped"], 1,
                         "a file over max_file_lines must be skipped and counted")

    def test_prefers_src_subdir(self):
        # a survivor-free run over ws/src still emits a cited-empty ledger
        ws = self._ws({"a.go": "package a\nfunc F() {}\n"})
        acct = _m.run(ws, None, emit=True)
        self.assertTrue((ws / ".auditooor" / "slice_oob_bounds_taint.jsonl").is_file())
        self.assertGreaterEqual(acct["files_total"], 1)


if __name__ == "__main__":
    unittest.main()
