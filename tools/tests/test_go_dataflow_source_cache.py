"""Regression: go-dataflow source-fingerprint cache (root-caused NUVA 2026-07-14).

The full go/ssa closure over a heavy cosmos-sdk module (NUVA vault keeper ~2550s)
was recomputed on EVERY pipeline invocation and re-degraded under the per-package
ceiling, so a COMPLETE slice was never reused. These tests lock the cache contract:
a COMPLETE slice for unchanged source+args is reused; a degraded/partial slice,
changed source, changed args, or AUDITOOOR_GO_DATAFLOW_NO_CACHE=1 all force a rerun.
"""
import importlib.util
import json
import os
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "go-dataflow.py"


def _load():
    spec = importlib.util.spec_from_file_location("gd_cache_test", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestGoDataflowSourceCache(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        # isolated fake workspace with one go module
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="gdcache_")
        self.ws = Path(self.tmp)
        mod = self.ws / "mod"
        (mod).mkdir(parents=True)
        (mod / "go.mod").write_text("module example.com/mod\n\ngo 1.25\n")
        (mod / "a.go").write_text("package mod\nfunc A() int { return 1 }\n")
        self.mod = mod
        self.out = self.ws / ".auditooor" / "dataflow_paths.jsonl"
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.write_text('{"kind":"x"}\n')
        # clear any inherited disable
        os.environ.pop("AUDITOOOR_GO_DATAFLOW_NO_CACHE", None)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("AUDITOOOR_GO_DATAFLOW_NO_CACHE", None)

    def _fp(self, md=24, fw=False):
        return self.m._go_source_fingerprint(self.ws, [self.mod], md, fw)

    def test_fingerprint_deterministic_and_arg_sensitive(self):
        fp1 = self._fp()
        fp2 = self._fp()
        self.assertEqual(fp1, fp2, "fingerprint must be deterministic for unchanged source")
        self.assertNotEqual(fp1, self._fp(md=8), "max_depth must change the fingerprint")
        self.assertNotEqual(fp1, self._fp(fw=True), "forward must change the fingerprint")
        self.assertEqual(len(fp1), 64)

    def test_complete_run_is_reused(self):
        fp = self._fp()
        result = {"status": "ok", "records": 5, "real_records": 5}
        self.m._write_cache_meta(self.out, fp, result, complete=True)
        rc = self.m._try_cache_reuse(self.out, fp, as_json=False)
        self.assertEqual(rc, 0, "a COMPLETE slice for the same fingerprint must be reused")

    def test_degraded_run_not_reused(self):
        fp = self._fp()
        self.m._write_cache_meta(self.out, fp, {"real_records": 0}, complete=False)
        rc = self.m._try_cache_reuse(self.out, fp, as_json=False)
        self.assertIsNone(rc, "a degraded/partial slice must NEVER be reused - retry instead")

    def test_source_change_invalidates(self):
        fp = self._fp()
        self.m._write_cache_meta(self.out, fp, {"status": "ok", "real_records": 5}, complete=True)
        # touch source -> new file changes size+mtime -> new fingerprint
        (self.mod / "b.go").write_text("package mod\nfunc B() int { return 2 }\n")
        fp2 = self._fp()
        self.assertNotEqual(fp, fp2, "adding a .go file must change the fingerprint")
        rc = self.m._try_cache_reuse(self.out, fp2, as_json=False)
        self.assertIsNone(rc, "changed source must force a recompute")

    def test_no_cache_env_disables_reuse(self):
        fp = self._fp()
        self.m._write_cache_meta(self.out, fp, {"status": "ok", "real_records": 5}, complete=True)
        os.environ["AUDITOOOR_GO_DATAFLOW_NO_CACHE"] = "1"
        rc = self.m._try_cache_reuse(self.out, fp, as_json=False)
        self.assertIsNone(rc, "AUDITOOOR_GO_DATAFLOW_NO_CACHE=1 must force a recompute")

    def test_missing_slice_file_no_reuse(self):
        fp = self._fp()
        self.m._write_cache_meta(self.out, fp, {"status": "ok", "real_records": 5}, complete=True)
        self.out.unlink()  # meta present but slice gone
        rc = self.m._try_cache_reuse(self.out, fp, as_json=False)
        self.assertIsNone(rc, "no slice on disk => no reuse even with a meta present")


if __name__ == "__main__":
    unittest.main()
